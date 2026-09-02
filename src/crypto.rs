//! Local-only account pseudonymization and Ed25519 device signing.

use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const FINGERPRINT_SALT: &[u8] = b"project-relay/account-fingerprint/v1";

/// An Ed25519 device key that never implements `Debug` or `Display`.
pub struct DeviceKey(SigningKey);

impl DeviceKey {
    /// Generate a new key using the operating system random source.
    #[must_use]
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    /// Restore a key from an unpadded Base64URL encoded 32-byte secret.
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let mut decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .context("stored device key is not valid Base64")?;
        if decoded.len() != 32 {
            decoded.zeroize();
            bail!("stored device key has an invalid length");
        }
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&decoded);
        decoded.zeroize();
        let key = Self(SigningKey::from_bytes(&bytes));
        bytes.zeroize();
        Ok(key)
    }

    /// Encode the secret for storage inside an OS credential store.
    #[must_use]
    pub fn secret_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(self.0.to_bytes()))
    }

    /// Return the unpadded Base64URL encoded raw 32-byte public key.
    #[must_use]
    pub fn public_key_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.verifying_key().to_bytes())
    }

    /// Sign arbitrary domain-separated bytes and return unpadded Base64URL.
    #[must_use]
    pub fn sign_base64(&self, message: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.0.sign(message).to_bytes())
    }
}

/// Verify an unpadded Base64URL Ed25519 signature. Used by fixtures and diagnostics.
pub fn verify_base64(public_key: &str, message: &[u8], signature: &str) -> Result<()> {
    let public = URL_SAFE_NO_PAD
        .decode(public_key)
        .context("public key is not valid Base64")?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .context("signature is not valid Base64")?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    VerifyingKey::from_bytes(&public)
        .context("invalid Ed25519 public key")?
        .verify(message, &Signature::from_bytes(&signature))
        .context("signature verification failed")
}

/// Normalize an account email without retaining the raw value beyond the call.
fn normalize_email(email: &str) -> Zeroizing<String> {
    Zeroizing::new(email.trim().to_lowercase())
}

/// Derive a deterministic pseudonymous account fingerprint with Argon2id.
///
/// The raw account email is used only in this function and is never serialized.
/// The server immediately HMACs this value with a private pepper. This is soft
/// duplicate detection, not an identity or OpenAI-verification claim.
pub fn account_fingerprint(email: &str) -> Result<String> {
    let normalized = normalize_email(email);
    if normalized.is_empty() || !normalized.contains('@') || normalized.len() > 320 {
        bail!("the managed ChatGPT account did not provide a usable email address");
    }
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|_| anyhow::anyhow!("invalid Argon2 parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; 32]);
    argon
        .hash_password_into(normalized.as_bytes(), FINGERPRINT_SALT, output.as_mut())
        .map_err(|_| anyhow::anyhow!("failed to derive account fingerprint"))?;
    Ok(format!("v1:{}", URL_SAFE_NO_PAD.encode(output.as_ref())))
}

/// Compute a lowercase SHA-256 digest.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_normalized_and_deterministic() {
        let first = account_fingerprint("  Builder@Example.COM ").unwrap_or_default();
        let second = account_fingerprint("builder@example.com").unwrap_or_default();
        assert_eq!(first, second);
        assert!(first.starts_with("v1:"));
        assert!(!first.contains("builder"));
    }

    #[test]
    fn generated_key_round_trips_and_verifies() {
        let key = DeviceKey::generate();
        let restored = DeviceKey::from_base64(&key.secret_base64())
            .unwrap_or_else(|_| panic!("generated keys must restore"));
        let message = b"project-relay-test";
        let signature = restored.sign_base64(message);
        assert!(verify_base64(&key.public_key_base64(), message, &signature).is_ok());
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
