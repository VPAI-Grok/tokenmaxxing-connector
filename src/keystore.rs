//! OS credential-store integration with an explicit file fallback.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const SERVICE_NAME: &str = "project-relay-connector";

/// User-selected secret storage backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStorage {
    /// macOS Keychain, Windows Credential Manager, or Linux Secret Service.
    Keyring,
    /// Permission-restricted local file, enabled only by explicit user choice.
    SecureFile,
}

/// Secrets that must never appear in config, logs, or command output.
#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct SecretBundle {
    /// Unpadded Base64URL 32-byte Ed25519 signing key.
    pub signing_key: String,
    /// Ephemeral pairing-only token. Cleared after every terminal pairing status.
    pub pairing_poll_token: Option<String>,
}

impl SecretBundle {
    /// Construct a bundle with no live pairing credential.
    #[must_use]
    pub fn new(signing_key: String) -> Self {
        Self {
            signing_key,
            pairing_poll_token: None,
        }
    }
}

/// Load the device secret using the configured backend.
pub fn load(storage: KeyStorage, device_id: &str, state_dir: &Path) -> Result<SecretBundle> {
    let raw = match storage {
        KeyStorage::Keyring => {
            let entry = keyring::Entry::new(SERVICE_NAME, device_id)
                .context("open operating-system credential entry")?;
            Zeroizing::new(
                entry
                    .get_password()
                    .context("read device key from operating-system credential store")?,
            )
        }
        KeyStorage::SecureFile => {
            let path = secret_file(state_dir);
            reject_symlink(&path)?;
            Zeroizing::new(
                fs::read_to_string(&path)
                    .with_context(|| format!("read secure fallback at {}", path.display()))?,
            )
        }
    };
    serde_json::from_str(&raw).context("decode stored device secret")
}

/// Persist the device secret using the configured backend.
pub fn save(
    storage: KeyStorage,
    device_id: &str,
    state_dir: &Path,
    bundle: &SecretBundle,
) -> Result<()> {
    let mut raw = Zeroizing::new(serde_json::to_string(bundle).context("encode device secret")?);
    match storage {
        KeyStorage::Keyring => {
            keyring::Entry::new(SERVICE_NAME, device_id)
                .context("open operating-system credential entry")?
                .set_password(&raw)
                .context("save device key in operating-system credential store")?;
        }
        KeyStorage::SecureFile => save_secure_file(state_dir, raw.as_bytes())?,
    }
    raw.zeroize();
    Ok(())
}

/// Remove connector-owned secret material.
pub fn delete(storage: KeyStorage, device_id: &str, state_dir: &Path) -> Result<()> {
    match storage {
        KeyStorage::Keyring => {
            let entry = keyring::Entry::new(SERVICE_NAME, device_id)
                .context("open operating-system credential entry")?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(error) => Err(error).context("delete device key from credential store"),
            }
        }
        KeyStorage::SecureFile => {
            let path = secret_file(state_dir);
            if !path.exists() {
                return Ok(());
            }
            reject_symlink(&path)?;
            fs::remove_file(&path)
                .with_context(|| format!("delete secure fallback at {}", path.display()))
        }
    }
}

fn secret_file(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join("device-secret.json")
}

fn reject_symlink(path: &Path) -> Result<()> {
    if path.exists() && fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("refusing to use a symlink as the device secret file");
    }
    Ok(())
}

fn save_secure_file(state_dir: &Path, bytes: &[u8]) -> Result<()> {
    fs::create_dir_all(state_dir).context("create connector state directory")?;
    let path = secret_file(state_dir);
    reject_symlink(&path)?;
    let temporary = state_dir.join(format!("device-secret-{}.tmp", uuid::Uuid::new_v4()));

    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .context("create secure secret file")?;
    file.write_all(bytes).context("write secure secret file")?;
    file.sync_all().context("flush secure secret file")?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    if path.exists() {
        fs::remove_file(&path).context("replace previous secure secret file")?;
    }
    fs::rename(&temporary, &path).context("install secure secret file")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn explicit_secure_file_round_trip_and_delete() {
        let root = tempdir().unwrap_or_else(|_| panic!("temp dir"));
        let bundle = SecretBundle::new("test-secret".into());
        assert!(save(KeyStorage::SecureFile, "device", root.path(), &bundle).is_ok());
        let restored = load(KeyStorage::SecureFile, "device", root.path());
        assert_eq!(
            restored.ok().map(|value| value.signing_key.clone()),
            Some("test-secret".into())
        );
        assert!(delete(KeyStorage::SecureFile, "device", root.path()).is_ok());
        assert!(!secret_file(root.path()).exists());
    }
}
