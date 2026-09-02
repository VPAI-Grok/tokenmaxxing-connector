//! Versioned Tokenmaxxing wire types and canonicalization.

use crate::crypto::sha256_hex;
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Write as _;

/// A single UTC daily token bucket returned by Codex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DailyUsageBucket {
    /// Inclusive UTC start date (`YYYY-MM-DD`).
    pub start_date: String,
    /// Non-negative token count encoded as a decimal string.
    pub tokens: String,
}

/// The complete and exclusive metrics upload allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageMetrics {
    /// Lifetime token activity, if provided upstream.
    pub lifetime_tokens: Option<String>,
    /// Highest daily token activity, if provided upstream.
    pub peak_daily_tokens: Option<String>,
    /// Longest running turn in seconds, if provided upstream.
    pub longest_running_turn_sec: Option<String>,
    /// Current consecutive active-day streak, if provided upstream.
    pub current_streak_days: Option<u32>,
    /// Longest consecutive active-day streak, if provided upstream.
    pub longest_streak_days: Option<u32>,
    /// Available UTC daily usage history, if provided upstream.
    pub daily_usage_buckets: Option<Vec<DailyUsageBucket>>,
}

impl UsageMetrics {
    /// Validate decimal strings, dates, and bucket ordering before preview or upload.
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("lifetimeTokens", self.lifetime_tokens.as_deref()),
            ("peakDailyTokens", self.peak_daily_tokens.as_deref()),
            (
                "longestRunningTurnSec",
                self.longest_running_turn_sec.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                validate_decimal(name, value)?;
            }
        }

        if self
            .current_streak_days
            .is_some_and(|value| value > 100_000)
            || self
                .longest_streak_days
                .is_some_and(|value| value > 100_000)
        {
            bail!("streak values must not exceed 100000");
        }
        if self
            .current_streak_days
            .zip(self.longest_streak_days)
            .is_some_and(|(current, longest)| current > longest)
        {
            bail!("current streak cannot exceed longest streak");
        }

        if let Some(buckets) = &self.daily_usage_buckets {
            if buckets.len() > 800 {
                bail!("daily usage history must not exceed 800 buckets");
            }
            let mut previous = None;
            for bucket in buckets {
                chrono::NaiveDate::parse_from_str(&bucket.start_date, "%Y-%m-%d")
                    .with_context(|| format!("invalid daily bucket date: {}", bucket.start_date))?;
                validate_decimal("dailyUsageBuckets.tokens", &bucket.tokens)?;
                if previous
                    .as_deref()
                    .is_some_and(|date| date >= bucket.start_date.as_str())
                {
                    bail!("daily usage buckets must be strictly ordered and unique");
                }
                previous = Some(bucket.start_date.clone());
            }
        }
        Ok(())
    }
}

fn validate_decimal(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        bail!("{name} must be a canonical non-negative decimal string");
    }
    let parsed = value
        .parse::<u64>()
        .with_context(|| format!("{name} exceeds the supported range"))?;
    if parsed > i64::MAX as u64 {
        bail!("{name} exceeds PostgreSQL bigint range");
    }
    Ok(())
}

/// The only payload the connector is allowed to upload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageSnapshotV1 {
    /// Always `1` for this shape.
    pub schema_version: u8,
    /// Locally generated UUID identifying the signing key.
    pub device_id: String,
    /// Server-issued, one-use challenge UUID.
    pub challenge_id: String,
    /// Connector semantic version.
    pub connector_version: String,
    /// Locally executed Codex CLI version string.
    pub codex_version: String,
    /// UTC time at which Codex returned the metrics.
    pub observed_at: String,
    /// Account fingerprint algorithm version.
    pub fingerprint_version: u8,
    /// Pseudonymous deterministic account fingerprint. Never a raw email.
    pub account_fingerprint: String,
    /// Consent language version accepted during pairing.
    pub consent_version: u8,
    /// Strict upload allowlist.
    pub metrics: UsageMetrics,
    /// SHA-256 receipt chain head, if a previous receipt exists.
    pub previous_receipt_hash: Option<String>,
    /// Unpadded Base64URL Ed25519 signature over [`Self::signing_bytes`].
    pub signature: String,
}

impl UsageSnapshotV1 {
    /// Return the canonical JSON payload, excluding the signature field.
    pub fn canonical_payload(&self) -> Result<String> {
        let mut value = serde_json::to_value(self).context("serialize snapshot")?;
        let object = value
            .as_object_mut()
            .context("snapshot must serialize as an object")?;
        object.remove("signature");
        canonical_json(&value)
    }

    /// Return the domain-separated snapshot signing bytes.
    pub fn signing_bytes(&self, server_nonce: &str) -> Result<Vec<u8>> {
        let digest = sha256_hex(self.canonical_payload()?.as_bytes());
        Ok(format!(
            "POST\n/api/v1/sync/snapshots\n{}\n{}\n{}",
            self.challenge_id, server_nonce, digest
        )
        .into_bytes())
    }

    /// Validate invariants shared by preview and upload.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.fingerprint_version != 1 || self.consent_version != 1 {
            bail!("unsupported protocol version in snapshot");
        }
        uuid::Uuid::parse_str(&self.device_id).context("invalid deviceId")?;
        uuid::Uuid::parse_str(&self.challenge_id).context("invalid challengeId")?;
        chrono::DateTime::parse_from_rfc3339(&self.observed_at).context("invalid observedAt")?;
        if self.connector_version.trim().is_empty() || self.connector_version.len() > 64 {
            bail!("connectorVersion must contain 1 to 64 characters");
        }
        if self.codex_version.trim().is_empty() || self.codex_version.len() > 64 {
            bail!("codexVersion must contain 1 to 64 characters");
        }
        validate_account_fingerprint(&self.account_fingerprint)?;
        if let Some(hash) = &self.previous_receipt_hash {
            validate_hash(hash)?;
        }
        validate_base64url(&self.signature, 64, "snapshot signature")?;
        self.metrics.validate()
    }
}

/// Start-pairing request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingStartRequest<'a> {
    /// Device UUID.
    pub device_id: &'a str,
    /// Unpadded Base64URL raw 32-byte Ed25519 public key.
    pub public_key: &'a str,
    /// Connector semantic version.
    pub connector_version: &'a str,
}

/// Pairing start result.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairingStart {
    /// Pairing UUID.
    pub pairing_id: String,
    /// Short browser entry code.
    pub user_code: String,
    /// Browser approval page.
    pub verification_uri: String,
    /// Expiry time.
    pub expires_at: String,
    /// Minimum poll interval.
    pub poll_interval_seconds: u64,
    /// Initial status.
    pub status: PairingStatus,
    /// Ephemeral credential used only for polling.
    pub poll_token: String,
    /// Server receipt verification key pinned during pairing.
    pub receipt_public_key: String,
}

/// Pairing lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PairingStatus {
    /// Waiting for browser approval.
    Pending,
    /// Approved and device public key registered.
    Approved,
    /// Pairing expired.
    Expired,
    /// Pairing was denied.
    Denied,
}

/// Pairing poll result.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairingPoll {
    /// Current status.
    pub status: PairingStatus,
    /// Expiry time.
    pub expires_at: String,
    /// Approval time when approved.
    pub approved_at: Option<String>,
}

/// One-use challenge request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRequest<'a> {
    /// Registered device UUID.
    pub device_id: &'a str,
    /// Current receipt chain head.
    pub previous_receipt_hash: Option<&'a str>,
}

/// Signed request to revoke this device and hide its profile.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisconnectRequest<'a> {
    /// Registered device UUID.
    pub device_id: &'a str,
}

/// Result of a remote disconnect.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisconnectResult {
    /// The device is no longer accepted for sync.
    pub disconnected: bool,
    /// The owning public profile was hidden immediately.
    pub profile_hidden: bool,
}

/// One-use challenge result.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncChallenge {
    /// Challenge UUID.
    pub challenge_id: String,
    /// Server-generated, unpadded Base64URL nonce bound to this challenge.
    pub server_nonce: String,
    /// Expiry time.
    pub expires_at: String,
    /// Signature algorithm (`Ed25519`).
    pub algorithm: String,
    /// Canonicalization algorithm (`relay-json-v1`).
    pub canonicalization: String,
}

/// Server-signed immutable sync receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    /// Receipt UUID.
    pub receipt_id: String,
    /// Server acceptance time.
    pub accepted_at: String,
    /// Public trust level computed by the server.
    pub trust_tier: TrustTier,
    /// Monotonic per-device receipt sequence.
    pub sequence: u64,
    /// SHA-256 hash of the accepted snapshot.
    pub snapshot_hash: String,
    /// SHA-256 receipt chain hash.
    pub receipt_hash: String,
    /// Server receipt signature.
    pub server_signature: String,
    /// Quarantine state.
    pub quarantine_status: QuarantineStatus,
    /// Machine-readable quarantine reasons.
    pub reason_codes: Vec<RiskReason>,
}

impl Receipt {
    /// Validate fields required for durable local chain state.
    pub fn validate(&self) -> Result<()> {
        uuid::Uuid::parse_str(&self.receipt_id).context("invalid receipt id")?;
        validate_hash(&self.snapshot_hash)?;
        validate_hash(&self.receipt_hash)?;
        chrono::DateTime::parse_from_rfc3339(&self.accepted_at)
            .context("invalid receipt acceptedAt")?;
        if self.sequence == 0 {
            bail!("receipt sequence must be positive");
        }
        validate_base64url(&self.server_signature, 64, "receipt signature")?;
        Ok(())
    }

    /// Canonical bytes signed by the Tokenmaxxing receipt key.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::json!({
            "receiptId": self.receipt_id,
            "acceptedAt": self.accepted_at,
            "trustTier": self.trust_tier,
            "sequence": self.sequence,
            "snapshotHash": self.snapshot_hash,
            "receiptHash": self.receipt_hash,
            "quarantineStatus": self.quarantine_status,
            "reasonCodes": self.reason_codes,
        });
        Ok(canonical_json(&value)?.into_bytes())
    }
}

/// Server trust tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustTier {
    /// Valid sync that has not met the age/count establishment gate.
    Synced,
    /// At least three accepted syncs spanning 48 hours.
    Established,
}

/// Quarantine state attached to a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuarantineStatus {
    /// No active quarantine.
    Clear,
    /// Withheld from rankings pending review.
    Quarantined,
}

/// Machine-readable risk reason emitted by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskReason {
    /// Fingerprint changed for a profile.
    AccountFingerprintChanged,
    /// Receipt chain did not match.
    ChainBreak,
    /// Daily token activity was an outlier.
    DailyOutlier,
    /// Too many active/replaced devices.
    DeviceChurn,
    /// Previously observed history changed.
    HistoryRewrite,
    /// Lifetime total decreased.
    LifetimeDecrease,
    /// Lifetime total jumped unexpectedly.
    LifetimeJump,
    /// Observation timestamp was implausible.
    ObservedAtSkew,
}

/// Snapshot upload result.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotAccepted {
    /// Durable receipt.
    pub receipt: Receipt,
    /// Whether this snapshot can affect public rankings.
    pub leaderboard_eligible: bool,
}

/// Uniform successful API response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiEnvelope<T> {
    /// Response schema version.
    pub schema_version: u8,
    /// Correlation UUID.
    pub request_id: String,
    /// Endpoint-specific response.
    pub data: T,
}

/// Uniform API error response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorEnvelope {
    /// Response schema version.
    pub schema_version: u8,
    /// Correlation UUID.
    pub request_id: String,
    /// Safe error detail.
    pub error: ApiError,
}

/// Safe server error fields.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    /// Machine-readable code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Whether a retry is appropriate.
    pub retryable: bool,
}

fn validate_hash(hash: &str) -> Result<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("receipt hash must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

/// Validate the exact versioned pseudonymous account-binding representation.
pub fn validate_account_fingerprint(fingerprint: &str) -> Result<()> {
    let encoded = fingerprint
        .strip_prefix("v1:")
        .context("accountFingerprint must use the v1 prefix")?;
    if encoded.len() != 43 {
        bail!("accountFingerprint must contain a 43-character Base64URL digest");
    }
    validate_base64url(encoded, 32, "accountFingerprint digest")
}

/// Validate and decode an unpadded Base64URL field with an exact byte length.
pub fn validate_base64url(value: &str, expected_bytes: usize, name: &str) -> Result<()> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("{name} must be unpadded Base64URL"))?;
    if decoded.len() != expected_bytes {
        bail!("{name} has an invalid decoded length");
    }
    Ok(())
}

/// Serialize JSON using Tokenmaxxing's compatibility-preserving `relay-json-v1` rules.
///
/// Object keys are lexicographically sorted, arrays retain order, strings use
/// standard JSON escaping, and no insignificant whitespace is emitted.
pub fn canonical_json(value: &Value) -> Result<String> {
    fn write_value(value: &Value, output: &mut String) -> Result<()> {
        match value {
            Value::Null => output.push_str("null"),
            Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => output.push_str(&value.to_string()),
            Value::String(value) => output.push_str(&serde_json::to_string(value)?),
            Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    write_value(value, output)?;
                }
                output.push(']');
            }
            Value::Object(values) => {
                output.push('{');
                let mut keys = values.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(key)?);
                    output.push(':');
                    write_value(&values[key], output)?;
                }
                output.push('}');
            }
        }
        Ok(())
    }

    let mut output = String::new();
    write_value(value, &mut output)?;
    Ok(output)
}

/// Redacted, user-visible preview which intentionally excludes device signature.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotPreview<'a> {
    /// Schema version.
    pub schema_version: u8,
    /// Device ID.
    pub device_id: &'a str,
    /// Connector version.
    pub connector_version: &'a str,
    /// Codex version.
    pub codex_version: &'a str,
    /// Observation time.
    pub observed_at: &'a str,
    /// Pseudonymous fingerprint.
    pub account_fingerprint: &'a str,
    /// Exact allowlisted metrics.
    pub metrics: &'a UsageMetrics,
    /// Receipt chain head.
    pub previous_receipt_hash: Option<&'a str>,
    /// Explicit exclusions shown for privacy review.
    pub never_collected: [&'static str; 9],
}

impl<'a> SnapshotPreview<'a> {
    /// Construct the privacy review representation of a snapshot.
    pub fn from_snapshot(snapshot: &'a UsageSnapshotV1) -> Self {
        Self {
            schema_version: snapshot.schema_version,
            device_id: &snapshot.device_id,
            connector_version: &snapshot.connector_version,
            codex_version: &snapshot.codex_version,
            observed_at: &snapshot.observed_at,
            account_fingerprint: &snapshot.account_fingerprint,
            metrics: &snapshot.metrics,
            previous_receipt_hash: snapshot.previous_receipt_hash.as_deref(),
            never_collected: [
                "raw account email",
                "prompts or responses",
                "source code",
                "filenames or repository paths",
                "hostname",
                "Codex credentials or installation identifiers",
                "plan type",
                "raw provider payloads",
                "undocumented fields",
            ],
        }
    }
}

/// Build the signed request string for challenge creation.
pub fn challenge_request_signing_bytes(
    request: &ChallengeRequest<'_>,
    timestamp: &str,
) -> Result<Vec<u8>> {
    let canonical = canonical_json(&serde_json::to_value(request)?)?;
    Ok(format!(
        "POST\n/api/v1/sync/challenges\n{timestamp}\n{}",
        sha256_hex(canonical.as_bytes())
    )
    .into_bytes())
}

/// Build the signed request string for device revocation.
pub fn disconnect_request_signing_bytes(
    request: &DisconnectRequest<'_>,
    timestamp: &str,
) -> Result<Vec<u8>> {
    let canonical = canonical_json(&serde_json::to_value(request)?)?;
    Ok(format!(
        "POST\n/api/v1/device/disconnect\n{timestamp}\n{}",
        sha256_hex(canonical.as_bytes())
    )
    .into_bytes())
}

/// Build the signed request string for receipt retrieval.
pub fn receipt_request_signing_bytes(receipt_id: &str, timestamp: &str) -> Vec<u8> {
    let mut value = String::new();
    let _ = write!(
        value,
        "GET\n/api/v1/sync/receipts/{receipt_id}\n{timestamp}"
    );
    value.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_nested_keys_and_preserves_arrays() {
        let value = json!({"z": 1, "a": {"two": 2, "one": 1}, "list": [3, 2, 1]});
        let canonical = canonical_json(&value).unwrap_or_default();
        assert_eq!(canonical, r#"{"a":{"one":1,"two":2},"list":[3,2,1],"z":1}"#);
    }

    #[test]
    fn metrics_reject_noncanonical_decimal_strings() {
        let metrics = UsageMetrics {
            lifetime_tokens: Some("01".into()),
            peak_daily_tokens: None,
            longest_running_turn_sec: None,
            current_streak_days: None,
            longest_streak_days: None,
            daily_usage_buckets: None,
        };
        assert!(metrics.validate().is_err());
    }

    #[test]
    fn account_fingerprint_requires_exact_v1_base64url_digest() {
        assert!(validate_account_fingerprint(&format!("v1:{}", "A".repeat(43))).is_ok());
        for invalid in [
            format!("v2:{}", "A".repeat(43)),
            format!("v1:{}", "A".repeat(42)),
            format!("v1:{}=", "A".repeat(42)),
            "v1:not+base64/url".to_owned(),
        ] {
            assert!(validate_account_fingerprint(&invalid).is_err());
        }
    }

    #[test]
    fn signing_bytes_never_include_signature() {
        let snapshot = UsageSnapshotV1 {
            schema_version: 1,
            device_id: "00000000-0000-4000-8000-000000000000".into(),
            challenge_id: "00000000-0000-4000-8000-000000000001".into(),
            connector_version: "0.1.0".into(),
            codex_version: "codex-cli 1.0.0".into(),
            observed_at: "2026-08-31T12:00:00Z".into(),
            fingerprint_version: 1,
            account_fingerprint: "v1:test".into(),
            consent_version: 1,
            metrics: UsageMetrics {
                lifetime_tokens: Some("123".into()),
                peak_daily_tokens: None,
                longest_running_turn_sec: None,
                current_streak_days: None,
                longest_streak_days: None,
                daily_usage_buckets: None,
            },
            previous_receipt_hash: None,
            signature: "secret-signature".into(),
        };
        let bytes = snapshot.signing_bytes("nonce").unwrap_or_default();
        let body = String::from_utf8(bytes).unwrap_or_default();
        assert!(body.starts_with("POST\n/api/v1/sync/snapshots\n"));
        assert!(!body.contains("signature"));
        assert!(!body.contains("secret-signature"));
    }
}
