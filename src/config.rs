//! Durable non-secret connector configuration.

use crate::keystore::KeyStorage;
use crate::protocol::{validate_account_fingerprint, validate_base64url};
use crate::storage;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use url::Url;

/// Files owned by the connector.
#[derive(Debug, Clone)]
pub struct AppPaths {
    /// Directory containing non-secret config.
    pub config_dir: PathBuf,
    /// Directory containing receipts and optional file-backed secret.
    pub state_dir: PathBuf,
}

impl AppPaths {
    /// Resolve platform-native directories, or use an explicit isolated root.
    pub fn discover(override_root: Option<&Path>) -> Result<Self> {
        if let Some(root) = override_root {
            return Ok(Self {
                config_dir: root.join("config"),
                state_dir: root.join("state"),
            });
        }
        let dirs = ProjectDirs::from("dev", "project-relay", "relay")
            .context("the operating system did not provide an application config directory")?;
        Ok(Self {
            config_dir: dirs.config_dir().to_path_buf(),
            state_dir: dirs.data_local_dir().to_path_buf(),
        })
    }

    /// Main config path.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// Durable receipt directory.
    #[must_use]
    pub fn receipts_dir(&self) -> PathBuf {
        self.state_dir.join("receipts")
    }

    /// Crash-recoverable exact-body retry journal.
    #[must_use]
    pub fn pending_upload_file(&self) -> PathBuf {
        self.state_dir.join("pending-upload-v1.json")
    }
}

/// Explicit automatic-sync settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoSyncConfig {
    /// User consented to background sync.
    pub enabled: bool,
    /// Minimum minutes between syncs.
    pub interval_minutes: u32,
}

impl Default for AutoSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: 30,
        }
    }
}

/// Non-secret connector state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// Config file format version.
    pub config_version: u8,
    /// Tokenmaxxing API origin.
    pub server_url: Url,
    /// Locally generated device UUID.
    pub device_id: String,
    /// Unpadded Base64URL raw Ed25519 public key.
    pub public_key: String,
    /// Secret storage selected explicitly at connect time.
    pub key_storage: KeyStorage,
    /// Whether browser pairing was approved.
    pub paired: bool,
    /// Server Ed25519 receipt key pinned during same-origin pairing.
    pub receipt_public_key: Option<String>,
    /// Pseudonymous v1 account binding captured at connect time; never an email.
    #[serde(default)]
    pub account_fingerprint: Option<String>,
    /// Auto-sync opt-in.
    pub auto_sync: AutoSyncConfig,
    /// Latest accepted receipt UUID.
    pub last_receipt_id: Option<String>,
    /// Latest receipt chain hash.
    pub last_receipt_hash: Option<String>,
    /// Last completed upload time.
    pub last_synced_at: Option<DateTime<Utc>>,
}

impl Config {
    /// Construct disconnected state for a new device key.
    pub fn new(
        server_url: Url,
        device_id: String,
        public_key: String,
        key_storage: KeyStorage,
    ) -> Self {
        Self {
            config_version: 1,
            server_url,
            device_id,
            public_key,
            key_storage,
            paired: false,
            receipt_public_key: None,
            account_fingerprint: None,
            auto_sync: AutoSyncConfig::default(),
            last_receipt_id: None,
            last_receipt_hash: None,
            last_synced_at: None,
        }
    }

    /// Load config if the connector has been initialized.
    pub fn load(paths: &AppPaths) -> Result<Option<Self>> {
        let path = paths.config_file();
        storage::read_recoverable(&path, 256 * 1024, "connector config", |bytes| {
            let text = std::str::from_utf8(bytes).context("connector config was not UTF-8")?;
            let config: Self = toml::from_str(text).context("parse connector config")?;
            config.validate()?;
            Ok(config)
        })
    }

    /// Persist config while retaining a validated crash-recovery backup.
    pub fn save(&self, paths: &AppPaths) -> Result<()> {
        self.validate()?;
        let serialized = toml::to_string_pretty(self).context("serialize connector config")?;
        storage::write_recoverable(
            &paths.config_file(),
            serialized.as_bytes(),
            "connector config",
        )
    }

    /// Reject corrupted or unsupported config before use.
    pub fn validate(&self) -> Result<()> {
        if self.config_version != 1 {
            bail!("unsupported connector config version");
        }
        uuid::Uuid::parse_str(&self.device_id).context("invalid configured device ID")?;
        validate_base64url(&self.public_key, 32, "configured device public key")?;
        if self.paired {
            validate_base64url(
                self.receipt_public_key
                    .as_deref()
                    .context("paired config omitted the pinned receipt public key")?,
                32,
                "pinned receipt public key",
            )?;
        }
        if let Some(fingerprint) = &self.account_fingerprint {
            validate_account_fingerprint(fingerprint)?;
        }
        if self.server_url.cannot_be_a_base() || self.server_url.host_str().is_none() {
            bail!("server URL must be an absolute origin");
        }
        let local = matches!(
            self.server_url.host_str(),
            Some("localhost" | "127.0.0.1" | "::1")
        );
        if self.server_url.scheme() != "https" && !(local && self.server_url.scheme() == "http") {
            bail!("server URL must use HTTPS outside localhost");
        }
        if self.server_url.username() != ""
            || self.server_url.password().is_some()
            || self.server_url.query().is_some()
            || self.server_url.fragment().is_some()
        {
            bail!("server URL must not contain credentials, query, or fragment");
        }
        if !(5..=1_440).contains(&self.auto_sync.interval_minutes) {
            bail!("auto-sync interval must be between 5 and 1440 minutes");
        }
        Ok(())
    }

    /// Privacy-safe device identifier for user-visible diagnostics.
    #[must_use]
    pub fn redacted_device_id(&self) -> String {
        let suffix = self
            .device_id
            .get(self.device_id.len().saturating_sub(6)..)
            .unwrap_or("unknown");
        format!("device-…{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn config_round_trips_without_secrets() {
        let root = tempdir().unwrap_or_else(|_| panic!("temp dir"));
        let paths = AppPaths::discover(Some(root.path())).unwrap_or_else(|_| panic!("paths"));
        let public_key = crate::crypto::DeviceKey::generate().public_key_base64();
        let config = Config::new(
            Url::parse("https://jointokenmaxxing.com").unwrap_or_else(|_| panic!("url")),
            uuid::Uuid::new_v4().to_string(),
            public_key,
            KeyStorage::Keyring,
        );
        assert!(config.save(&paths).is_ok());
        let loaded = Config::load(&paths).ok().flatten();
        assert_eq!(loaded.map(|value| value.device_id), Some(config.device_id));
        let raw = fs::read_to_string(paths.config_file()).unwrap_or_default();
        assert!(!raw.contains("private"));
        assert!(!raw.contains("pollToken"));
    }

    #[test]
    fn config_rejects_non_http_local_and_insecure_remote_urls() {
        let key = crate::crypto::DeviceKey::generate().public_key_base64();
        for invalid in [
            "file:///tmp/relay",
            "ftp://localhost",
            "http://jointokenmaxxing.com",
        ] {
            let config = Config::new(
                Url::parse(invalid).unwrap_or_else(|_| panic!("url")),
                uuid::Uuid::new_v4().to_string(),
                key.clone(),
                KeyStorage::Keyring,
            );
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn config_recovers_validated_backup_after_interrupted_replace() {
        let root = tempdir().unwrap_or_else(|_| panic!("temp dir"));
        let paths = AppPaths::discover(Some(root.path())).unwrap_or_else(|_| panic!("paths"));
        let config = Config::new(
            Url::parse("https://jointokenmaxxing.com").unwrap_or_else(|_| panic!("url")),
            uuid::Uuid::new_v4().to_string(),
            crate::crypto::DeviceKey::generate().public_key_base64(),
            KeyStorage::Keyring,
        );
        assert!(config.save(&paths).is_ok());
        let backup = storage::backup_path(&paths.config_file()).unwrap_or_default();
        assert!(fs::rename(paths.config_file(), &backup).is_ok());

        let recovered = Config::load(&paths).ok().flatten();
        assert_eq!(
            recovered.map(|value| value.device_id),
            Some(config.device_id)
        );
        assert!(paths.config_file().is_file());
        assert!(!backup.exists());
    }

    #[cfg(unix)]
    #[test]
    fn config_refuses_symlinked_storage_directory() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap_or_else(|_| panic!("temp dir"));
        let outside = tempdir().unwrap_or_else(|_| panic!("outside temp dir"));
        let paths = AppPaths::discover(Some(root.path())).unwrap_or_else(|_| panic!("paths"));
        assert!(symlink(outside.path(), &paths.config_dir).is_ok());
        let config = Config::new(
            Url::parse("https://jointokenmaxxing.com").unwrap_or_else(|_| panic!("url")),
            uuid::Uuid::new_v4().to_string(),
            crate::crypto::DeviceKey::generate().public_key_base64(),
            KeyStorage::Keyring,
        );
        assert!(config.save(&paths).is_err());
        assert!(!outside.path().join("config.toml").exists());
    }
}
