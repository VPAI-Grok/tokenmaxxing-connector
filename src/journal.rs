//! Durable exact-body retry journal for one in-flight sync upload.

use crate::config::AppPaths;
use crate::crypto::sha256_hex;
use crate::protocol::{validate_base64url, Receipt, SnapshotAccepted, UsageSnapshotV1};
use crate::storage;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write as _;

const JOURNAL_VERSION: u8 = 1;
const SNAPSHOT_ENDPOINT: &str = "/api/v1/sync/snapshots";
const MAX_JOURNAL_BYTES: usize = 1024 * 1024;

/// A server response durably captured before receipt/config commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingAcceptance {
    /// Server-signed immutable receipt.
    pub receipt: Receipt,
    /// Eligibility returned with this exact accepted snapshot.
    pub leaderboard_eligible: bool,
}

/// Exact signed request retained until its receipt and chain head are committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingUpload {
    /// Local journal schema version.
    pub journal_version: u8,
    /// Fixed API endpoint for the exact request body.
    pub endpoint: String,
    /// Server nonce required to verify the retained device signature.
    pub server_nonce: String,
    /// Exact allowlisted signed request body, safe to retry byte-for-byte.
    pub snapshot: UsageSnapshotV1,
    /// Captured response, when received, retained until local commit completes.
    pub accepted: Option<PendingAcceptance>,
}

impl PendingUpload {
    /// Construct and validate a prepared exact-body retry journal.
    pub fn new(snapshot: UsageSnapshotV1, server_nonce: String) -> Result<Self> {
        let journal = Self {
            journal_version: JOURNAL_VERSION,
            endpoint: SNAPSHOT_ENDPOINT.into(),
            server_nonce,
            snapshot,
            accepted: None,
        };
        journal.validate()?;
        Ok(journal)
    }

    /// Validate the strict journal allowlist before using local state.
    pub fn validate(&self) -> Result<()> {
        if self.journal_version != JOURNAL_VERSION || self.endpoint != SNAPSHOT_ENDPOINT {
            bail!("unsupported pending-upload journal format");
        }
        validate_base64url(&self.server_nonce, 32, "pending server nonce")?;
        self.snapshot.validate()?;
        if let Some(accepted) = &self.accepted {
            accepted.receipt.validate()?;
            let snapshot_hash = sha256_hex(self.snapshot.canonical_payload()?.as_bytes());
            if accepted.receipt.snapshot_hash != snapshot_hash {
                bail!("pending receipt did not match the retained exact snapshot");
            }
        }
        Ok(())
    }

    /// Record the verified server response before advancing any local chain state.
    pub fn record_acceptance(&mut self, accepted: SnapshotAccepted) -> Result<()> {
        self.accepted = Some(PendingAcceptance {
            receipt: accepted.receipt,
            leaderboard_eligible: accepted.leaderboard_eligible,
        });
        self.validate()
    }

    /// Persist this journal using a recoverable private-file replacement.
    pub fn save(&self, paths: &AppPaths) -> Result<()> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self).context("serialize pending upload journal")?;
        storage::write_recoverable(
            &paths.pending_upload_file(),
            &bytes,
            "pending upload journal",
        )
    }

    /// Persist the first prepared journal without replacing a concurrent sync.
    pub fn save_new(&self, paths: &AppPaths) -> Result<()> {
        self.validate()?;
        storage::ensure_directory(&paths.state_dir, "connector state directory")?;
        let path = paths.pending_upload_file();
        let backup = storage::backup_path(&path)?;
        if backup
            .try_exists()
            .context("inspect pending upload recovery backup")?
        {
            bail!("a pending upload recovery backup already exists; retry sync to recover it");
        }
        let bytes = serde_json::to_vec_pretty(self).context("serialize pending upload journal")?;
        let mut file = storage::create_private_new(&path, "pending upload journal")?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .context("write and flush pending upload journal")?;
        storage::sync_parent(&path)
    }

    /// Load a strict pending journal, recovering its validated backup if needed.
    pub fn load(paths: &AppPaths) -> Result<Option<Self>> {
        storage::read_recoverable(
            &paths.pending_upload_file(),
            MAX_JOURNAL_BYTES,
            "pending upload journal",
            |bytes| {
                let journal: Self =
                    serde_json::from_slice(bytes).context("parse pending upload journal")?;
                journal.validate()?;
                Ok(journal)
            },
        )
    }

    /// Remove the committed primary and backup journal files.
    pub fn remove(paths: &AppPaths) -> Result<()> {
        storage::remove_recoverable(&paths.pending_upload_file(), "pending upload journal")
    }
}
