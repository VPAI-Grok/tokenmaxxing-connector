//! Privacy-first connector library for Tokenmaxxing.
//!
//! The crate keeps Codex credentials and raw account identity on the user's
//! device. Only the fields represented by [`protocol::UsageSnapshotV1`] can be
//! serialized for upload.

pub mod api;
pub mod codex;
pub mod config;
pub mod crypto;
pub mod journal;
pub mod keystore;
pub mod launcher;
pub mod protocol;
pub mod storage;

/// Wire protocol version implemented by this connector.
pub const SCHEMA_VERSION: u8 = 1;

/// Consent statement version accepted by this connector.
pub const CONSENT_VERSION: u8 = 1;

/// Email fingerprint derivation version.
pub const FINGERPRINT_VERSION: u8 = 1;
