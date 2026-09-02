//! Maintainer utility for regenerating the cross-language protocol fixture.

use project_relay_connector::crypto::{sha256_hex, DeviceKey};
use project_relay_connector::protocol::{
    DailyUsageBucket, QuarantineStatus, Receipt, RiskReason, TrustTier, UsageMetrics,
    UsageSnapshotV1,
};
use serde_json::json;

fn main() -> anyhow::Result<()> {
    // Public test vector only: bytes 0x00..0x1f. Never use this key in production.
    let private_key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    let server_nonce = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
    let key = DeviceKey::from_base64(private_key)?;
    let mut snapshot = UsageSnapshotV1 {
        schema_version: 1,
        device_id: "f19c7b47-0470-4410-bf9b-7f8a70d1f8fe".into(),
        challenge_id: "7413d0fb-56e0-49c1-b520-e263f39d4040".into(),
        connector_version: "0.1.0".into(),
        codex_version: "codex-cli 1.2.3".into(),
        observed_at: "2026-08-31T16:00:00Z".into(),
        fingerprint_version: 1,
        account_fingerprint: "v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        consent_version: 1,
        metrics: UsageMetrics {
            lifetime_tokens: Some("1234567".into()),
            peak_daily_tokens: Some("45678".into()),
            longest_running_turn_sec: Some("540".into()),
            current_streak_days: Some(8),
            longest_streak_days: Some(14),
            daily_usage_buckets: Some(vec![DailyUsageBucket {
                start_date: "2026-08-30".into(),
                tokens: "12345".into(),
            }]),
        },
        previous_receipt_hash: None,
        signature: String::new(),
    };
    let canonical_payload = snapshot.canonical_payload()?;
    let snapshot_signing_text = String::from_utf8(snapshot.signing_bytes(server_nonce)?)?;
    snapshot.signature = key.sign_base64(snapshot_signing_text.as_bytes());

    let mut receipt = Receipt {
        receipt_id: "f3163c42-732c-49f2-bf7f-6c4b194efb7b".into(),
        accepted_at: "2026-08-31T16:00:01Z".into(),
        trust_tier: TrustTier::Synced,
        sequence: 1,
        snapshot_hash: sha256_hex(canonical_payload.as_bytes()),
        receipt_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        server_signature: String::new(),
        quarantine_status: QuarantineStatus::Quarantined,
        reason_codes: vec![RiskReason::ObservedAtSkew],
    };
    let receipt_signing_text = String::from_utf8(receipt.signing_bytes()?)?;
    receipt.server_signature = key.sign_base64(receipt_signing_text.as_bytes());

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "warning": "Fixture-only deterministic private key; never use for a real device",
            "privateKey": private_key,
            "publicKey": key.public_key_base64(),
            "serverNonce": server_nonce,
            "snapshot": snapshot,
            "snapshotCanonicalPayload": canonical_payload,
            "snapshotPayloadSha256": sha256_hex(canonical_payload.as_bytes()),
            "snapshotSigningText": snapshot_signing_text,
            "receipt": receipt,
            "receiptSigningText": receipt_signing_text
        }))?
    );
    Ok(())
}
