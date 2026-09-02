//! Cross-language canonicalization and signature fixture verification.

use project_relay_connector::crypto::{sha256_hex, verify_base64, DeviceKey};
use project_relay_connector::protocol::{Receipt, UsageSnapshotV1};
use serde::Deserialize;

const GOLDEN_FIXTURE_SHA256: &str =
    "7e69f64729b14b4cc9bac4bd13c890101fde0fee8e17acef8aea7742c99cce16";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoldenFixture {
    private_key: String,
    public_key: String,
    server_nonce: String,
    snapshot: UsageSnapshotV1,
    snapshot_canonical_payload: String,
    snapshot_payload_sha256: String,
    snapshot_signing_text: String,
    receipt: Receipt,
    receipt_signing_text: String,
    warning: String,
}

#[test]
fn rust_matches_the_shared_relay_json_v1_golden_vector() {
    let raw = include_str!("fixtures/relay-json-v1-golden.json");
    assert_eq!(
        sha256_hex(raw.as_bytes()),
        GOLDEN_FIXTURE_SHA256,
        "fixture bytes must match the server contracts mirror"
    );
    let fixture: GoldenFixture =
        serde_json::from_str(raw).unwrap_or_else(|_| panic!("golden fixture must parse"));
    assert!(fixture.warning.contains("never use"));

    let key = DeviceKey::from_base64(&fixture.private_key)
        .unwrap_or_else(|_| panic!("fixture key must parse"));
    assert_eq!(key.public_key_base64(), fixture.public_key);
    assert_eq!(
        fixture.snapshot.canonical_payload().unwrap_or_default(),
        fixture.snapshot_canonical_payload
    );
    assert_eq!(
        sha256_hex(fixture.snapshot_canonical_payload.as_bytes()),
        fixture.snapshot_payload_sha256
    );
    assert_eq!(
        String::from_utf8(
            fixture
                .snapshot
                .signing_bytes(&fixture.server_nonce)
                .unwrap_or_default()
        )
        .unwrap_or_default(),
        fixture.snapshot_signing_text
    );
    assert!(verify_base64(
        &fixture.public_key,
        fixture.snapshot_signing_text.as_bytes(),
        &fixture.snapshot.signature
    )
    .is_ok());

    assert_eq!(
        String::from_utf8(fixture.receipt.signing_bytes().unwrap_or_default()).unwrap_or_default(),
        fixture.receipt_signing_text
    );
    assert!(verify_base64(
        &fixture.public_key,
        fixture.receipt_signing_text.as_bytes(),
        &fixture.receipt.server_signature
    )
    .is_ok());
}
