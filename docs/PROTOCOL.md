# Tokenmaxxing Connector Protocol v1

This document is normative for the connector. The server contract and golden
fixture must produce identical bytes.

> **Upstream release risk:** [Codex `app-server`](https://developers.openai.com/codex/app-server/)
> is experimental and unsupported for production. This connector remains a
> technical preview while compatibility evidence accumulates from voluntary
> open-beta users; registration and source installation remain open. Usage
> responses can lag; a sync is a timestamped observation, not a real-time
> activity signal.

## Encoding

- JSON property names use lower camel case.
- Counters that can exceed JavaScript's safe range are non-negative canonical
  decimal strings (`"0"` or a nonzero digit followed by digits).
- Ed25519 public keys and signatures are raw bytes encoded as unpadded Base64URL.
- Hashes are lowercase SHA-256 hexadecimal strings.
- Times are RFC 3339 UTC strings; bucket dates are `YYYY-MM-DD` UTC.
- `null` is preserved. Missing upstream values are never converted to zero.

`relay-json-v1` canonical JSON sorts object keys lexicographically at every
depth, preserves array order, uses normal JSON string escaping, and emits no
insignificant whitespace.

## Pairing

`POST /api/v1/device/pairings` starts pairing with:

```json
{ "deviceId": "uuid", "publicKey": "base64url", "connectorVersion": "semver" }
```

The response supplies `pairingId`, `userCode`, same-origin `verificationUri`,
`expiresAt`, `pollIntervalSeconds`, `status`, a short-lived `pollToken`, and the
server `receiptPublicKey`. The connector pins that receipt key after same-origin
TLS pairing. V1 never silently rotates it; a changed key requires re-pairing.
The connector reads status at `GET /api/v1/device/pairings/{pairingId}` using
`Authorization: Bearer <pollToken>`. The poll credential cannot authorize or
mutate any other resource and is erased after a terminal status.

## Signed challenge request

`POST /api/v1/sync/challenges` uses body
`{deviceId, previousReceiptHash}` and headers `X-Relay-Device-Id`,
`X-Relay-Timestamp`, and `X-Relay-Signature`. Sign these UTF-8 bytes:

```text
POST\n/api/v1/sync/challenges\n<timestamp>\n<sha256hex(canonical request body)>
```

The result contains `challengeId`, `serverNonce`, `expiresAt`, algorithm
`Ed25519`, and canonicalization `relay-json-v1`.

## Signed snapshot

The body is exactly the schema in
[`schemas/usage-snapshot-v1.schema.json`](../schemas/usage-snapshot-v1.schema.json).
Remove `signature`, canonicalize the remaining object, SHA-256 that UTF-8 JSON,
then sign:

```text
POST\n/api/v1/sync/snapshots\n<challengeId>\n<serverNonce>\n<sha256hex(canonical payload)>
```

The server binds the challenge to the device, enforces a two-minute expiry and
one-use consumption transactionally, and returns an immutable signed receipt.

After confirmation and before the HTTP upload, the connector durably journals
the exact signed snapshot plus its server nonce. A retry sends that same body;
it never regenerates a snapshot against a stale receipt-chain head. The server
therefore must handle an identical retry of an already accepted signed snapshot
idempotently and return its original immutable receipt.

## Signed receipt read and disconnect

Receipt retrieval signs:

```text
GET\n/api/v1/sync/receipts/<receiptId>\n<timestamp>
```

Before persisting a receipt or advancing `previousReceiptHash`, the connector
verifies `serverSignature` against the pinned key over canonical JSON of every
receipt field except `serverSignature`. It also requires `snapshotHash` to equal
SHA-256 of the exact canonical local snapshot and `sequence` to continue the
locally verified immutable receipt chain. Verification failure is fail-closed.

The pseudonymous `accountFingerprint` observed at connection is retained as the
device's local account binding. A later mismatch is rejected before a challenge
or snapshot upload; changing managed ChatGPT accounts requires disconnecting and
pairing again. The raw account email is never retained.

Disconnect uses `{deviceId}` and signs:

```text
POST\n/api/v1/device/disconnect\n<timestamp>\n<sha256hex(canonical request body)>
```

All API responses are `{schemaVersion:1,requestId,data}` or
`{schemaVersion:1,requestId,error:{code,message,retryable}}`.

Public clients must display both “last synced” and the latest available
“provider data through” date when present. They must never promise real-time
freshness.

## Golden fixture

[`tests/fixtures/relay-json-v1-golden.json`](../tests/fixtures/relay-json-v1-golden.json)
contains a deterministic private test key, canonical payload, signing text,
public key, and signature. The private key is fixture-only and must never be
used by a real device.
