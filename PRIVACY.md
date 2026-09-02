# Privacy Notice (Consent Version 1)

Last updated: 2026-08-31

Tokenmaxxing Connector is designed to make its network payload reviewable.
Before each interactive upload, it prints the exact JSON request body. Automatic
sync is off by default and requires a separate opt-in.

## Data uploaded

Only these fields can be serialized by `UsageSnapshotV1`:

- protocol, connector, Codex, fingerprint, and consent versions;
- a random device UUID and a one-use server challenge UUID;
- observation timestamp and previous receipt hash;
- an Argon2id-derived pseudonymous account fingerprint;
- nullable lifetime tokens, peak daily tokens, longest turn seconds, current
  streak, longest streak, and UTC daily token buckets;
- an Ed25519 signature.

The account fingerprint is derived locally from a trimmed, lowercased email and
a versioned product salt. The raw email is zeroized after derivation and is never
stored or uploaded. The versioned pseudonym is retained locally so the connector
can refuse an upload after a managed ChatGPT account switch. Switching accounts
requires an explicit disconnect and reconnect. The service HMACs the received
pseudonym with a private pepper before storage. This is soft duplicate detection,
not identity proof.

## Data never collected

The connector does not collect or upload prompts, responses, generated content,
source code, filenames, repository paths, working directories, hostname, Codex
credentials or tokens, Codex installation identifiers, account plan type, raw
app-server messages, undocumented fields, or ordinary ChatGPT/API usage.

Codex stderr and raw JSON-RPC messages are deliberately discarded. Errors are
reported as bounded, generic categories rather than raw provider text.

## Local storage

- Permission-restricted config contains the server origin, device UUID, public
  key, pairing flag, auto-sync choice, pseudonymous account binding, and latest
  receipt identifiers. It contains no email or symmetric server credential.
- The private key is stored in the OS credential store by default.
- A permission-restricted file fallback is used only after the user explicitly
  selects `--key-storage secure-file`. On Windows, inherited ACLs govern this
  file; use the credential-store default whenever possible.
- Signed server receipts are stored locally as immutable JSON files.
- After the user confirms a sync, a permission-restricted retry journal stores
  only the exact allowlisted signed snapshot and its challenge nonce. This
  permits a byte-for-byte retry if the server accepts the upload but the network
  response is lost. If a receipt arrives, the same journal retains that signed
  receipt until the receipt file and config chain head are durably committed;
  the journal is then removed.
- The short-lived pairing poll token exists only in process memory and is
  zeroized after approval, denial, or expiry.

## Control and deletion

`tokenmaxxing disconnect` revokes the device and hides the profile immediately.
`tokenmaxxing uninstall` disconnects remotely and removes connector-owned local state.
Account export and full server-side deletion are provided by the Tokenmaxxing
web application; server-side deletion completes within 30 days.

## Limitations

The local connector is user-controlled software. Signatures prevent transit
tampering and replay, but they cannot prove that a modified client reported
truthful numbers. Public surfaces must say “Synced from a local Codex session,”
never “Verified by OpenAI.”
