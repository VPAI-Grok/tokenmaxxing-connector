# Security Policy

## Supported versions

Only the latest released minor version receives security fixes during beta.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting form at
<https://github.com/VPAI-Grok/tokenmaxxing-connector/security/advisories/new>.
Include a minimal reproduction, affected version, and impact. Do not include
real Codex credentials, raw account data, prompts, or source code. If GitHub's
form is unavailable, do not disclose the issue publicly; wait for private
reporting to be enabled on the repository.

We aim to acknowledge reports within three business days and provide a status
update within seven business days. There is no bounty program unless separately
announced in writing.

## Security boundaries

- Codex is spawned directly from the resolved executable and never through a
  shell. Browser authorization uses the operating system's default-browser
  mechanism.
- The optional Windows URL handler accepts only the exact
  `tokenmaxxing://connect` action. Its HTTPS server origin is pinned when the
  handler is registered and cannot be supplied by a website launcher URL.
- App-server JSON-RPC stays on child-process stdio. App Server alone temporarily
  owns the documented loopback callback during browser authorization; the
  connector exposes no general-purpose listener.
- Raw app-server stdout/stderr is never logged.
- HTTP redirects are disabled, response sizes are bounded, and non-local server
  origins require HTTPS.
- Pairing poll tokens are read-only, short-lived, memory-only credentials.
- Snapshot and control requests use Ed25519 signatures and replay-resistant
  timestamps/challenges.
- The connector pins the receipt-signing key obtained during pairing, verifies
  every receipt signature, binds its snapshot hash to the exact local canonical
  payload, and requires a continuous receipt sequence before advancing state.
- A private exact-body journal makes an accepted upload retryable after a lost
  response and makes receipt/config commits recoverable after interruption.
- Connector-owned config and journal replacement retains a validated recovery
  copy and refuses symlinked storage targets.
- A changed pseudonymous managed-ChatGPT account binding is refused locally
  before the connector requests a new sync challenge.
- A malicious local administrator, modified connector, compromised Codex
  executable, or compromised OS credential store is outside this trust boundary.

Release binaries are accompanied by checksums, CycloneDX SBOMs, and GitHub
artifact attestations. Public tag releases fail closed unless the Windows
binary is Authenticode-signed and the macOS binaries are Developer ID-signed
and accepted by Apple notarization. See [docs/RELEASE.md](docs/RELEASE.md).
