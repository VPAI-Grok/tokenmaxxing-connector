# Changelog

All notable changes follow Keep a Changelog. This project uses Semantic
Versioning while its public wire schema is versioned independently.

## [Unreleased]

### Added

- Managed-ChatGPT Codex app-server adapter and strict usage projection.
- Browser pairing, Ed25519 challenge/snapshot signing, receipt chaining, signed
  receipt reads, and remote disconnect.
- `connect`, `preview`, `sync`, `status`, `doctor`, `disconnect`, `uninstall`,
  and explicit `auto-sync` commands.
- Optional per-user Windows browser-launcher registration for the narrowly
  allowlisted `tokenmaxxing://connect` action; terminal connection remains the
  cross-platform path.
- OS credential storage with explicit secure-file fallback.
- Privacy, security, protocol, install, release, schema, CI, SBOM, and provenance
  documentation.

### Changed

- Replaced the preview-host JSON Schema identifier with the stable
  `urn:tokenmaxxing:schema:usage-snapshot:v1` identifier. The serialized v1
  snapshot and its canonical bytes are unchanged.
