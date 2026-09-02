# Release, SBOM, Provenance, and Signing

## Release gate

Codex `app-server` is experimental and unsupported for production. Every build
is a **technical preview** while compatibility evidence accumulates from
voluntary users who arrive through the open beta. Removing that label requires
usable nonzero data from at least 10 of 12 qualifying, recently active
installations across Windows, macOS, and Linux. The evidence must also compare
one volunteered account across two machines and record freshness lag, history
depth, bucket rollover, null behavior, workspace switching, connector/App
Server versions, and desktop/CLI/cloud deltas. This is not an invitation or
registration gate. Insufficient or failed evidence keeps the connector openly
accessible as a source-installed technical preview with affected metrics
clearly marked unavailable or experimental; it does not permit undocumented
local-log parsing. Sync is never marketed as real-time.

1. Record the open-beta compatibility evidence and explicit preview/production-support decision.
2. Update the changelog and protocol/consent versions when applicable.
3. Run format, Clippy with warnings denied, all tests, `cargo deny check`, and a
   locked release build.
4. Confirm the server and Rust suites pass the same golden protocol fixture.
5. Confirm packet capture contains only the documented HTTPS destination and
   upload schema; never commit a capture containing real account data.
6. Complete the native-signing approval and credential gate below.
7. Tag an annotated `vX.Y.Z` release from a reviewed commit.

The GitHub release workflow builds on native Windows x64, macOS x64/arm64, and
Linux x64/arm64 runners. Each archive includes the binary, license, privacy
notice, protocol, checksum, and CycloneDX SBOM. GitHub build-provenance and SBOM
attestations bind artifacts to the workflow and commit.

## Fail-closed platform signing

Release provenance is not a substitute for native code signing.

- macOS signing/notarization requires an approved Apple Developer ID
  Application identity, hardened runtime, `codesign`, and `notarytool`. The
  workflow submits a temporary ZIP containing the exact signed standalone
  executable and requires an `Accepted` result before packaging it. A
  notarization ticket cannot be stapled to a bare Mach-O command-line file.
- Windows Authenticode requires an owner-approved exportable PFX certificate
  and RFC 3161 timestamp service. If the selected certificate provider requires
  managed or hardware-backed signing instead, replace the PFX step with that
  provider's commit-SHA-pinned action before enabling releases.

Public tag releases are disabled by default. The `release-policy` job stops the
workflow before any platform build unless the owner has explicitly set the
repository variable `RELAY_NATIVE_SIGNING_READY=true` and configured all of
these protected GitHub secrets:

- `WINDOWS_CERTIFICATE_BASE64`
- `WINDOWS_CERTIFICATE_PASSWORD`
- `MACOS_CERTIFICATE_BASE64`
- `MACOS_CERTIFICATE_PASSWORD`
- `MACOS_SIGNING_IDENTITY`
- `APPLE_ID`
- `APPLE_APP_SPECIFIC_PASSWORD`
- `APPLE_TEAM_ID`

Set the variable only after explicit spending and identity approval. The
workflow imports credentials into ephemeral runner storage, signs and verifies
the Windows executable with `signtool`, signs the macOS executable with
`codesign`, waits for Apple notarization, removes temporary credential files,
and only then packages and attests the archives. A missing credential, invalid
signature, failed timestamp, or non-accepted notarization result fails the
whole tag release; Linux artifacts are not published by a partially failed
matrix. Local `cargo build` technical-preview binaries remain available and are
unsigned. Never place signing secrets in repository files, workflow logs, or
artifacts.

## Reproducibility

`Cargo.lock`, `rust-toolchain.toml`, locked builds, explicit runner labels, and
documented flags provide a reproducible baseline. Every referenced GitHub
Action is pinned to an immutable commit SHA with its release version noted
inline. Exact bit-for-bit equality is not claimed until runner image digests and
linker versions can also be independently pinned and verified. Publish the full
workflow run URL with every release.
