# Installation and Removal

## Install the open technical preview from source

Rust 1.87 or newer is required. Install the reviewed `v0.1.0` source snapshot
with its committed lockfile:

```console
cargo install --locked --git https://github.com/VPAI-Grok/tokenmaxxing-connector --tag v0.1.0 --bin tokenmaxxing
tokenmaxxing --help
```

For a different reviewable, commit-pinned installation, clone the repository,
check out the commit you trust, and run
`cargo install --path . --locked --bin tokenmaxxing` from that checkout.
Source-built technical-preview binaries are unsigned.

Connect from a terminal on Windows, macOS, or Linux:

```console
tokenmaxxing --server https://jointokenmaxxing.com connect
```

On Windows only, you may also register the connector as the current user's
handler for the website's **Open Tokenmaxxing Connector** button:

```console
tokenmaxxing --server https://jointokenmaxxing.com launcher install
tokenmaxxing launcher status
```

Browser-launcher registration is not currently implemented on macOS or Linux;
use the terminal `connect` command there. Registration is optional on Windows.

## Verify a release

Download the archive and its `.sha256` file from the same release. The archive
contains its CycloneDX SBOM; GitHub publishes provenance and SBOM attestations
for the archive. Verify the checksum with `sha256sum -c` (Linux/macOS) or
`Get-FileHash` (PowerShell), then verify the attestation with GitHub CLI:

```console
gh attestation verify tokenmaxxing-<platform-archive> --repo VPAI-Grok/tokenmaxxing-connector
```

Extract `tokenmaxxing` (`tokenmaxxing.exe` on Windows) into a user-controlled directory on
`PATH`. The public tag workflow fails closed unless Windows signing and macOS
signing/notarization are explicitly approved, configured, and verified. Check
the native signature in addition to the checksum and GitHub attestation:

```powershell
Get-AuthenticodeSignature .\tokenmaxxing.exe | Format-List Status,StatusMessage,SignerCertificate
```

```console
codesign --verify --strict --verbose=2 ./tokenmaxxing
spctl --assess --type execute --verbose=4 ./tokenmaxxing
```

Do not redistribute a locally compiled technical-preview binary as an official
release: local builds are intentionally unsigned. A macOS standalone executable
is notarized through the exact ZIP submitted by the release workflow; Apple
does not support stapling a ticket directly to a bare Mach-O command-line file,
so first-launch assessment may require network access.

When Codex is logged out, `tokenmaxxing connect` opens App Server's managed
ChatGPT browser authorization URL and App Server hosts the localhost callback.
Use `connect --device-code` only when that callback is brittle. Finish either
interactive flow within the connector's bounded 10-minute login window.
Ordinary app-server requests retain a 30-second timeout, and background sync
never launches an interactive sign-in.

## Background scheduling

First record explicit consent:

```console
tokenmaxxing auto-sync enable --interval 30
```

Then configure exactly one scheduler to run `tokenmaxxing auto-sync run --once` every
30 minutes. Automatic sync still enforces the opt-in, pseudonymous account
binding, and durable exact-body retry journal. Redirect output to a user-private
location because an exact upload preview contains the allowlisted activity
totals and pseudonymous fingerprint.

- Windows: create a per-user Task Scheduler task, “run only when user is logged
  on,” with no elevated privileges.
- macOS: create a per-user LaunchAgent in `~/Library/LaunchAgents`.
- Linux: use a user systemd timer (`systemctl --user`) or a user crontab.

The connector intentionally does not install scheduler entries itself. Disable
consent before deleting a scheduler: `tokenmaxxing auto-sync disable`.

## Removal

```console
tokenmaxxing uninstall
```

This remotely revokes the device and hides the profile before deleting the
connector's OS credential, config, receipts, and Windows browser-launcher
registration. Remove the binary separately from the directory where you
installed it. Use `tokenmaxxing uninstall --local-only` only if the service is
unreachable and you accept that remote state may remain.
