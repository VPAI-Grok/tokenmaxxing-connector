# Tokenmaxxing Connector

An open-source, privacy-first connector that lets a person sync a narrow set of
Codex account activity to Tokenmaxxing. Tokenmaxxing is an independent product
and is not affiliated with, endorsed by, or “verified by” OpenAI.

> **Technical preview:** [Codex `app-server`](https://developers.openai.com/codex/app-server/)
> is documented as experimental and unsupported for production. This
> source-installed connector is available to anyone in the open technical beta,
> but do not treat it as production-ready until compatibility evidence gathered
> from qualifying public signups covers Windows, macOS, and Linux. Provider
> usage can lag, so “last synced” and “provider data through” are freshness
> markers—not a real-time promise.

The connector talks directly to `codex app-server --stdio`, checks that Codex is
using managed ChatGPT authentication, and projects the response into a strict,
versioned allowlist. It never uploads prompts, responses, source code, filenames,
repository paths, hostnames, Codex credentials, installation identifiers, plan
type, raw provider responses, or the account email.

## Trust model

- The public description is **“Synced from a local Codex session.”**
- A device Ed25519 signature proves that a snapshot came from the paired
  connector key and that it was not altered in transit.
- A one-use server challenge prevents replay.
- This cannot prove that a modified local client reported truthful usage.
- Tokenmaxxing keeps token activity and shipping evidence on separate
  leaderboards.

Read [PRIVACY.md](PRIVACY.md), [SECURITY.md](SECURITY.md), and
[docs/PROTOCOL.md](docs/PROTOCOL.md) before connecting.

## Install from source

Rust 1.87 or newer is required:

```console
cargo install --locked --git https://github.com/VPAI-Grok/tokenmaxxing-connector --bin tokenmaxxing
tokenmaxxing --help
```

That command builds the source at the repository's current default branch. To
inspect and pin the exact source first, clone the repository, check out the
commit you trust, and install that checkout:

```console
git clone https://github.com/VPAI-Grok/tokenmaxxing-connector.git
cd tokenmaxxing-connector
cargo install --path . --locked --bin tokenmaxxing
```

Release archives, checksums, SBOMs, and provenance attestations are produced by
the release workflow. Verify those artifacts before installing a published
binary; see [docs/INSTALL.md](docs/INSTALL.md).

## Connect and sync

Use the terminal flow. `connect` displays the connector's consent statement,
requires the exact words `I AGREE`, and pairs this device without uploading an
activity snapshot. Automatic sync remains off.

```console
tokenmaxxing --server https://jointokenmaxxing.com connect
tokenmaxxing preview
tokenmaxxing sync
tokenmaxxing status --verify-receipt
```

`preview` shows the allowlisted snapshot locally. Interactive `sync` prints the
exact JSON request body and requires the word `UPLOAD` before anything is sent.

If Codex is logged out, `connect` starts the documented managed ChatGPT browser
flow automatically. Codex App Server returns the authorization URL and hosts the
localhost callback; the connector opens the URL but never reads or receives the
OpenAI tokens. If a browser callback is brittle, use the documented device-code
fallback explicitly:

```console
tokenmaxxing --server https://jointokenmaxxing.com connect --device-code
```

Use `--no-open-browser` to print the browser authorization URL without launching
it. Normal app-server calls time out after 30 seconds. Interactive browser and
device-code completion have a separate bounded 10-minute window. Background
sync never starts an interactive sign-in.

The legacy `relay` binary remains a compatibility alias for source installs;
new instructions and release artifacts use `tokenmaxxing`.

The Ed25519 key is stored in macOS Keychain, Windows Credential Manager, or
Linux Secret Service by default. The connector never silently falls back to a
file. If the OS credential store is unavailable, review the limitations and opt
in explicitly:

```console
tokenmaxxing --server https://jointokenmaxxing.com connect --key-storage secure-file
```

### Optional website launcher on Windows

Windows users can register the installed connector as the per-user handler for
the website's **Open Tokenmaxxing Connector** button:

```console
tokenmaxxing --server https://jointokenmaxxing.com launcher install
tokenmaxxing launcher status
```

The browser launcher is currently Windows-only. On Windows, macOS, and Linux,
the terminal `connect` command above is the supported cross-platform path and
does not require protocol-handler registration.

Every interactive sync prints the exact JSON request body and requires the word
`UPLOAD`. `tokenmaxxing sync --yes` is the explicit non-interactive equivalent.
Usage snapshots reflect the provider data available at collection time and may
not include activity that has not yet appeared in Codex's usage response.

The connector binds the device to the locally derived pseudonymous account
fingerprint captured during `connect`. It refuses a later managed ChatGPT
account switch before uploading; use `tokenmaxxing disconnect` and reconnect to bind a
different account. Once an upload is confirmed, a private exact-body journal
keeps retries and receipt-chain recovery safe across lost responses or crashes.

## Automatic sync is opt-in

Automatic sync starts disabled. Enabling it only records consent; it does not
silently install a service:

```console
tokenmaxxing auto-sync enable --interval 30
tokenmaxxing auto-sync run
```

For an OS scheduler, schedule `tokenmaxxing auto-sync run --once`. Disable it with
`tokenmaxxing auto-sync disable`. Platform examples are in
[docs/INSTALL.md](docs/INSTALL.md).

## Disconnect and uninstall

`tokenmaxxing disconnect` signs a remote revocation request. The server revokes the
device, consumes outstanding challenges, hides the profile immediately, and
removes leaderboard rows before the local key is deleted.

`tokenmaxxing uninstall` performs that remote disconnect by default, then
removes only connector-owned config, receipts, key material, and
browser-launcher registration. `--local-only` is an explicit emergency escape
hatch when the server is unavailable; it may leave remote profile/device state
unchanged.

## Development

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny --all-features --locked check
cargo build --release --locked
```

Public tag releases are fail-closed until the owner explicitly approves and
configures Windows signing plus macOS signing/notarization. Local development
builds remain unsigned technical previews; see [docs/RELEASE.md](docs/RELEASE.md).

Set `PROJECT_RELAY_CONFIG_ROOT` to isolate all connector state during local
testing. Set `PROJECT_RELAY_CODEX_PATH` to an exact test executable; it is
always spawned directly and never through a shell.

The app-server integration is intentionally isolated behind `src/codex.rs` so a
future documented transport can replace it without changing the upload schema.
