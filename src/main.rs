//! Tokenmaxxing connector command-line application.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use project_relay_connector::api::ApiClient;
use project_relay_connector::codex::{self, CollectOptions, CollectedUsage, LoginMode};
use project_relay_connector::config::{AppPaths, Config};
use project_relay_connector::crypto::{sha256_hex, verify_base64, DeviceKey};
use project_relay_connector::journal::{PendingAcceptance, PendingUpload};
use project_relay_connector::keystore::{self, KeyStorage, SecretBundle};
use project_relay_connector::launcher::{self, LauncherAction};
use project_relay_connector::protocol::{
    validate_base64url, PairingStatus, Receipt, SnapshotPreview, UsageSnapshotV1,
};
use project_relay_connector::storage;
use project_relay_connector::{CONSENT_VERSION, FINGERPRINT_VERSION, SCHEMA_VERSION};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::io::{self, IsTerminal as _, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(
    name = "tokenmaxxing",
    version,
    about = "Privacy-first Codex activity connector for Tokenmaxxing",
    long_about = None
)]
struct Cli {
    /// Tokenmaxxing origin. Required by `connect`; later commands use saved config.
    #[arg(long, global = true, env = "PROJECT_RELAY_SERVER_URL")]
    server: Option<Url>,

    /// Exact Codex executable path. Never executed through a shell.
    #[arg(long, global = true, env = "PROJECT_RELAY_CODEX_PATH")]
    codex_path: Option<PathBuf>,

    /// Isolated connector config/state root (primarily for development and tests).
    #[arg(long, global = true, env = "PROJECT_RELAY_CONFIG_ROOT")]
    config_root: Option<PathBuf>,

    /// Emit machine-readable command results. Interactive previews remain JSON.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate managed ChatGPT usage and pair this device in a browser.
    Connect(ConnectArgs),
    /// Display the exact local allowlist without contacting Tokenmaxxing.
    Preview(UsageArgs),
    /// Preview and upload one challenge-bound usage snapshot.
    Sync(SyncArgs),
    /// Show local connection, receipt, and automatic-sync state.
    Status(StatusArgs),
    /// Run privacy-safe local diagnostics.
    Doctor,
    /// Revoke this device and immediately hide the owning profile.
    Disconnect(ConfirmArgs),
    /// Remove connector-owned state; disconnects remotely unless explicitly local-only.
    Uninstall(UninstallArgs),
    /// Explicitly configure or run background synchronization.
    AutoSync(AutoSyncArgs),
    /// Install, inspect, or remove the browser launcher integration.
    Launcher(LauncherArgs),
    /// Handle a validated operating-system protocol invocation.
    #[command(hide = true)]
    Launch(LaunchArgs),
}

#[derive(Debug, Args)]
struct ConnectArgs {
    /// Use device-code sign-in instead of the default ChatGPT browser flow.
    #[arg(long)]
    device_code: bool,
    /// Do not open verification pages automatically.
    #[arg(long)]
    no_open_browser: bool,
    /// Where to store the Ed25519 private key.
    #[arg(long, value_enum, default_value = "keyring")]
    key_storage: StorageChoice,
    /// Accept consent v1 non-interactively after reviewing PRIVACY.md.
    #[arg(long)]
    accept_consent: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum StorageChoice {
    /// OS Keychain, Credential Manager, or Secret Service.
    Keyring,
    /// Explicit permission-restricted file fallback.
    SecureFile,
}

impl From<StorageChoice> for KeyStorage {
    fn from(value: StorageChoice) -> Self {
        match value {
            StorageChoice::Keyring => Self::Keyring,
            StorageChoice::SecureFile => Self::SecureFile,
        }
    }
}

#[derive(Debug, Args)]
struct UsageArgs {
    /// Use device-code sign-in instead of the default ChatGPT browser flow.
    #[arg(long)]
    device_code: bool,
}

#[derive(Debug, Args)]
struct SyncArgs {
    /// Use device-code sign-in instead of the default ChatGPT browser flow.
    #[arg(long)]
    device_code: bool,
    /// Upload the displayed snapshot without an additional prompt.
    #[arg(long)]
    yes: bool,
}

#[derive(Debug, Args)]
struct StatusArgs {
    /// Retrieve the latest receipt using a signed, read-only request.
    #[arg(long)]
    verify_receipt: bool,
}

#[derive(Debug, Args)]
struct ConfirmArgs {
    /// Confirm this consequential action non-interactively.
    #[arg(long)]
    yes: bool,
}

#[derive(Debug, Args)]
struct UninstallArgs {
    /// Confirm removal non-interactively.
    #[arg(long)]
    yes: bool,
    /// Remove local state even when remote revocation cannot be completed.
    #[arg(long)]
    local_only: bool,
}

#[derive(Debug, Args)]
struct AutoSyncArgs {
    #[command(subcommand)]
    command: AutoSyncCommand,
}

#[derive(Debug, Args)]
struct LauncherArgs {
    #[command(subcommand)]
    command: LauncherCommand,
}

#[derive(Debug, Subcommand)]
enum LauncherCommand {
    /// Register `tokenmaxxing://connect` for the current user.
    Install,
    /// Show whether the browser launcher is registered.
    Status,
    /// Remove the current user's browser launcher registration.
    Uninstall(ConfirmArgs),
}

#[derive(Debug, Args)]
struct LaunchArgs {
    /// Exact URL supplied by the operating-system protocol handler.
    uri: Url,
}

#[derive(Debug, Subcommand)]
enum AutoSyncCommand {
    /// Record explicit background-sync consent.
    Enable {
        /// Sync interval in minutes (5–1440).
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(5..=1440))]
        interval: u32,
    },
    /// Disable background sync.
    Disable,
    /// Show background-sync state.
    Status,
    /// Run the opt-in sync loop. Use `--once` from a system scheduler.
    Run {
        /// Perform one sync and exit.
        #[arg(long)]
        once: bool,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let paths = AppPaths::discover(cli.config_root.as_deref())?;
    match &cli.command {
        Command::Connect(args) => connect(&cli, &paths, args).await,
        Command::Preview(args) => preview(&cli, &paths, args),
        Command::Sync(args) => sync_once(&cli, &paths, args.device_code, args.yes, false).await,
        Command::Status(args) => status(&cli, &paths, args).await,
        Command::Doctor => doctor(&cli, &paths),
        Command::Disconnect(args) => disconnect(&cli, &paths, args.yes).await,
        Command::Uninstall(args) => uninstall(&cli, &paths, args).await,
        Command::AutoSync(args) => auto_sync(&cli, &paths, &args.command).await,
        Command::Launcher(args) => launcher_command(&cli, &paths, &args.command),
        Command::Launch(args) => launch(&cli, &paths, args).await,
    }
}

async fn connect(cli: &Cli, paths: &AppPaths, args: &ConnectArgs) -> Result<()> {
    let server_url = resolve_server_url(cli, paths)?;
    connect_to_server(cli, paths, args, server_url).await
}

async fn connect_to_server(
    cli: &Cli,
    paths: &AppPaths,
    args: &ConnectArgs,
    server_url: Url,
) -> Result<()> {
    validate_server_url(&server_url)?;
    let previous_config = Config::load(paths)?;
    if previous_config.as_ref().is_some_and(|config| config.paired) {
        bail!("this connector is already paired; run `tokenmaxxing status` or disconnect first");
    }
    accept_consent(args.accept_consent)?;

    // Validate the upstream dependency before registering a device. The raw
    // email is pseudonymized in memory; only that pseudonym is bound locally.
    let collected = collect_interactive_usage(cli, args.device_code, !args.no_open_browser)?;
    emit(
        cli.json,
        &json!({
            "event": "codexValidated",
            "managedChatgpt": true,
            "providerDataThrough": provider_data_through(&collected)
        }),
        "Managed ChatGPT activity is available.",
    )?;

    if let Some(previous) = previous_config {
        // Clean up key material from an expired, denied, or interrupted pairing
        // before creating a replacement device identity.
        keystore::delete(previous.key_storage, &previous.device_id, &paths.state_dir)?;
        PendingUpload::remove(paths)?;
    }

    let storage = KeyStorage::from(args.key_storage);
    let device_id = uuid::Uuid::new_v4().to_string();
    let key = DeviceKey::generate();
    let secret = SecretBundle::new(key.secret_base64().to_string());
    keystore::save(storage, &device_id, &paths.state_dir, &secret).with_context(|| {
        if storage == KeyStorage::Keyring {
            "OS credential storage failed; rerun with --key-storage secure-file only if you accept the documented fallback"
        } else {
            "secure-file key storage failed"
        }
    })?;
    let mut config = Config::new(
        server_url.clone(),
        device_id.clone(),
        key.public_key_base64(),
        storage,
    );
    config.account_fingerprint = Some(collected.account_fingerprint.clone());
    config.save(paths)?;

    let api = ApiClient::new(server_url.clone())?;
    let pairing = api
        .start_pairing(&device_id, &config.public_key)
        .await
        .context("start browser pairing")?;
    if pairing.status != PairingStatus::Pending {
        bail!("Tokenmaxxing returned an invalid initial pairing status");
    }
    let verification = Url::parse(&pairing.verification_uri).context("invalid pairing URL")?;
    ensure_same_origin(&server_url, &verification)?;
    println!(
        "Open {} and enter pairing code {}",
        pairing.verification_uri, pairing.user_code
    );
    if !args.no_open_browser {
        let _ = webbrowser::open(&pairing.verification_uri);
    }

    let mut poll_token = Zeroizing::new(pairing.poll_token);
    let expires_at = DateTime::parse_from_rfc3339(&pairing.expires_at)
        .context("invalid pairing expiry")?
        .with_timezone(&Utc);
    let poll_interval = Duration::from_secs(pairing.poll_interval_seconds.clamp(2, 30));
    loop {
        if Utc::now() >= expires_at {
            poll_token.zeroize();
            bail!("pairing expired before approval");
        }
        tokio::time::sleep(poll_interval).await;
        let state = api.poll_pairing(&pairing.pairing_id, &poll_token).await?;
        match state.status {
            PairingStatus::Pending => {}
            PairingStatus::Approved => {
                poll_token.zeroize();
                config.paired = true;
                config.receipt_public_key = Some(pairing.receipt_public_key.clone());
                config.save(paths)?;
                emit(
                    cli.json,
                    &json!({"paired": true, "device": config.redacted_device_id()}),
                    "Device paired. Automatic sync remains off.",
                )?;
                return Ok(());
            }
            PairingStatus::Expired => {
                poll_token.zeroize();
                bail!("pairing expired");
            }
            PairingStatus::Denied => {
                poll_token.zeroize();
                bail!("pairing was denied");
            }
        }
    }
}

fn launcher_command(cli: &Cli, paths: &AppPaths, command: &LauncherCommand) -> Result<()> {
    match command {
        LauncherCommand::Install => {
            let server_url = resolve_server_url(cli, paths)?;
            let executable = std::env::current_exe()
                .context("resolve the absolute Tokenmaxxing executable path")?;
            let config_root = cli
                .config_root
                .as_deref()
                .map(absolute_path)
                .transpose()?;
            launcher::install(&executable, &server_url, config_root.as_deref())?;
            emit(
                cli.json,
                &json!({"installed": true, "scheme": "tokenmaxxing"}),
                "Browser connection enabled. Tokenmaxxing links can now open this connector.",
            )
        }
        LauncherCommand::Status => {
            let installed = launcher::is_installed()?;
            emit(
                cli.json,
                &json!({"installed": installed, "scheme": "tokenmaxxing"}),
                if installed {
                    "The Tokenmaxxing browser launcher is installed."
                } else {
                    "The Tokenmaxxing browser launcher is not installed."
                },
            )
        }
        LauncherCommand::Uninstall(args) => {
            if !args.yes {
                confirm(
                    "This removes the browser launcher only. Type REMOVE LAUNCHER: ",
                    "REMOVE LAUNCHER",
                )?;
            }
            let removed = launcher::uninstall()?;
            emit(
                cli.json,
                &json!({"installed": false, "removed": removed}),
                "The Tokenmaxxing browser launcher is removed.",
            )
        }
    }
}

async fn launch(cli: &Cli, paths: &AppPaths, args: &LaunchArgs) -> Result<()> {
    match launcher::parse_uri(&args.uri)? {
        LauncherAction::Connect => {
            let server_url = resolve_server_url(cli, paths)?;
            if let Some(config) = Config::load(paths)? {
                if config.paired {
                    if !same_origin(&server_url, &config.server_url) {
                        bail!("browser launcher server did not match the paired connector origin");
                    }
                    return emit(
                        cli.json,
                        &json!({"launched": true, "alreadyConnected": true}),
                        "Codex is already connected to Tokenmaxxing.",
                    );
                }
            }
            let connect_args = ConnectArgs {
                device_code: false,
                no_open_browser: false,
                key_storage: StorageChoice::Keyring,
                // Clicking the explicit website connection action authorizes
                // device setup. Activity still cannot upload until the user
                // reviews and confirms the exact snapshot locally.
                accept_consent: true,
            };
            connect_to_server(cli, paths, &connect_args, server_url).await
        }
    }
}

fn preview(cli: &Cli, paths: &AppPaths, args: &UsageArgs) -> Result<()> {
    let config = require_config(paths)?;
    let collected = collect_interactive_usage(cli, args.device_code, true)?;
    ensure_account_binding(&config, &collected.account_fingerprint)?;
    let snapshot = make_snapshot(&config, &collected, uuid::Uuid::nil().to_string());
    let preview = SnapshotPreview::from_snapshot(&snapshot);
    println!("{}", serde_json::to_string_pretty(&preview)?);
    println!(
        "Local preview only. No network request was made. Provider data through: {}",
        provider_data_through(&collected).unwrap_or_else(|| "unknown".into())
    );
    Ok(())
}

async fn sync_once(
    cli: &Cli,
    paths: &AppPaths,
    device_code: bool,
    assume_yes: bool,
    background: bool,
) -> Result<()> {
    let mut config = require_paired_config(paths)?;
    let api = ApiClient::new(config.server_url.clone())?;
    if let Some(pending) = PendingUpload::load(paths)? {
        if !background {
            println!(
                "Retrying the previously confirmed exact upload before collecting new activity."
            );
        }
        let provider_data_through = provider_data_through_snapshot(&pending.snapshot);
        let accepted = submit_pending_upload(&mut config, paths, &api, pending).await?;
        return emit_sync_result(
            cli,
            &accepted,
            provider_data_through.as_deref(),
            true,
            "Pending exact snapshot recovered and receipt stored.",
        );
    }

    let mut secret = keystore::load(config.key_storage, &config.device_id, &paths.state_dir)?;
    let key = DeviceKey::from_base64(&secret.signing_key)?;
    secret.zeroize();
    let login_mode = if background {
        LoginMode::Disabled
    } else {
        interactive_login_mode(device_code)
    };
    let collected = collect_usage(cli, login_mode, !background)?;
    ensure_account_binding(&config, &collected.account_fingerprint)?;
    let challenge = api
        .create_challenge(&config.device_id, config.last_receipt_hash.as_deref(), &key)
        .await?;
    if challenge.algorithm != "Ed25519" || challenge.canonicalization != "relay-json-v1" {
        bail!("Tokenmaxxing returned an unsupported signing protocol");
    }
    validate_base64url(&challenge.server_nonce, 32, "server challenge nonce")?;
    let expires_at = DateTime::parse_from_rfc3339(&challenge.expires_at)
        .context("invalid challenge expiry")?
        .with_timezone(&Utc);
    if expires_at <= Utc::now() {
        bail!("Tokenmaxxing returned an expired challenge");
    }
    let mut snapshot = make_snapshot(&config, &collected, challenge.challenge_id);
    snapshot.signature = key.sign_base64(&snapshot.signing_bytes(&challenge.server_nonce)?);
    snapshot.validate()?;

    println!("Exact upload preview (the following JSON is the full request body):");
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    if !assume_yes {
        confirm("Type UPLOAD to send exactly this snapshot: ", "UPLOAD")?;
    }
    let provider_data_through = provider_data_through(&collected);
    let pending = PendingUpload::new(snapshot, challenge.server_nonce)?;
    pending.save_new(paths)?;
    let accepted = submit_pending_upload(&mut config, paths, &api, pending).await?;
    emit_sync_result(
        cli,
        &accepted,
        provider_data_through.as_deref(),
        false,
        "Snapshot accepted and receipt stored.",
    )
}

async fn status(cli: &Cli, paths: &AppPaths, args: &StatusArgs) -> Result<()> {
    let Some(config) = Config::load(paths)? else {
        return emit(
            cli.json,
            &json!({"connected": false, "autoSync": false}),
            "Tokenmaxxing is not connected.",
        );
    };
    let mut value = json!({
        "connected": config.paired,
        "device": config.redacted_device_id(),
        "server": config.server_url,
        "autoSync": {
            "enabled": config.auto_sync.enabled,
            "intervalMinutes": config.auto_sync.interval_minutes
        },
        "lastSyncedAt": config.last_synced_at,
        "lastReceiptId": config.last_receipt_id,
        "accountBound": config.account_fingerprint.is_some(),
        "pendingUpload": PendingUpload::load(paths)?.is_some()
    });
    if args.verify_receipt {
        let receipt_id = config
            .last_receipt_id
            .as_deref()
            .context("there is no receipt to verify")?;
        let secret = keystore::load(config.key_storage, &config.device_id, &paths.state_dir)?;
        let key = DeviceKey::from_base64(&secret.signing_key)?;
        let receipt = ApiClient::new(config.server_url.clone())?
            .get_receipt(&config.device_id, receipt_id, &key)
            .await?;
        verify_receipt(&config, &receipt)?;
        value["receiptVerified"] = json!(true);
        value["receiptTrustTier"] = json!(receipt.trust_tier);
        value["receiptQuarantineStatus"] = json!(receipt.quarantine_status);
    }
    emit(cli.json, &value, "Connector status loaded.")
}

fn doctor(cli: &Cli, paths: &AppPaths) -> Result<()> {
    let config = Config::load(paths)?;
    let probe = codex::probe(cli.codex_path.as_deref())?;
    let key_available = match &config {
        Some(config) => {
            keystore::load(config.key_storage, &config.device_id, &paths.state_dir).is_ok()
        }
        None => false,
    };
    let value = json!({
        "codexResolved": true,
        "codexVersion": probe.version,
        "managedChatgpt": probe.managed_chatgpt,
        "configured": config.is_some(),
        "keyAvailable": key_available,
        "privacy": {
            "rawMessagesLogged": false,
            "rawEmailStored": false,
            "shellSpawnUsed": false
        }
    });
    emit(cli.json, &value, "Diagnostics passed.")
}

async fn disconnect(cli: &Cli, paths: &AppPaths, assume_yes: bool) -> Result<()> {
    let mut config = require_paired_config(paths)?;
    if !assume_yes {
        confirm(
            "This revokes the device and immediately hides the profile. Type DISCONNECT: ",
            "DISCONNECT",
        )?;
    }
    let mut secret = keystore::load(config.key_storage, &config.device_id, &paths.state_dir)?;
    let key = DeviceKey::from_base64(&secret.signing_key)?;
    let result = ApiClient::new(config.server_url.clone())?
        .disconnect(&config.device_id, &key)
        .await?;
    if !result.disconnected || !result.profile_hidden {
        bail!("Tokenmaxxing did not confirm device revocation and profile hiding");
    }
    secret.zeroize();
    keystore::delete(config.key_storage, &config.device_id, &paths.state_dir)?;
    PendingUpload::remove(paths)?;
    config.paired = false;
    config.auto_sync.enabled = false;
    config.save(paths)?;
    emit(
        cli.json,
        &json!({"disconnected": true, "profileHidden": true}),
        "Device revoked, profile hidden, and local key removed.",
    )
}

async fn uninstall(cli: &Cli, paths: &AppPaths, args: &UninstallArgs) -> Result<()> {
    if !args.yes {
        confirm(
            "This removes all connector-owned local state. Type UNINSTALL: ",
            "UNINSTALL",
        )?;
    }
    if let Some(config) = Config::load(paths)? {
        if config.paired && !args.local_only {
            let secret = keystore::load(config.key_storage, &config.device_id, &paths.state_dir)
                .context("remote disconnect is required before uninstall; use --local-only only if you accept leaving the remote device/profile state unchanged")?;
            let key = DeviceKey::from_base64(&secret.signing_key)?;
            let result = ApiClient::new(config.server_url.clone())?
                .disconnect(&config.device_id, &key)
                .await?;
            if !result.disconnected || !result.profile_hidden {
                bail!("remote disconnect was not confirmed; local state was preserved");
            }
        }
        keystore::delete(config.key_storage, &config.device_id, &paths.state_dir)?;
    }
    remove_connector_state(paths)?;
    let launcher_removed = launcher::uninstall()?;
    emit(
        cli.json,
        &json!({
            "uninstalled": true,
            "localOnly": args.local_only,
            "launcherRemoved": launcher_removed
        }),
        "Connector-owned local state removed.",
    )
}

async fn auto_sync(cli: &Cli, paths: &AppPaths, command: &AutoSyncCommand) -> Result<()> {
    match command {
        AutoSyncCommand::Enable { interval } => {
            let mut config = require_paired_config(paths)?;
            config.auto_sync.enabled = true;
            config.auto_sync.interval_minutes = *interval;
            config.save(paths)?;
            emit(
                cli.json,
                &json!({"autoSync": true, "intervalMinutes": interval}),
                "Automatic sync enabled. Run `tokenmaxxing auto-sync run`, or schedule `tokenmaxxing auto-sync run --once` with the OS scheduler.",
            )
        }
        AutoSyncCommand::Disable => {
            let mut config = require_config(paths)?;
            config.auto_sync.enabled = false;
            config.save(paths)?;
            emit(
                cli.json,
                &json!({"autoSync": false}),
                "Automatic sync disabled.",
            )
        }
        AutoSyncCommand::Status => {
            let config = require_config(paths)?;
            emit(
                cli.json,
                &json!({
                    "autoSync": config.auto_sync.enabled,
                    "intervalMinutes": config.auto_sync.interval_minutes
                }),
                if config.auto_sync.enabled {
                    "Automatic sync is enabled."
                } else {
                    "Automatic sync is disabled."
                },
            )
        }
        AutoSyncCommand::Run { once } => loop {
            let config = require_paired_config(paths)?;
            if !config.auto_sync.enabled {
                bail!("automatic sync is not enabled; run `tokenmaxxing auto-sync enable` first");
            }
            if let Err(error) = sync_once(cli, paths, false, true, true).await {
                eprintln!("Automatic sync failed safely: {error:#}");
                if *once {
                    return Err(error);
                }
            }
            if *once {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(
                u64::from(config.auto_sync.interval_minutes) * 60,
            ))
            .await;
        },
    }
}

fn interactive_login_mode(device_code: bool) -> LoginMode {
    if device_code {
        LoginMode::DeviceCode
    } else {
        LoginMode::Browser
    }
}

fn collect_interactive_usage(
    cli: &Cli,
    device_code: bool,
    open_browser: bool,
) -> Result<CollectedUsage> {
    collect_usage(cli, interactive_login_mode(device_code), open_browser)
}

fn collect_usage(cli: &Cli, login_mode: LoginMode, open_browser: bool) -> Result<CollectedUsage> {
    codex::collect(&CollectOptions {
        codex_path: cli.codex_path.as_deref(),
        login_mode,
        open_browser,
        request_timeout: Duration::from_secs(30),
    })
}

fn make_snapshot(config: &Config, usage: &CollectedUsage, challenge_id: String) -> UsageSnapshotV1 {
    UsageSnapshotV1 {
        schema_version: SCHEMA_VERSION,
        device_id: config.device_id.clone(),
        challenge_id,
        connector_version: env!("CARGO_PKG_VERSION").into(),
        codex_version: usage.codex_version.clone(),
        observed_at: usage.observed_at.clone(),
        fingerprint_version: FINGERPRINT_VERSION,
        account_fingerprint: usage.account_fingerprint.clone(),
        consent_version: CONSENT_VERSION,
        metrics: usage.metrics.clone(),
        previous_receipt_hash: config.last_receipt_hash.clone(),
        signature: String::new(),
    }
}

fn provider_data_through(usage: &CollectedUsage) -> Option<String> {
    provider_data_through_metrics(&usage.metrics)
}

fn provider_data_through_snapshot(snapshot: &UsageSnapshotV1) -> Option<String> {
    provider_data_through_metrics(&snapshot.metrics)
}

fn provider_data_through_metrics(
    metrics: &project_relay_connector::protocol::UsageMetrics,
) -> Option<String> {
    metrics
        .daily_usage_buckets
        .as_ref()
        .and_then(|buckets| buckets.last())
        .map(|bucket| bucket.start_date.clone())
}

fn ensure_account_binding(config: &Config, observed_fingerprint: &str) -> Result<()> {
    let expected = config.account_fingerprint.as_deref().context(
        "this pairing predates local account binding; disconnect and reconnect before syncing",
    )?;
    if expected != observed_fingerprint {
        bail!(
            "the managed ChatGPT account changed; no upload was sent. Disconnect and reconnect to bind the new account explicitly"
        );
    }
    Ok(())
}

async fn submit_pending_upload(
    config: &mut Config,
    paths: &AppPaths,
    api: &ApiClient,
    mut pending: PendingUpload,
) -> Result<PendingAcceptance> {
    verify_pending_upload(config, &pending)?;

    if let Some(accepted) = pending.accepted.clone() {
        return commit_pending_acceptance(config, paths, &pending, accepted);
    }

    if pending.snapshot.previous_receipt_hash != config.last_receipt_hash {
        bail!("pending upload did not match the current local receipt-chain head");
    }
    let accepted = api
        .upload_snapshot(&pending.snapshot)
        .await
        .context("upload failed; the exact signed snapshot remains journaled for a safe retry")?;
    verify_sync_receipt(config, paths, &pending.snapshot, &accepted.receipt)?;
    pending.record_acceptance(accepted)?;
    pending.save(paths)?;
    let accepted = pending
        .accepted
        .clone()
        .context("pending upload omitted its captured acceptance")?;
    commit_pending_acceptance(config, paths, &pending, accepted)
}

fn verify_pending_upload(config: &Config, pending: &PendingUpload) -> Result<()> {
    pending.validate()?;
    if pending.snapshot.device_id != config.device_id {
        bail!("pending upload belonged to a different connector device");
    }
    ensure_account_binding(config, &pending.snapshot.account_fingerprint)?;
    verify_base64(
        &config.public_key,
        &pending.snapshot.signing_bytes(&pending.server_nonce)?,
        &pending.snapshot.signature,
    )
    .context("pending upload device signature verification failed")
}

fn commit_pending_acceptance(
    config: &mut Config,
    paths: &AppPaths,
    pending: &PendingUpload,
    accepted: PendingAcceptance,
) -> Result<PendingAcceptance> {
    verify_pending_upload(config, pending)?;
    verify_receipt(config, &accepted.receipt)?;
    let expected_hash = sha256_hex(pending.snapshot.canonical_payload()?.as_bytes());
    if accepted.receipt.snapshot_hash != expected_hash {
        bail!("pending receipt did not match the exact journaled snapshot");
    }

    let already_committed = config.last_receipt_id.as_deref()
        == Some(accepted.receipt.receipt_id.as_str())
        && config.last_receipt_hash.as_deref() == Some(accepted.receipt.receipt_hash.as_str());
    if already_committed {
        persist_receipt(paths, &accepted.receipt)?;
        PendingUpload::remove(paths)?;
        return Ok(accepted);
    }

    verify_sync_receipt(config, paths, &pending.snapshot, &accepted.receipt)?;
    persist_receipt(paths, &accepted.receipt)?;
    config.last_receipt_id = Some(accepted.receipt.receipt_id.clone());
    config.last_receipt_hash = Some(accepted.receipt.receipt_hash.clone());
    config.last_synced_at = Some(
        DateTime::parse_from_rfc3339(&accepted.receipt.accepted_at)
            .context("invalid receipt acceptance time")?
            .with_timezone(&Utc),
    );
    config.save(paths)?;
    PendingUpload::remove(paths)?;
    Ok(accepted)
}

fn emit_sync_result(
    cli: &Cli,
    accepted: &PendingAcceptance,
    provider_data_through: Option<&str>,
    recovered_pending_upload: bool,
    message: &str,
) -> Result<()> {
    emit(
        cli.json,
        &json!({
            "synced": true,
            "receiptId": accepted.receipt.receipt_id,
            "quarantineStatus": accepted.receipt.quarantine_status,
            "leaderboardEligible": accepted.leaderboard_eligible,
            "providerDataThrough": provider_data_through,
            "recoveredPendingUpload": recovered_pending_upload
        }),
        message,
    )
}

fn require_config(paths: &AppPaths) -> Result<Config> {
    Config::load(paths)?.context("Tokenmaxxing is not configured; run `tokenmaxxing connect` first")
}

fn require_paired_config(paths: &AppPaths) -> Result<Config> {
    let config = require_config(paths)?;
    if !config.paired {
        bail!("Tokenmaxxing is not paired; run `tokenmaxxing connect` first");
    }
    Ok(config)
}

fn accept_consent(non_interactive: bool) -> Result<()> {
    if non_interactive {
        return Ok(());
    }
    println!(
        "Consent v1: Tokenmaxxing uploads only the displayed token/streak metrics, a pseudonymous account fingerprint, connector/Codex versions, timestamps, device ID, and receipt chain. It never collects prompts, responses, code, paths, hostname, credentials, plan type, or raw email."
    );
    confirm("Type I AGREE to continue: ", "I AGREE")
}

fn confirm(prompt: &str, expected: &str) -> Result<()> {
    if !io::stdin().is_terminal() {
        bail!("interactive confirmation requires a terminal; use the command's explicit confirmation flag after reviewing the preview")
    }
    print!("{prompt}");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let accepted = answer.trim() == expected;
    answer.zeroize();
    if !accepted {
        bail!("confirmation did not match; no action was taken");
    }
    Ok(())
}

fn resolve_server_url(cli: &Cli, paths: &AppPaths) -> Result<Url> {
    let configured = Config::load(paths)?;
    if let Some(server_url) = cli.server.clone() {
        validate_server_url(&server_url)?;
        if configured
            .as_ref()
            .is_some_and(|config| config.paired && !same_origin(&server_url, &config.server_url))
        {
            bail!("requested server did not match the paired connector origin");
        }
        return Ok(server_url);
    }
    configured
        .map(|config| config.server_url)
        .context("connect requires --server, PROJECT_RELAY_SERVER_URL, or saved connector config")
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("resolve current directory for launcher registration")?
        .join(path))
}

fn validate_server_url(url: &Url) -> Result<()> {
    if url.cannot_be_a_base() || url.host_str().is_none() {
        bail!("server URL must be an absolute origin");
    }
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if url.scheme() != "https" && !(local && url.scheme() == "http") {
        bail!("server URL must use HTTPS outside localhost");
    }
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("server URL must not contain credentials, query, or fragment");
    }
    Ok(())
}

fn ensure_same_origin(expected: &Url, actual: &Url) -> Result<()> {
    if !same_origin(expected, actual) {
        bail!("pairing URL did not match the configured Tokenmaxxing origin");
    }
    Ok(())
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn persist_receipt(paths: &AppPaths, receipt: &Receipt) -> Result<()> {
    storage::ensure_directory(&paths.receipts_dir(), "receipt directory")?;
    let path = paths
        .receipts_dir()
        .join(format!("{}.json", receipt.receipt_id));
    let serialized = serde_json::to_vec_pretty(receipt)?;
    match storage::create_private_new(&path, "immutable receipt") {
        Ok(mut file) => {
            file.write_all(&serialized)?;
            file.sync_all()?;
            storage::sync_parent(&path)
        }
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|source| source.kind() == io::ErrorKind::AlreadyExists) =>
        {
            storage::reject_symlink(&path, "immutable receipt")?;
            let existing: Receipt = serde_json::from_slice(
                &fs::read(&path).context("read existing immutable receipt")?,
            )
            .context("parse existing immutable receipt")?;
            if &existing != receipt {
                bail!("an immutable receipt with this ID already contains different data");
            }
            Ok(())
        }
        Err(error) => {
            Err(error).with_context(|| format!("create immutable receipt {}", receipt.receipt_id))
        }
    }
}

fn verify_receipt(config: &Config, receipt: &Receipt) -> Result<()> {
    receipt.validate()?;
    let public_key = config
        .receipt_public_key
        .as_deref()
        .context("no pinned server receipt key; disconnect and pair again")?;
    verify_base64(
        public_key,
        &receipt.signing_bytes()?,
        &receipt.server_signature,
    )
    .context(
        "server receipt signature verification failed; receipt and chain state were not persisted",
    )
}

fn verify_sync_receipt(
    config: &Config,
    paths: &AppPaths,
    snapshot: &UsageSnapshotV1,
    receipt: &Receipt,
) -> Result<()> {
    snapshot.validate()?;
    verify_receipt(config, receipt)?;

    if snapshot.previous_receipt_hash != config.last_receipt_hash {
        bail!("local snapshot receipt-chain head did not match connector state");
    }
    let expected_snapshot_hash = sha256_hex(snapshot.canonical_payload()?.as_bytes());
    if receipt.snapshot_hash != expected_snapshot_hash {
        bail!(
            "server receipt snapshot hash did not match the exact uploaded snapshot; receipt and chain state were not persisted"
        );
    }

    let expected_sequence = expected_receipt_sequence(config, paths)?;
    if receipt.sequence != expected_sequence {
        bail!(
            "server receipt sequence did not continue the local receipt chain; receipt and chain state were not persisted"
        );
    }
    Ok(())
}

fn expected_receipt_sequence(config: &Config, paths: &AppPaths) -> Result<u64> {
    match (&config.last_receipt_id, &config.last_receipt_hash) {
        (None, None) => Ok(1),
        (Some(receipt_id), Some(receipt_hash)) => {
            let path = paths.receipts_dir().join(format!("{receipt_id}.json"));
            let previous: Receipt = serde_json::from_slice(
                &fs::read(&path).context("read previous immutable receipt")?,
            )
            .context("parse previous immutable receipt")?;
            verify_receipt(config, &previous).context("verify previous immutable receipt")?;
            if previous.receipt_id != *receipt_id || previous.receipt_hash != *receipt_hash {
                bail!("previous immutable receipt did not match connector chain state");
            }
            previous
                .sequence
                .checked_add(1)
                .context("receipt sequence overflow")
        }
        _ => bail!("connector receipt-chain state was incomplete"),
    }
}

fn remove_connector_state(paths: &AppPaths) -> Result<()> {
    storage::remove_recoverable(&paths.config_file(), "connector config")?;
    PendingUpload::remove(paths)?;
    let receipts = paths.receipts_dir();
    if receipts.exists() {
        safe_remove_owned_dir(&receipts, &paths.state_dir)?;
    }
    let secure_file = paths.state_dir.join("device-secret.json");
    if secure_file.exists() {
        fs::remove_file(secure_file).context("remove connector secure-file fallback")?;
    }
    for directory in [&paths.config_dir, &paths.state_dir] {
        if directory.exists() {
            match fs::remove_dir(directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => {}
                Err(error) => return Err(error).context("remove empty connector directory"),
            }
        }
    }
    Ok(())
}

fn safe_remove_owned_dir(target: &Path, allowed_parent: &Path) -> Result<()> {
    let target = target.canonicalize().context("resolve removal target")?;
    let parent = allowed_parent
        .canonicalize()
        .context("resolve connector state directory")?;
    if target == parent || !target.starts_with(&parent) {
        bail!("refusing to remove a directory outside connector-owned state");
    }
    fs::remove_dir_all(target).context("remove connector-owned receipts")
}

fn emit<T: Serialize>(json_output: bool, value: &T, text: &str) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{text}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use project_relay_connector::protocol::{
        QuarantineStatus, SnapshotAccepted, TrustTier, UsageMetrics,
    };
    use std::collections::HashSet;
    use std::io::{BufRead as _, BufReader, Read as _};
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn browser_login_is_the_interactive_default() {
        assert_eq!(interactive_login_mode(false), LoginMode::Browser);
        assert_eq!(interactive_login_mode(true), LoginMode::DeviceCode);
    }

    fn test_config(server_key: &DeviceKey, device_key: &DeviceKey) -> Result<Config> {
        let mut config = Config::new(
            Url::parse("https://jointokenmaxxing.com")?,
            uuid::Uuid::new_v4().to_string(),
            device_key.public_key_base64(),
            KeyStorage::SecureFile,
        );
        config.paired = true;
        config.receipt_public_key = Some(server_key.public_key_base64());
        config.account_fingerprint = Some(format!("v1:{}", "A".repeat(43)));
        Ok(config)
    }

    fn test_snapshot(config: &Config) -> UsageSnapshotV1 {
        UsageSnapshotV1 {
            schema_version: 1,
            device_id: config.device_id.clone(),
            challenge_id: uuid::Uuid::new_v4().to_string(),
            connector_version: "0.1.0".into(),
            codex_version: "codex-cli 1.2.3".into(),
            observed_at: "2026-08-31T16:00:00Z".into(),
            fingerprint_version: 1,
            account_fingerprint: format!("v1:{}", "A".repeat(43)),
            consent_version: 1,
            metrics: UsageMetrics {
                lifetime_tokens: Some("12345".into()),
                peak_daily_tokens: None,
                longest_running_turn_sec: None,
                current_streak_days: None,
                longest_streak_days: None,
                daily_usage_buckets: None,
            },
            previous_receipt_hash: config.last_receipt_hash.clone(),
            signature: "A".repeat(86),
        }
    }

    fn signed_receipt(
        server_key: &DeviceKey,
        snapshot_hash: String,
        sequence: u64,
    ) -> Result<Receipt> {
        let mut receipt = Receipt {
            receipt_id: uuid::Uuid::new_v4().to_string(),
            accepted_at: "2026-08-31T16:00:01Z".into(),
            trust_tier: TrustTier::Synced,
            sequence,
            snapshot_hash,
            receipt_hash: "b".repeat(64),
            server_signature: "A".repeat(86),
            quarantine_status: QuarantineStatus::Clear,
            reason_codes: Vec::new(),
        };
        receipt.server_signature = server_key.sign_base64(&receipt.signing_bytes()?);
        Ok(receipt)
    }

    #[test]
    fn rejects_validly_signed_receipt_for_a_different_snapshot() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::discover(Some(directory.path()))?;
        let server_key = DeviceKey::generate();
        let device_key = DeviceKey::generate();
        let config = test_config(&server_key, &device_key)?;
        let snapshot = test_snapshot(&config);
        let receipt = signed_receipt(&server_key, "c".repeat(64), 1)?;

        let error = verify_sync_receipt(&config, &paths, &snapshot, &receipt)
            .err()
            .context("a receipt for a different snapshot must fail closed")?;
        assert!(error.to_string().contains("snapshot hash did not match"));
        assert!(!paths.receipts_dir().exists());
        Ok(())
    }

    #[test]
    fn rejects_receipt_that_skips_the_persisted_sequence() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::discover(Some(directory.path()))?;
        let server_key = DeviceKey::generate();
        let device_key = DeviceKey::generate();
        let mut config = test_config(&server_key, &device_key)?;
        let first_snapshot = test_snapshot(&config);
        let first_hash = sha256_hex(first_snapshot.canonical_payload()?.as_bytes());
        let first_receipt = signed_receipt(&server_key, first_hash, 1)?;
        verify_sync_receipt(&config, &paths, &first_snapshot, &first_receipt)?;
        persist_receipt(&paths, &first_receipt)?;
        config.last_receipt_id = Some(first_receipt.receipt_id.clone());
        config.last_receipt_hash = Some(first_receipt.receipt_hash.clone());

        let second_snapshot = test_snapshot(&config);
        let second_hash = sha256_hex(second_snapshot.canonical_payload()?.as_bytes());
        let skipped_receipt = signed_receipt(&server_key, second_hash, 3)?;
        let error = verify_sync_receipt(&config, &paths, &second_snapshot, &skipped_receipt)
            .err()
            .context("a skipped receipt sequence must fail closed")?;
        assert!(error.to_string().contains("sequence did not continue"));
        Ok(())
    }

    #[test]
    fn refuses_a_changed_managed_chatgpt_account_before_upload() -> Result<()> {
        let server_key = DeviceKey::generate();
        let device_key = DeviceKey::generate();
        let config = test_config(&server_key, &device_key)?;
        assert!(ensure_account_binding(
            &config,
            config.account_fingerprint.as_deref().unwrap_or_default()
        )
        .is_ok());
        let error = ensure_account_binding(&config, &format!("v1:{}", "B".repeat(43)))
            .err()
            .context("a changed account must fail before upload")?;
        assert!(error.to_string().contains("account changed"));
        Ok(())
    }

    #[test]
    fn recovers_receipt_written_before_config_chain_advance() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::discover(Some(directory.path()))?;
        let server_key = DeviceKey::generate();
        let device_key = DeviceKey::generate();
        let mut config = test_config(&server_key, &device_key)?;
        config.save(&paths)?;
        let nonce = "A".repeat(43);
        let mut snapshot = test_snapshot(&config);
        snapshot.signature = device_key.sign_base64(&snapshot.signing_bytes(&nonce)?);
        let snapshot_hash = sha256_hex(snapshot.canonical_payload()?.as_bytes());
        let receipt = signed_receipt(&server_key, snapshot_hash, 1)?;
        let mut pending = PendingUpload::new(snapshot, nonce)?;
        pending.save_new(&paths)?;
        pending.record_acceptance(SnapshotAccepted {
            receipt: receipt.clone(),
            leaderboard_eligible: false,
        })?;
        pending.save(&paths)?;

        // Fault injection: immutable receipt reached disk, then the process died
        // before config.save advanced the local chain head.
        persist_receipt(&paths, &receipt)?;
        let accepted = pending.accepted.clone().context("accepted journal state")?;
        let committed = commit_pending_acceptance(&mut config, &paths, &pending, accepted)?;
        assert_eq!(committed.receipt, receipt);
        let recovered = Config::load(&paths)?.context("recovered config")?;
        assert_eq!(recovered.last_receipt_id, Some(receipt.receipt_id));
        assert_eq!(recovered.last_receipt_hash, Some(receipt.receipt_hash));
        assert!(PendingUpload::load(&paths)?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn retries_exact_journal_after_accepted_upload_response_is_lost() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::discover(Some(directory.path()))?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server_key = DeviceKey::generate();
        let device_key = DeviceKey::generate();
        let mut config = test_config(&server_key, &device_key)?;
        config.server_url = Url::parse(&format!("http://{address}/"))?;
        config.save(&paths)?;
        let nonce = "A".repeat(43);
        let mut snapshot = test_snapshot(&config);
        snapshot.signature = device_key.sign_base64(&snapshot.signing_bytes(&nonce)?);
        let expected_body = serde_json::to_vec(&snapshot)?;
        let snapshot_hash = sha256_hex(snapshot.canonical_payload()?.as_bytes());
        let receipt = signed_receipt(&server_key, snapshot_hash, 1)?;
        let response_body = json!({
            "schemaVersion": 1,
            "requestId": uuid::Uuid::new_v4(),
            "data": {
                "receipt": receipt,
                "leaderboardEligible": false
            }
        })
        .to_string();
        let server = std::thread::spawn(move || -> Result<(Vec<Vec<u8>>, usize)> {
            let mut bodies = Vec::new();
            let mut accepted_bodies = HashSet::new();
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept()?;
                let body = read_http_request_body(&stream)?;
                accepted_bodies.insert(body.clone());
                bodies.push(body);
                if attempt == 0 {
                    // The server commits the first exact body, then the transport
                    // drops before the client receives its signed receipt.
                    continue;
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                stream.write_all(response.as_bytes())?;
                stream.flush()?;
            }
            Ok((bodies, accepted_bodies.len()))
        });

        let pending = PendingUpload::new(snapshot, nonce)?;
        pending.save_new(&paths)?;
        let api = ApiClient::new(config.server_url.clone())?;
        let first = submit_pending_upload(&mut config, &paths, &api, pending).await;
        assert!(first.is_err());
        assert!(config.last_receipt_hash.is_none());
        let retained = PendingUpload::load(&paths)?.context("retained exact upload")?;
        let committed = submit_pending_upload(&mut config, &paths, &api, retained).await?;
        assert_eq!(config.last_receipt_id, Some(committed.receipt.receipt_id));
        assert!(PendingUpload::load(&paths)?.is_none());

        let (bodies, accepted_count) = server
            .join()
            .map_err(|_| anyhow::anyhow!("test server thread panicked"))??;
        assert_eq!(bodies, vec![expected_body.clone(), expected_body]);
        assert_eq!(accepted_count, 1);
        Ok(())
    }

    fn read_http_request_body(stream: &TcpStream) -> Result<Vec<u8>> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut content_length = None;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                bail!("test request ended before its headers completed");
            }
            if line == "\r\n" {
                break;
            }
            let lowercase = line.to_ascii_lowercase();
            if let Some(value) = lowercase.strip_prefix("content-length:") {
                content_length = Some(value.trim().parse::<usize>()?);
            }
        }
        let length = content_length.context("test request omitted Content-Length")?;
        let mut body = vec![0_u8; length];
        reader.read_exact(&mut body)?;
        Ok(body)
    }
}
