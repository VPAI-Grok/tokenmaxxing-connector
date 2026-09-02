//! Minimal privacy-bounded client for `codex app-server --stdio`.
//!
//! Raw JSON-RPC messages are never logged or returned to callers. Provider
//! responses are projected immediately into the documented usage allowlist.

use crate::crypto::account_fingerprint;
use crate::protocol::{DailyUsageBucket, UsageMetrics};
use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const MAX_RPC_LINE_BYTES: usize = 2 * 1024 * 1024;
const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Privacy-safe usage collected from the documented Codex account endpoints.
#[derive(Clone)]
pub struct CollectedUsage {
    /// Connector-safe Codex version.
    pub codex_version: String,
    /// UTC observation timestamp.
    pub observed_at: String,
    /// Locally derived pseudonymous account fingerprint.
    pub account_fingerprint: String,
    /// Strict upload allowlist.
    pub metrics: UsageMetrics,
}

/// Local Codex executable diagnostics that never include account identity.
#[derive(Debug, Clone)]
pub struct CodexProbe {
    /// Resolved executable path.
    pub executable: PathBuf,
    /// Sanitized CLI version.
    pub version: String,
    /// Whether the account is managed ChatGPT auth.
    pub managed_chatgpt: bool,
}

/// Managed ChatGPT sign-in behavior when Codex is logged out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginMode {
    /// Fail without starting an interactive sign-in ceremony.
    Disabled,
    /// Use the App Server browser flow and its localhost callback.
    Browser,
    /// Use the App Server device-code flow as an explicit fallback.
    DeviceCode,
}

/// Options for collecting account usage.
#[derive(Debug, Clone)]
pub struct CollectOptions<'a> {
    /// Optional exact executable path.
    pub codex_path: Option<&'a Path>,
    /// Managed ChatGPT sign-in behavior when logged out.
    pub login_mode: LoginMode,
    /// Open the sign-in URL in the default browser.
    pub open_browser: bool,
    /// Maximum wait for each app-server message.
    pub request_timeout: Duration,
}

/// Resolve a Codex executable without invoking a shell.
pub fn resolve_codex(explicit: Option<&Path>) -> Result<PathBuf> {
    let candidate = if let Some(path) = explicit {
        path.to_path_buf()
    } else if let Some(path) = env::var_os("PROJECT_RELAY_CODEX_PATH") {
        PathBuf::from(path)
    } else {
        which::which("codex").context(
            "Codex CLI was not found; install Codex or pass --codex-path / set PROJECT_RELAY_CODEX_PATH",
        )?
    };
    if !candidate.is_file() {
        bail!("the resolved Codex path is not a file");
    }
    candidate
        .canonicalize()
        .context("resolve the exact Codex executable path")
}

/// Collect the documented account usage fields from managed ChatGPT auth.
pub fn collect(options: &CollectOptions<'_>) -> Result<CollectedUsage> {
    let executable = resolve_codex(options.codex_path)?;
    let version = codex_version(&executable)?;
    let mut server = AppServer::spawn(&executable, options.request_timeout)?;
    server.initialize()?;

    let mut account = server.read_account(1)?;
    if account.is_none() {
        match options.login_mode {
            LoginMode::Disabled => {
                bail!("Codex is logged out; run `tokenmaxxing connect` to sign in")
            }
            LoginMode::Browser => server
                .browser_login(options.open_browser)
                .context(
                    "ChatGPT browser sign-in failed; rerun with --device-code if the localhost callback is unavailable",
                )?,
            LoginMode::DeviceCode => server.device_code_login(options.open_browser)?,
        }
        account = server.read_account(3)?;
    }

    let mut email = match account {
        Some(Account::ChatGpt { email }) => email,
        Some(Account::Unsupported) => {
            bail!("Tokenmaxxing supports managed ChatGPT authentication only; API-key and external-provider auth are excluded")
        }
        None => bail!("managed ChatGPT login did not complete"),
    };
    let fingerprint = account_fingerprint(&email)?;
    email.zeroize();

    let mut result = server.request(4, "account/usage/read", None)?;
    let projected = project_usage(&result);
    scrub_json_strings(&mut result);
    let metrics = projected?;
    metrics.validate()?;
    Ok(CollectedUsage {
        codex_version: version,
        observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        account_fingerprint: fingerprint,
        metrics,
    })
}

/// Verify executable, app-server handshake, and managed-auth state without reading usage.
pub fn probe(codex_path: Option<&Path>) -> Result<CodexProbe> {
    let executable = resolve_codex(codex_path)?;
    let version = codex_version(&executable)?;
    let mut server = AppServer::spawn(&executable, RPC_TIMEOUT)?;
    server.initialize()?;
    let managed_chatgpt = matches!(server.read_account(1)?, Some(Account::ChatGpt { .. }));
    Ok(CodexProbe {
        executable,
        version,
        managed_chatgpt,
    })
}

fn codex_version(executable: &Path) -> Result<String> {
    let output = Command::new(executable)
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("execute `codex --version` directly")?;
    if !output.status.success() {
        bail!("`codex --version` failed");
    }
    let version = String::from_utf8(output.stdout).context("Codex version was not UTF-8")?;
    let version = version.trim();
    if version.is_empty() || version.len() > 64 || version.chars().any(char::is_control) {
        bail!("Codex returned an invalid version string");
    }
    Ok(version.to_owned())
}

enum Account {
    ChatGpt { email: Zeroizing<String> },
    Unsupported,
}

struct AppServer {
    child: Child,
    stdin: ChildStdin,
    receiver: Receiver<std::result::Result<Value, &'static str>>,
    pending: VecDeque<Value>,
    reader_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    timeout: Duration,
}

impl AppServer {
    fn spawn(executable: &Path, timeout: Duration) -> Result<Self> {
        let mut child = Command::new(executable)
            .arg("app-server")
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("start `codex app-server --stdio` directly")?;
        let stdin = child.stdin.take().context("open Codex app-server stdin")?;
        let stdout = child
            .stdout
            .take()
            .context("open Codex app-server stdout")?;
        let stderr = child
            .stderr
            .take()
            .context("open Codex app-server stderr")?;
        let (sender, receiver) = mpsc::channel();
        let reader_thread = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                // `take` caps allocation before a malicious or incompatible
                // child can emit an unterminated, arbitrarily large line.
                let mut line = Vec::with_capacity(8 * 1024);
                match reader
                    .by_ref()
                    .take((MAX_RPC_LINE_BYTES + 1) as u64)
                    .read_until(b'\n', &mut line)
                {
                    Ok(0) => {
                        let _ = sender.send(Err("Codex app-server closed its output"));
                        break;
                    }
                    Ok(count) if count > MAX_RPC_LINE_BYTES => {
                        line.zeroize();
                        let _ =
                            sender.send(Err("Codex app-server response exceeded the safety limit"));
                        break;
                    }
                    Ok(_) => {
                        let parsed = serde_json::from_slice::<Value>(&line)
                            .map_err(|_| "Codex app-server returned malformed JSON");
                        line.zeroize();
                        if sender.send(parsed).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = sender.send(Err("failed to read Codex app-server output"));
                        break;
                    }
                }
            }
        });
        let stderr_thread = thread::spawn(move || {
            // Deliberately discard stderr. It can include upstream diagnostics,
            // file paths, or account details and must never enter Tokenmaxxing logs.
            let mut stderr = stderr;
            let mut buffer = [0_u8; 8 * 1024];
            while let Ok(count) = stderr.read(&mut buffer) {
                if count == 0 {
                    break;
                }
                buffer[..count].zeroize();
            }
        });
        Ok(Self {
            child,
            stdin,
            receiver,
            pending: VecDeque::new(),
            reader_thread: Some(reader_thread),
            stderr_thread: Some(stderr_thread),
            timeout,
        })
    }

    fn initialize(&mut self) -> Result<()> {
        let mut result = self.request(
            0,
            "initialize",
            Some(json!({
                "clientInfo": {
                    "name": "project_relay_connector",
                    "title": "Tokenmaxxing Connector",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
        )?;
        let valid = result.is_object();
        scrub_json_strings(&mut result);
        if !valid {
            bail!("Codex app-server returned an invalid initialize response");
        }
        self.send(&json!({"method": "initialized"}))
    }

    fn read_account(&mut self, id: u64) -> Result<Option<Account>> {
        let mut result = self.request(id, "account/read", Some(json!({"refreshToken": false})))?;
        let account = result
            .as_object()
            .and_then(|object| object.get("account"))
            .context("Codex account response omitted account")?;
        if account.is_null() {
            scrub_json_strings(&mut result);
            return Ok(None);
        }
        let object = account
            .as_object()
            .context("Codex account response was invalid")?;
        let account_type = object
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let email = object
            .get("email")
            .and_then(Value::as_str)
            .map(str::to_owned);
        scrub_json_strings(&mut result);
        if account_type.as_deref() != Some("chatgpt") {
            return Ok(Some(Account::Unsupported));
        }
        let email = email.context("managed ChatGPT account did not provide an email")?;
        Ok(Some(Account::ChatGpt {
            email: Zeroizing::new(email),
        }))
    }

    fn browser_login(&mut self, open_browser: bool) -> Result<()> {
        let mut result = self.request(
            2,
            "account/login/start",
            Some(json!({
                "type": "chatgpt",
                "useHostedLoginSuccessPage": true,
                "appBrand": "chatgpt"
            })),
        )?;
        let login_type = required_string(&result, "type", "browser login")?;
        let login_id = required_string(&result, "loginId", "browser login")?;
        let auth_url = required_string(&result, "authUrl", "browser login")?;
        scrub_json_strings(&mut result);
        if login_type != "chatgpt" {
            bail!("Codex returned an unexpected browser login type");
        }
        validate_login_url(&auth_url, "chatgpt.com", "browser authorization")?;
        validate_browser_redirect(&auth_url)?;

        if open_browser {
            if webbrowser::open(&auth_url).is_ok() {
                println!("Your browser is opening. Complete ChatGPT sign-in to continue.");
            } else {
                println!("Could not open a browser automatically. Open this URL: {auth_url}");
            }
        } else {
            println!("Open this URL to sign in with ChatGPT: {auth_url}");
        }
        self.wait_for_login(&login_id)
    }

    fn device_code_login(&mut self, open_browser: bool) -> Result<()> {
        let mut result = self.request(
            2,
            "account/login/start",
            Some(json!({"type": "chatgptDeviceCode"})),
        )?;
        let login_type = required_string(&result, "type", "device login")?;
        let login_id = required_string(&result, "loginId", "device login")?;
        let verification_url = required_string(&result, "verificationUrl", "device login")?;
        let user_code = required_string(&result, "userCode", "device login")?;
        scrub_json_strings(&mut result);
        if login_type != "chatgptDeviceCode" {
            bail!("Codex returned an unexpected device login type");
        }
        validate_login_url(&verification_url, "auth.openai.com", "device verification")?;
        println!("Open {verification_url} and enter code {user_code}");
        if open_browser {
            let _ = webbrowser::open(&verification_url);
        }
        self.wait_for_login(&login_id)
    }

    fn wait_for_login(&mut self, login_id: &str) -> Result<()> {
        // Interactive authorization needs time for a human to switch to a
        // browser. Normal RPCs remain bounded to 30 seconds; login alone gets
        // ten minutes. Tests that opt into a shorter RPC timeout retain it.
        let timeout = if self.timeout < RPC_TIMEOUT {
            self.timeout
        } else {
            LOGIN_TIMEOUT
        };
        let deadline = Instant::now() + timeout;
        loop {
            let pending_index = self.pending.iter().position(|message| {
                message.get("method").and_then(Value::as_str) == Some("account/login/completed")
                    && message
                        .get("params")
                        .and_then(Value::as_object)
                        .and_then(|value| value.get("loginId"))
                        .and_then(Value::as_str)
                        == Some(login_id)
            });
            let mut message = if let Some(index) = pending_index {
                self.pending
                    .remove(index)
                    .context("read pending login notification")?
            } else {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .context("timed out waiting for managed ChatGPT sign-in")?;
                self.receive_message_with_timeout(remaining)
                    .context("timed out waiting for managed ChatGPT sign-in")?
            };
            if message.get("method").and_then(Value::as_str) != Some("account/login/completed") {
                self.pending.push_back(message);
                continue;
            }
            let params = message.get("params").and_then(Value::as_object);
            let matching = params
                .and_then(|value| value.get("loginId"))
                .and_then(Value::as_str)
                == Some(login_id);
            let succeeded = params
                .and_then(|value| value.get("success"))
                .and_then(Value::as_bool)
                == Some(true);
            scrub_json_strings(&mut message);
            if !matching {
                continue;
            }
            if succeeded {
                return Ok(());
            }
            bail!("managed ChatGPT sign-in did not complete");
        }
    }

    fn request(&mut self, id: u64, method: &'static str, params: Option<Value>) -> Result<Value> {
        let mut request = json!({"method": method, "id": id});
        if let Some(params) = params {
            request
                .as_object_mut()
                .context("construct app-server request")?
                .insert("params".into(), params);
        }
        self.send(&request)?;
        loop {
            let mut message = if let Some(index) = self
                .pending
                .iter()
                .position(|message| message.get("id").and_then(Value::as_u64) == Some(id))
            {
                self.pending
                    .remove(index)
                    .context("read pending app-server response")?
            } else {
                self.receive_message()?
            };
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                self.pending.push_back(message);
                continue;
            }
            if let Some(error) = message.get("error") {
                let code = error
                    .get("code")
                    .map_or_else(|| "unknown".into(), Value::to_string);
                scrub_json_strings(&mut message);
                bail!("Codex app-server rejected {method} (code {code})");
            }
            let result = message
                .get("result")
                .cloned()
                .with_context(|| format!("Codex app-server omitted the {method} result"));
            scrub_json_strings(&mut message);
            return result;
        }
    }

    fn send(&mut self, value: &Value) -> Result<()> {
        serde_json::to_writer(&mut self.stdin, value).context("encode app-server request")?;
        self.stdin
            .write_all(b"\n")
            .context("write app-server request")?;
        self.stdin.flush().context("flush app-server request")
    }

    fn receive_message(&mut self) -> Result<Value> {
        self.receive_message_with_timeout(self.timeout)
    }

    fn receive_message_with_timeout(&mut self, timeout: Duration) -> Result<Value> {
        self.receiver
            .recv_timeout(timeout)
            .context("timed out waiting for Codex app-server")?
            .map_err(anyhow::Error::msg)
    }
}

impl Drop for AppServer {
    fn drop(&mut self) {
        self.pending.iter_mut().for_each(scrub_json_strings);
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr_thread.take() {
            let _ = handle.join();
        }
    }
}

fn required_string(value: &Value, field: &str, context: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .with_context(|| format!("{context} response omitted {field}"))
}

fn validate_login_url(value: &str, expected_host: &str, context: &str) -> Result<()> {
    let parsed = Url::parse(value).with_context(|| format!("invalid {context} URL"))?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some(expected_host)
        || parsed.port_or_known_default() != Some(443)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        bail!("Codex returned an unexpected {context} origin");
    }
    Ok(())
}

fn validate_browser_redirect(value: &str) -> Result<()> {
    let authorization_url = Url::parse(value).context("invalid browser authorization URL")?;
    let redirect_values = authorization_url
        .query_pairs()
        .filter_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
        .collect::<Vec<_>>();
    if redirect_values.len() != 1 {
        bail!("Codex browser authorization omitted the unique loopback callback");
    }

    let redirect = Url::parse(&redirect_values[0]).context("invalid browser callback URL")?;
    if redirect.scheme() != "http"
        || redirect.host_str() != Some("localhost")
        || redirect.port().is_none_or(|port| port == 0)
        || redirect.path() != "/auth/callback"
        || !redirect.username().is_empty()
        || redirect.password().is_some()
    {
        bail!("Codex returned an unexpected browser callback");
    }
    Ok(())
}

fn project_usage(result: &Value) -> Result<UsageMetrics> {
    let object = result
        .as_object()
        .context("Codex usage response was not an object")?;
    let summary = object
        .get("summary")
        .and_then(Value::as_object)
        .context("Codex usage response omitted summary")?;
    let mut daily_usage_buckets = match object.get("dailyUsageBuckets") {
        None | Some(Value::Null) => None,
        Some(Value::Array(values)) => {
            let mut buckets = Vec::with_capacity(values.len());
            for value in values {
                let bucket = value
                    .as_object()
                    .context("invalid Codex daily usage bucket")?;
                buckets.push(DailyUsageBucket {
                    start_date: bucket
                        .get("startDate")
                        .and_then(Value::as_str)
                        .context("Codex daily bucket omitted startDate")?
                        .to_owned(),
                    tokens: project_decimal(bucket.get("tokens"), "daily bucket tokens")?
                        .context("Codex daily bucket tokens were null")?,
                });
            }
            buckets.sort_by(|left, right| left.start_date.cmp(&right.start_date));
            Some(buckets)
        }
        Some(_) => bail!("Codex dailyUsageBuckets had an invalid type"),
    };
    // The temporary raw response is dropped immediately after this projection.
    let metrics = UsageMetrics {
        lifetime_tokens: project_decimal(summary.get("lifetimeTokens"), "lifetimeTokens")?,
        peak_daily_tokens: project_decimal(summary.get("peakDailyTokens"), "peakDailyTokens")?,
        longest_running_turn_sec: project_decimal(
            summary.get("longestRunningTurnSec"),
            "longestRunningTurnSec",
        )?,
        current_streak_days: project_u32(summary.get("currentStreakDays"), "currentStreakDays")?,
        longest_streak_days: project_u32(summary.get("longestStreakDays"), "longestStreakDays")?,
        daily_usage_buckets: daily_usage_buckets.take(),
    };
    metrics.validate()?;
    Ok(metrics)
}

fn project_decimal(value: Option<&Value>, field: &str) -> Result<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) if number.is_u64() => Ok(Some(number.to_string())),
        Some(Value::String(value)) if value.bytes().all(|byte| byte.is_ascii_digit()) => {
            Ok(Some(value.clone()))
        }
        Some(_) => bail!("Codex {field} was not a non-negative integer"),
    }
}

fn project_u32(value: Option<&Value>, field: &str) -> Result<Option<u32>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(Some)
            .with_context(|| format!("Codex {field} exceeded the supported range")),
        Some(_) => bail!("Codex {field} was not a non-negative integer"),
    }
}

fn scrub_json_strings(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(scrub_json_strings),
        Value::Object(values) => values.values_mut().for_each(scrub_json_strings),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_projection_is_a_strict_allowlist() {
        let raw = json!({
            "summary": {
                "lifetimeTokens": 123,
                "peakDailyTokens": null,
                "longestRunningTurnSec": 5,
                "currentStreakDays": 2,
                "longestStreakDays": 4,
                "planType": "must-not-leak",
                "futureUndocumentedField": "must-not-leak"
            },
            "dailyUsageBuckets": [{
                "startDate": "2026-08-31",
                "tokens": 12,
                "prompt": "must-not-leak"
            }],
            "raw": "must-not-leak"
        });
        let metrics = project_usage(&raw).unwrap_or_else(|_| panic!("valid documented fields"));
        let serialized = serde_json::to_string(&metrics).unwrap_or_default();
        assert!(serialized.contains("123"));
        assert!(!serialized.contains("planType"));
        assert!(!serialized.contains("prompt"));
        assert!(!serialized.contains("futureUndocumentedField"));
    }

    #[test]
    fn login_urls_are_https_and_pinned_to_the_expected_origin() {
        assert!(validate_login_url(
            "https://chatgpt.com/auth?redirect_uri=http%3A%2F%2Flocalhost%3A1234%2Fauth%2Fcallback",
            "chatgpt.com",
            "browser authorization",
        )
        .is_ok());
        assert!(validate_browser_redirect(
            "https://chatgpt.com/auth?redirect_uri=http%3A%2F%2Flocalhost%3A1234%2Fauth%2Fcallback",
        )
        .is_ok());
        assert!(validate_login_url(
            "https://auth.openai.com/codex/device",
            "auth.openai.com",
            "device verification",
        )
        .is_ok());
        assert!(validate_login_url(
            "https://chatgpt.com.evil.example/auth",
            "chatgpt.com",
            "browser authorization",
        )
        .is_err());
        assert!(validate_login_url(
            "http://chatgpt.com/auth",
            "chatgpt.com",
            "browser authorization",
        )
        .is_err());
        assert!(validate_login_url(
            "https://chatgpt.com:8443/auth",
            "chatgpt.com",
            "browser authorization",
        )
        .is_err());
        assert!(validate_browser_redirect(
            "https://chatgpt.com/auth?redirect_uri=http%3A%2F%2Fevil.example%3A1234%2Fauth%2Fcallback",
        )
        .is_err());
    }

    #[test]
    fn usage_projection_preserves_null_as_null() {
        let raw = json!({
            "summary": {
                "lifetimeTokens": null,
                "peakDailyTokens": null,
                "longestRunningTurnSec": null,
                "currentStreakDays": null,
                "longestStreakDays": null
            },
            "dailyUsageBuckets": null
        });
        let metrics = project_usage(&raw).unwrap_or_else(|_| panic!("nullable fields"));
        assert!(metrics.lifetime_tokens.is_none());
        assert!(metrics.daily_usage_buckets.is_none());
    }
}
