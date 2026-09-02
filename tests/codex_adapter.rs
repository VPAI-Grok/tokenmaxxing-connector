//! Failure-matrix coverage for the real child-process adapter.

#![cfg(feature = "test-fixtures")]

use project_relay_connector::codex::{collect, CollectOptions, LoginMode};
use std::env;
use std::path::Path;
use std::time::{Duration, Instant};

fn collect_mode(
    mode: &str,
    login_mode: LoginMode,
    timeout: Duration,
) -> anyhow::Result<project_relay_connector::codex::CollectedUsage> {
    env::set_var("RELAY_FAKE_CODEX_MODE", mode);
    collect(&CollectOptions {
        codex_path: Some(Path::new(env!("CARGO_BIN_EXE_fake-codex"))),
        login_mode,
        open_browser: false,
        request_timeout: timeout,
    })
}

#[test]
fn adapter_handles_auth_schema_crash_timeout_and_account_switching() {
    let happy = collect_mode("happy", LoginMode::Disabled, Duration::from_secs(2))
        .unwrap_or_else(|_| panic!("happy fixture must collect"));
    assert_eq!(happy.metrics.lifetime_tokens.as_deref(), Some("1234567"));
    let serialized = serde_json::to_string(&happy.metrics).unwrap_or_default();
    assert!(!serialized.contains("SECRET"));
    assert!(!serialized.contains("rawPrompt"));
    assert!(!happy.account_fingerprint.contains("builder"));

    let second = collect_mode("account_b", LoginMode::Disabled, Duration::from_secs(2))
        .unwrap_or_else(|_| panic!("second account fixture must collect"));
    assert_ne!(happy.account_fingerprint, second.account_fingerprint);

    let logged_out = collect_mode("logged_out", LoginMode::Disabled, Duration::from_secs(2))
        .err()
        .map(|error| format!("{error:#}"))
        .unwrap_or_default();
    assert!(logged_out.contains("logged out"));
    assert!(!logged_out.contains("SECRET"));

    let browser_login = collect_mode("browser_login", LoginMode::Browser, Duration::from_secs(2));
    assert!(browser_login.is_ok());

    let device_login = collect_mode(
        "device_login",
        LoginMode::DeviceCode,
        Duration::from_secs(2),
    );
    assert!(device_login.is_ok());

    let bad_browser_origin = collect_mode(
        "browser_bad_origin",
        LoginMode::Browser,
        Duration::from_secs(2),
    )
    .err()
    .map(|error| format!("{error:#}"))
    .unwrap_or_default();
    assert!(bad_browser_origin.contains("unexpected browser authorization origin"));

    let failed_browser_login = collect_mode(
        "browser_login_failed",
        LoginMode::Browser,
        Duration::from_secs(2),
    )
    .err()
    .map(|error| format!("{error:#}"))
    .unwrap_or_default();
    assert!(failed_browser_login.contains("--device-code"));
    assert!(!failed_browser_login.contains("SECRET"));

    let api_key = collect_mode("api_key", LoginMode::Disabled, Duration::from_secs(2))
        .err()
        .map(|error| format!("{error:#}"))
        .unwrap_or_default();
    assert!(api_key.contains("managed ChatGPT authentication only"));
    assert!(!api_key.contains("SECRET"));

    for mode in [
        "malformed",
        "oversized",
        "child_crash",
        "unsupported_version",
    ] {
        let error = collect_mode(mode, LoginMode::Disabled, Duration::from_secs(2))
            .err()
            .map(|error| format!("{error:#}"))
            .unwrap_or_default();
        assert!(!error.is_empty(), "{mode} must fail closed");
        assert!(!error.contains("SECRET"), "{mode} leaked raw provider text");
    }

    let started = Instant::now();
    let timeout = collect_mode("timeout", LoginMode::Disabled, Duration::from_millis(100))
        .err()
        .map(|error| format!("{error:#}"))
        .unwrap_or_default();
    assert!(timeout.contains("timed out"));
    assert!(started.elapsed() < Duration::from_secs(2));
    env::remove_var("RELAY_FAKE_CODEX_MODE");
}
