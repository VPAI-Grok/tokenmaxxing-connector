//! Synthetic Codex executable used only by the connector integration tests.

use serde_json::{json, Value};
use std::env;
use std::io::{self, BufRead as _, Write};
use std::thread;
use std::time::Duration;

#[allow(clippy::too_many_lines)]
fn main() {
    let mode = env::var("RELAY_FAKE_CODEX_MODE").unwrap_or_else(|_| "happy".into());
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments == ["--version"] {
        if mode == "unsupported_version" {
            println!("codex-cli {}", "x".repeat(70));
        } else {
            println!("codex-cli 1.2.3");
        }
        return;
    }
    if arguments != ["app-server", "--stdio"] {
        std::process::exit(2);
    }
    if mode == "child_crash" {
        eprintln!("SECRET-RAW-PROVIDER-DIAGNOSTIC");
        std::process::exit(3);
    }

    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut logged_in = false;
    let login_fixture = matches!(
        mode.as_str(),
        "browser_login" | "browser_bad_origin" | "browser_login_failed" | "device_login"
    );
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            std::process::exit(4);
        };
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let id = request.get("id").cloned();
        if method == "initialized" {
            continue;
        }
        if mode == "timeout" {
            thread::sleep(Duration::from_secs(5));
        }
        if mode == "malformed" {
            let _ = writeln!(stdout, "{{SECRET-RAW-MALFORMED");
            let _ = stdout.flush();
            continue;
        }
        if mode == "oversized" {
            let _ = writeln!(stdout, "{}", "x".repeat(2 * 1024 * 1024 + 1));
            let _ = stdout.flush();
            continue;
        }

        let response = match method {
            "initialize" => json!({"id": id, "result": {"userAgent": "fake"}}),
            "account/read" => {
                let account = if mode == "logged_out" || (login_fixture && !logged_in) {
                    Value::Null
                } else {
                    match mode.as_str() {
                        "api_key" => {
                            json!({"type": "apiKey", "apiKey": "SECRET-MUST-NOT-LEAK"})
                        }
                        "account_b" => json!({
                            "type": "chatgpt",
                            "email": "second@example.com",
                            "planType": "SECRET-MUST-NOT-LEAK"
                        }),
                        _ => json!({
                            "type": "chatgpt",
                            "email": "builder@example.com",
                            "planType": "SECRET-MUST-NOT-LEAK",
                            "accessToken": "SECRET-MUST-NOT-LEAK"
                        }),
                    }
                };
                json!({"id": id, "result": {"account": account, "requiresOpenaiAuth": true}})
            }
            "account/login/start" => {
                let params = request.get("params").and_then(Value::as_object);
                let login_type = params
                    .and_then(|value| value.get("type"))
                    .and_then(Value::as_str);
                let browser_params_are_exact = login_type == Some("chatgpt")
                    && params
                        .and_then(|value| value.get("useHostedLoginSuccessPage"))
                        .and_then(Value::as_bool)
                        == Some(true)
                    && params
                        .and_then(|value| value.get("appBrand"))
                        .and_then(Value::as_str)
                        == Some("chatgpt");
                let login_id = "11111111-1111-4111-8111-111111111111";
                let (result, success) = match mode.as_str() {
                    "browser_login" | "browser_login_failed" if browser_params_are_exact => (
                        json!({
                            "type": "chatgpt",
                            "loginId": login_id,
                            "authUrl": "https://chatgpt.com/auth?redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback"
                        }),
                        mode != "browser_login_failed",
                    ),
                    "browser_bad_origin" if browser_params_are_exact => (
                        json!({
                            "type": "chatgpt",
                            "loginId": login_id,
                            "authUrl": "https://chatgpt.com.evil.example/steal"
                        }),
                        true,
                    ),
                    "device_login" if login_type == Some("chatgptDeviceCode") => (
                        json!({
                            "type": "chatgptDeviceCode",
                            "loginId": login_id,
                            "verificationUrl": "https://auth.openai.com/codex/device",
                            "userCode": "ABCD-1234"
                        }),
                        true,
                    ),
                    _ => {
                        write_json(
                            &mut stdout,
                            &json!({"id": id, "error": {"code": -32602, "message": "SECRET"}}),
                        );
                        continue;
                    }
                };
                logged_in = success;
                let response = json!({"id": id, "result": result});
                write_json(&mut stdout, &response);
                write_json(
                    &mut stdout,
                    &json!({
                        "method": "account/login/completed",
                        "params": {
                            "loginId": login_id,
                            "success": success,
                            "error": if success { Value::Null } else { json!("SECRET") }
                        }
                    }),
                );
                continue;
            }
            "account/usage/read" => json!({
                "id": id,
                "result": {
                    "summary": {
                        "lifetimeTokens": 1_234_567,
                        "peakDailyTokens": 45678,
                        "longestRunningTurnSec": 540,
                        "currentStreakDays": 8,
                        "longestStreakDays": 14,
                        "rawPrompt": "SECRET-MUST-NOT-LEAK"
                    },
                    "dailyUsageBuckets": [{
                        "startDate": "2026-08-30",
                        "tokens": 12345,
                        "path": "SECRET-MUST-NOT-LEAK"
                    }],
                    "undocumented": "SECRET-MUST-NOT-LEAK"
                }
            }),
            _ => json!({"id": id, "error": {"code": -32601, "message": "SECRET"}}),
        };
        write_json(&mut stdout, &response);
    }
}

fn write_json(output: &mut impl Write, value: &Value) {
    let _ = serde_json::to_writer(&mut *output, value);
    let _ = output.write_all(b"\n");
    let _ = output.flush();
}
