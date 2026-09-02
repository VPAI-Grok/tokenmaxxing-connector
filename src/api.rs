//! Typed Tokenmaxxing HTTP client.

use crate::crypto::DeviceKey;
use crate::protocol::{
    challenge_request_signing_bytes, disconnect_request_signing_bytes,
    receipt_request_signing_bytes, ApiEnvelope, ApiErrorEnvelope, ChallengeRequest,
    DisconnectRequest, DisconnectResult, PairingPoll, PairingStart, PairingStartRequest, Receipt,
    SnapshotAccepted, SyncChallenge, UsageSnapshotV1,
};
use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use reqwest::{Client, Method, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;
use url::Url;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// API client with bounded responses and no automatic credential state.
#[derive(Clone)]
pub struct ApiClient {
    base_url: Url,
    client: Client,
}

impl ApiClient {
    /// Construct a client for a validated Tokenmaxxing origin.
    pub fn new(base_url: Url) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!(
                "project-relay-connector/",
                env!("CARGO_PKG_VERSION")
            ))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build Tokenmaxxing HTTP client")?;
        Ok(Self { base_url, client })
    }

    /// Begin a browser pairing ceremony.
    pub async fn start_pairing(&self, device_id: &str, public_key: &str) -> Result<PairingStart> {
        let request = PairingStartRequest {
            device_id,
            public_key,
            connector_version: env!("CARGO_PKG_VERSION"),
        };
        self.send_json(
            Method::POST,
            "/api/v1/device/pairings",
            Some(&request),
            None,
        )
        .await
    }

    /// Read pairing status using the short-lived, read-only poll token.
    pub async fn poll_pairing(&self, pairing_id: &str, poll_token: &str) -> Result<PairingPoll> {
        uuid::Uuid::parse_str(pairing_id).context("invalid pairing ID")?;
        self.send_json::<(), PairingPoll>(
            Method::GET,
            &format!("/api/v1/device/pairings/{pairing_id}"),
            None,
            Some(poll_token),
        )
        .await
    }

    /// Create a short-lived challenge, proving possession of the device key.
    pub async fn create_challenge(
        &self,
        device_id: &str,
        previous_receipt_hash: Option<&str>,
        key: &DeviceKey,
    ) -> Result<SyncChallenge> {
        let body = ChallengeRequest {
            device_id,
            previous_receipt_hash,
        };
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let signature = key.sign_base64(&challenge_request_signing_bytes(&body, &timestamp)?);
        let url = self.endpoint("/api/v1/sync/challenges")?;
        let response = self
            .client
            .post(url)
            .header("X-Relay-Device-Id", device_id)
            .header("X-Relay-Timestamp", &timestamp)
            .header("X-Relay-Signature", signature)
            .json(&body)
            .send()
            .await
            .context("request a sync challenge")?;
        parse_response(response).await
    }

    /// Upload one signed, challenge-bound usage snapshot.
    pub async fn upload_snapshot(&self, snapshot: &UsageSnapshotV1) -> Result<SnapshotAccepted> {
        self.send_json(Method::POST, "/api/v1/sync/snapshots", Some(snapshot), None)
            .await
    }

    /// Revoke this device and immediately hide the owning profile.
    pub async fn disconnect(&self, device_id: &str, key: &DeviceKey) -> Result<DisconnectResult> {
        let body = DisconnectRequest { device_id };
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let signature = key.sign_base64(&disconnect_request_signing_bytes(&body, &timestamp)?);
        let response = self
            .client
            .post(self.endpoint("/api/v1/device/disconnect")?)
            .header("X-Relay-Device-Id", device_id)
            .header("X-Relay-Timestamp", &timestamp)
            .header("X-Relay-Signature", signature)
            .json(&body)
            .send()
            .await
            .context("disconnect Tokenmaxxing device")?;
        parse_response(response).await
    }

    /// Retrieve and verify accessibility of a durable receipt.
    pub async fn get_receipt(
        &self,
        device_id: &str,
        receipt_id: &str,
        key: &DeviceKey,
    ) -> Result<Receipt> {
        uuid::Uuid::parse_str(receipt_id).context("invalid receipt ID")?;
        let path = format!("/api/v1/sync/receipts/{receipt_id}");
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let signature = key.sign_base64(&receipt_request_signing_bytes(receipt_id, &timestamp));
        let response = self
            .client
            .get(self.endpoint(&path)?)
            .header("X-Relay-Device-Id", device_id)
            .header("X-Relay-Timestamp", timestamp)
            .header("X-Relay-Signature", signature)
            .send()
            .await
            .context("retrieve sync receipt")?;
        parse_response(response).await
    }

    async fn send_json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        bearer: Option<&str>,
    ) -> Result<T> {
        let mut request = self.client.request(method, self.endpoint(path)?);
        if let Some(body) = body {
            request = request.json(body);
        }
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.context("contact Tokenmaxxing")?;
        parse_response(response).await
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        if !path.starts_with('/') || path.contains("..") {
            bail!("invalid Tokenmaxxing API path");
        }
        self.base_url
            .join(path)
            .context("construct Tokenmaxxing API URL")
    }
}

async fn parse_response<T: DeserializeOwned>(mut response: Response) -> Result<T> {
    let status = response.status();
    let header_request_id = response
        .headers()
        .get("x-request-id")
        .map(|value| {
            value
                .to_str()
                .context("Tokenmaxxing returned a non-text request ID header")
                .map(str::to_owned)
        })
        .transpose()?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        bail!("Tokenmaxxing response exceeded the safety limit");
    }
    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .map_or(0, |length| length.min(MAX_RESPONSE_BYTES));
    let mut bytes = Vec::with_capacity(capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read Tokenmaxxing response")?
    {
        if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(bytes.len()) {
            bail!("Tokenmaxxing response exceeded the safety limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        return parse_error(status, &bytes, header_request_id.as_deref());
    }
    let envelope: ApiEnvelope<T> =
        serde_json::from_slice(&bytes).context("Tokenmaxxing returned an invalid response")?;
    if envelope.schema_version != 1 {
        bail!("Tokenmaxxing returned an unsupported schema version");
    }
    uuid::Uuid::parse_str(&envelope.request_id)
        .context("Tokenmaxxing returned an invalid request ID")?;
    validate_request_id(header_request_id.as_deref(), &envelope.request_id)?;
    Ok(envelope.data)
}

fn parse_error<T>(status: StatusCode, bytes: &[u8], header_request_id: Option<&str>) -> Result<T> {
    if let Ok(envelope) = serde_json::from_slice::<ApiErrorEnvelope>(bytes) {
        if envelope.schema_version != 1 || uuid::Uuid::parse_str(&envelope.request_id).is_err() {
            bail!("Tokenmaxxing returned an invalid error response (HTTP {status})");
        }
        validate_request_id(header_request_id, &envelope.request_id)?;
        let safe_code = sanitize_server_text(&envelope.error.code, 64);
        let safe_message = sanitize_server_text(&envelope.error.message, 240);
        bail!(
            "Tokenmaxxing request failed ({status}, {safe_code}, retryable={}): {safe_message}; request {}",
            envelope.error.retryable,
            envelope.request_id
        );
    }
    bail!("Tokenmaxxing request failed with HTTP {status}")
}

fn validate_request_id(header_request_id: Option<&str>, envelope_request_id: &str) -> Result<()> {
    if let Some(header_request_id) = header_request_id {
        uuid::Uuid::parse_str(header_request_id)
            .context("Tokenmaxxing returned an invalid request ID header")?;
        if header_request_id != envelope_request_id {
            bail!("Tokenmaxxing response request IDs did not match");
        }
    }
    Ok(())
}

fn sanitize_server_text(value: &str, maximum: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(maximum)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn pairing_uses_exact_allowlisted_request() {
        let server = MockServer::start().await;
        let request_id = uuid::Uuid::new_v4();
        let pairing_id = uuid::Uuid::new_v4();
        Mock::given(method("POST"))
            .and(path("/api/v1/device/pairings"))
            .and(body_json(json!({
                "deviceId": "device-id",
                "publicKey": "public-key",
                "connectorVersion": env!("CARGO_PKG_VERSION")
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({
                        "schemaVersion": 1,
                        "requestId": request_id,
                        "data": {
                            "pairingId": pairing_id,
                            "userCode": "ABCD-1234",
                            "verificationUri": "https://jointokenmaxxing.com/connect",
                            "expiresAt": "2026-08-31T12:00:00Z",
                            "pollIntervalSeconds": 5,
                            "status": "pending",
                            "pollToken": "secret-poll-token",
                            "receiptPublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                        }
                    }))
                    .insert_header("x-request-id", request_id.to_string()),
            )
            .mount(&server)
            .await;
        let client = ApiClient::new(Url::parse(&server.uri()).unwrap_or_else(|_| panic!("url")))
            .unwrap_or_else(|_| panic!("client"));
        let result = client.start_pairing("device-id", "public-key").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn response_rejects_mismatched_request_id_header() {
        let server = MockServer::start().await;
        let body_request_id = uuid::Uuid::new_v4();
        let header_request_id = uuid::Uuid::new_v4();
        Mock::given(method("POST"))
            .and(path("/api/v1/device/pairings"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-request-id", header_request_id.to_string())
                    .set_body_json(json!({
                        "schemaVersion": 1,
                        "requestId": body_request_id,
                        "data": {
                            "pairingId": uuid::Uuid::new_v4(),
                            "userCode": "ABCD-1234",
                            "verificationUri": "https://jointokenmaxxing.com/connect",
                            "expiresAt": "2026-08-31T12:00:00Z",
                            "pollIntervalSeconds": 5,
                            "status": "pending",
                            "pollToken": "secret-poll-token",
                            "receiptPublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                        }
                    })),
            )
            .mount(&server)
            .await;
        let client = ApiClient::new(Url::parse(&server.uri()).unwrap_or_else(|_| panic!("url")))
            .unwrap_or_else(|_| panic!("client"));
        let error = client
            .start_pairing("device-id", "public-key")
            .await
            .err()
            .map(|value| format!("{value:#}"))
            .unwrap_or_default();
        assert!(error.contains("request IDs did not match"));
    }

    #[test]
    fn untrusted_server_text_is_bounded_and_single_line() {
        let text = format!("hello\n{}", "x".repeat(500));
        let safe = sanitize_server_text(&text, 20);
        assert_eq!(safe.len(), 20);
        assert!(!safe.contains('\n'));
    }
}
