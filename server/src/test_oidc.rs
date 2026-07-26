//! Fake OIDC issuer for integration tests (feature `test-util`): serves
//! discovery/JWKS documents, mints RS256-signed tokens, and implements a
//! minimal auto-approving device authorization flow.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::response::IntoResponse;
use base64::Engine;
use rsa::traits::PublicKeyParts;

const KID: &str = "test-key";
const DEVICE_CODE: &str = "test-device-code";
const REFRESH_TOKEN: &str = "test-refresh-token";

pub struct FakeIssuer {
    inner: Arc<Inner>,
}

struct Inner {
    addr: SocketAddr,
    encoding_key: jsonwebtoken::EncodingKey,
    jwks: serde_json::Value,
    device_flow: Mutex<DeviceFlow>,
}

/// State of the auto-approving device grant.
#[derive(Default)]
struct DeviceFlow {
    /// Subject issued once the device code is polled; None rejects the grant.
    grant_sub: Option<String>,
    /// Number of polls answered with authorization_pending before success.
    pending_polls: u32,
}

#[derive(serde::Serialize)]
struct Claims {
    iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    aud: String,
    exp: u64,
    iat: u64,
}

impl FakeIssuer {
    pub async fn start() -> Self {
        let private_key =
            rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("generate test RSA key");
        let pem = rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_pem(&private_key, Default::default())
            .expect("encode test key");
        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).expect("load test key");

        let base64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let public_key = private_key.to_public_key();
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": KID,
                "n": base64url.encode(public_key.n().to_bytes_be()),
                "e": base64url.encode(public_key.e().to_bytes_be()),
            }]
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake issuer");
        let addr = listener.local_addr().expect("issuer address");
        let inner = Arc::new(Inner {
            addr,
            encoding_key,
            jwks,
            device_flow: Mutex::new(DeviceFlow::default()),
        });

        let router = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(discovery),
            )
            .route("/jwks", axum::routing::get(jwks_document))
            .route("/device", axum::routing::post(device_authorization))
            .route("/token", axum::routing::post(token_grant))
            .with_state(Arc::clone(&inner));
        tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });

        Self { inner }
    }

    pub fn issuer_url(&self) -> String {
        self.inner.issuer_url()
    }

    /// Configures the device flow to grant tokens for `sub` after answering
    /// `pending_polls` token requests with authorization_pending.
    pub fn grant_device_flow(&self, sub: &str, pending_polls: u32) {
        *self.inner.device_flow.lock().unwrap() = DeviceFlow {
            grant_sub: Some(sub.to_string()),
            pending_polls,
        };
    }

    /// Mints a signed token; `expires_in` may be negative to produce an
    /// already-expired token.
    pub fn token(&self, sub: &str, audience: &str, expires_in_secs: i64) -> String {
        self.inner.token(Some(sub), audience, expires_in_secs)
    }

    /// Mints a client_credentials-style token: no `sub`, only `client_id`
    /// (matching e.g. Authelia's behaviour).
    pub fn client_credentials_token(&self, client_id: &str) -> String {
        self.inner.token(None, client_id, 300)
    }
}

impl Inner {
    fn issuer_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn token(&self, sub: Option<&str>, audience: &str, expires_in_secs: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let claims = Claims {
            iss: self.issuer_url(),
            sub: sub.map(str::to_string),
            client_id: sub.is_none().then(|| audience.to_string()),
            aud: audience.to_string(),
            exp: now.saturating_add_signed(expires_in_secs),
            iat: now,
        };
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(KID.to_string());
        jsonwebtoken::encode(&header, &claims, &self.encoding_key).expect("sign test token")
    }
}

async fn discovery(State(inner): State<Arc<Inner>>) -> impl IntoResponse {
    let issuer = inner.issuer_url();
    axum::Json(serde_json::json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/jwks"),
        "device_authorization_endpoint": format!("{issuer}/device"),
        "token_endpoint": format!("{issuer}/token"),
    }))
}

async fn jwks_document(State(inner): State<Arc<Inner>>) -> impl IntoResponse {
    axum::Json(inner.jwks.clone())
}

async fn device_authorization(State(inner): State<Arc<Inner>>) -> impl IntoResponse {
    let issuer = inner.issuer_url();
    axum::Json(serde_json::json!({
        "device_code": DEVICE_CODE,
        "user_code": "TEST-CODE",
        "verification_uri": format!("{issuer}/verify"),
        "verification_uri_complete": format!("{issuer}/verify?user_code=TEST-CODE"),
        "interval": 0,
        "expires_in": 300,
    }))
}

async fn token_grant(
    State(inner): State<Arc<Inner>>,
    axum::Form(form): axum::Form<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let client_id = form.get("client_id").cloned().unwrap_or_default();
    let grant_type = form.get("grant_type").map(String::as_str);

    let sub = match grant_type {
        Some("urn:ietf:params:oauth:grant-type:device_code")
            if form.get("device_code").map(String::as_str) == Some(DEVICE_CODE) =>
        {
            let mut flow = inner.device_flow.lock().unwrap();
            if flow.pending_polls > 0 {
                flow.pending_polls -= 1;
                return oauth_error("authorization_pending");
            }
            flow.grant_sub.clone()
        }
        Some("refresh_token")
            if form.get("refresh_token").map(String::as_str) == Some(REFRESH_TOKEN) =>
        {
            inner.device_flow.lock().unwrap().grant_sub.clone()
        }
        _ => None,
    };
    let Some(sub) = sub else {
        return oauth_error("access_denied");
    };

    axum::Json(serde_json::json!({
        "access_token": inner.token(Some(&sub), &client_id, 3600),
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": REFRESH_TOKEN,
    }))
    .into_response()
}

fn oauth_error(error: &str) -> axum::response::Response {
    (
        axum::http::StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({ "error": error })),
    )
        .into_response()
}
