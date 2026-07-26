//! Fake OIDC issuer for integration tests (feature `test-util`): serves
//! discovery and JWKS documents over HTTP and mints RS256-signed tokens.

use std::net::SocketAddr;

use base64::Engine;
use rsa::traits::PublicKeyParts;

const KID: &str = "test-key";

pub struct FakeIssuer {
    addr: SocketAddr,
    encoding_key: jsonwebtoken::EncodingKey,
}

#[derive(serde::Serialize)]
struct Claims {
    iss: String,
    sub: String,
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
        let issuer = format!("http://{addr}");

        let discovery = serde_json::json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
        });
        let router = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(move || {
                    let discovery = discovery.clone();
                    async move { axum::Json(discovery) }
                }),
            )
            .route(
                "/jwks",
                axum::routing::get(move || {
                    let jwks = jwks.clone();
                    async move { axum::Json(jwks) }
                }),
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });

        Self { addr, encoding_key }
    }

    pub fn issuer_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Mints a signed token; `expires_in` may be negative to produce an
    /// already-expired token.
    pub fn token(&self, sub: &str, audience: &str, expires_in_secs: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let claims = Claims {
            iss: self.issuer_url(),
            sub: sub.to_string(),
            aud: audience.to_string(),
            exp: now.saturating_add_signed(expires_in_secs),
            iat: now,
        };
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(KID.to_string());
        jsonwebtoken::encode(&header, &claims, &self.encoding_key).expect("sign test token")
    }
}
