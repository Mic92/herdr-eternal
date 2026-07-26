//! Client authentication: a pre-shared static token and/or OIDC bearer
//! tokens. OIDC validation is provider-generic: issuer discovery, JWKS
//! signature check, issuer/audience/expiry validation, and a single allowed
//! `sub` claim (single-user daemon).

use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::debug;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("token rejected")]
    Rejected,
    #[error("cannot fetch {url}: {source}")]
    Fetch {
        url: String,
        source: Box<reqwest::Error>,
    },
    #[error("invalid JWT: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("no JWKS key matches the token's key id")]
    UnknownKey,
    #[error("token subject {0:?} is not allowed")]
    SubNotAllowed(String),
    #[error("token has no subject")]
    MissingSub,
}

/// OIDC validation settings.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Issuer URL, e.g. `https://auth.example.com`.
    pub issuer: String,
    /// OAuth client id; must appear in the token's `aud` claim.
    pub client_id: String,
    /// Only this `sub` claim is accepted.
    pub allowed_sub: String,
}

/// Authentication policy for incoming connections.
pub struct Auth {
    static_token: Option<String>,
    oidc: Option<Oidc>,
}

impl Auth {
    pub fn new(static_token: Option<String>, oidc: Option<OidcConfig>) -> Self {
        Self {
            static_token,
            oidc: oidc.map(|config| Oidc {
                config,
                jwks: Mutex::new(None),
            }),
        }
    }

    pub fn static_token(token: String) -> Self {
        Self::new(Some(token), None)
    }

    /// Checks a token presented in Hello against the static token and, if
    /// configured, as an OIDC bearer token.
    pub async fn verify(&self, presented: &str) -> Result<(), AuthError> {
        if let Some(static_token) = &self.static_token {
            if constant_time_eq(static_token.as_bytes(), presented.as_bytes()) {
                return Ok(());
            }
        }
        let Some(oidc) = &self.oidc else {
            return Err(AuthError::Rejected);
        };
        oidc.verify(presented).await.inspect_err(|err| {
            debug!("bearer token rejected: {err}");
        })
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

struct Oidc {
    config: OidcConfig,
    /// Cached JWKS; refetched when a token references an unknown key id.
    jwks: Mutex<Option<jsonwebtoken::jwk::JwkSet>>,
}

#[derive(Deserialize)]
struct Discovery {
    jwks_uri: String,
}

#[derive(Deserialize)]
struct Claims {
    sub: Option<String>,
    /// Some providers (e.g. Authelia) omit `sub` for client_credentials
    /// grants and only set `client_id`.
    client_id: Option<String>,
}

impl Oidc {
    async fn verify(&self, token: &str) -> Result<(), AuthError> {
        let header = jsonwebtoken::decode_header(token)?;
        let key = self.decoding_key(header.kid.as_deref()).await?;

        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.client_id]);
        let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)?.claims;

        // The subject identifies the user; tokens from the client_credentials
        // grant may only carry client_id, which requires the client secret to
        // obtain and therefore also identifies a single principal.
        let subject = claims
            .sub
            .or(claims.client_id)
            .ok_or(AuthError::MissingSub)?;
        if subject != self.config.allowed_sub {
            return Err(AuthError::SubNotAllowed(subject));
        }
        Ok(())
    }

    async fn decoding_key(
        &self,
        kid: Option<&str>,
    ) -> Result<jsonwebtoken::DecodingKey, AuthError> {
        let mut jwks = self.jwks.lock().await;
        for fetch in [false, true] {
            if fetch || jwks.is_none() {
                *jwks = Some(self.fetch_jwks().await?);
            }
            let set = jwks.as_ref().expect("jwks fetched above");
            let jwk = match kid {
                Some(kid) => set.find(kid),
                None => set.keys.first(),
            };
            if let Some(jwk) = jwk {
                return Ok(jsonwebtoken::DecodingKey::from_jwk(jwk)?);
            }
        }
        Err(AuthError::UnknownKey)
    }

    async fn fetch_jwks(&self) -> Result<jsonwebtoken::jwk::JwkSet, AuthError> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let discovery: Discovery = get_json(&discovery_url).await?;
        get_json(&discovery.jwks_uri).await
    }
}

async fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, AuthError> {
    let map_err = |source| AuthError::Fetch {
        url: url.to_string(),
        source: Box::new(source),
    };
    reqwest::get(url)
        .await
        .and_then(|response| response.error_for_status())
        .map_err(map_err)?
        .json()
        .await
        .map_err(map_err)
}
