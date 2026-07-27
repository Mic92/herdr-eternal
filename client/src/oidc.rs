//! OIDC device-code login and token cache. Provider-generic: everything is
//! taken from the issuer's discovery document. Tokens are cached per target
//! under XDG state and refreshed with the refresh token when expired.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{ClientError, TargetConfig};

/// Access tokens are refreshed this long before their actual expiry.
const EXPIRY_MARGIN_SECS: u64 = 60;

#[derive(Debug, Deserialize)]
struct Discovery {
    device_authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    interval: Option<u64>,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
}

/// Cached tokens for one target, stored as JSON in the state directory.
#[derive(Debug, Serialize, Deserialize)]
struct CachedTokens {
    access_token: String,
    refresh_token: Option<String>,
    /// Unix timestamp after which the access token is considered expired.
    expires_at: u64,
}

struct OidcTarget<'a> {
    issuer: &'a str,
    client_id: &'a str,
}

fn oidc_target(target: &TargetConfig) -> Result<OidcTarget<'_>, ClientError> {
    match (&target.issuer, &target.client_id) {
        (Some(issuer), Some(client_id)) => Ok(OidcTarget { issuer, client_id }),
        _ => Err(ClientError::NoAuthConfigured),
    }
}

/// Runs the device-code flow and stores the resulting tokens for `name`.
pub async fn login(name: &str, target: &TargetConfig) -> Result<(), ClientError> {
    login_with_prompt(name, target, &mut std::io::stderr()).await
}

/// Like [`login`], but prompts on /dev/tty because stdio carries herdr's
/// protocol during an exec.
pub async fn login_on_tty(name: &str, target: &TargetConfig) -> Result<(), ClientError> {
    let mut tty = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|_| ClientError::NotLoggedIn(name.to_string()))?;
    login_with_prompt(name, target, &mut tty).await
}

async fn login_with_prompt(
    name: &str,
    target: &TargetConfig,
    prompt: &mut dyn std::io::Write,
) -> Result<(), ClientError> {
    let oidc = oidc_target(target)?;
    let discovery = discover(oidc.issuer).await?;
    let client = reqwest::Client::new();

    let device: DeviceAuthorization = token_request(
        &client,
        &discovery.device_authorization_endpoint,
        &[
            ("client_id", oidc.client_id),
            ("scope", "openid offline_access"),
        ],
    )
    .await?
    .map_err(|error| ClientError::Oidc(format!("device authorization failed: {error}")))?;

    match &device.verification_uri_complete {
        Some(url) => writeln!(prompt, "To authorize {name}, open: {url}")?,
        None => writeln!(
            prompt,
            "To authorize {name}, open {} and enter code {}",
            device.verification_uri, device.user_code
        )?,
    }

    let interval = std::time::Duration::from_secs(device.interval.unwrap_or(5));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(device.expires_in);
    let tokens = loop {
        let response: Result<TokenResponse, String> = token_request(
            &client,
            &discovery.token_endpoint,
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &device.device_code),
                ("client_id", oidc.client_id),
            ],
        )
        .await?;
        match response {
            Ok(tokens) => break tokens,
            Err(error) if error == "authorization_pending" || error == "slow_down" => {
                if std::time::Instant::now() > deadline {
                    return Err(ClientError::Oidc("device code expired".to_string()));
                }
                tokio::time::sleep(interval).await;
            }
            Err(error) => return Err(ClientError::Oidc(format!("login failed: {error}"))),
        }
    };

    store_tokens(name, &tokens)?;
    writeln!(prompt, "Logged in to {name}.")?;
    Ok(())
}

/// Returns a valid access token for `name`, refreshing it if necessary.
pub async fn access_token(name: &str, target: &TargetConfig) -> Result<String, ClientError> {
    let oidc = oidc_target(target)?;
    let cached = load_tokens(name)?.ok_or_else(|| ClientError::NotLoggedIn(name.to_string()))?;
    if now_unix() + EXPIRY_MARGIN_SECS < cached.expires_at {
        return Ok(cached.access_token);
    }

    let Some(refresh_token) = cached.refresh_token else {
        return Err(ClientError::NotLoggedIn(name.to_string()));
    };
    let discovery = discover(oidc.issuer).await?;
    let client = reqwest::Client::new();
    let tokens: TokenResponse = token_request(
        &client,
        &discovery.token_endpoint,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", oidc.client_id),
        ],
    )
    .await?
    .map_err(|_| ClientError::NotLoggedIn(name.to_string()))?;
    let access_token = tokens.access_token.clone();
    store_tokens(name, &tokens)?;
    Ok(access_token)
}

async fn discover(issuer: &str) -> Result<Discovery, ClientError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let map_err = |source: reqwest::Error| ClientError::Http {
        url: url.clone(),
        source: Box::new(source),
    };
    reqwest::get(&url)
        .await
        .and_then(|response| response.error_for_status())
        .map_err(map_err)?
        .json()
        .await
        .map_err(map_err)
}

/// Sends an OAuth form request; a 4xx response with an `error` field is
/// returned as `Ok(Err(error))` so callers can react to protocol errors like
/// authorization_pending.
async fn token_request<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    form: &[(&str, &str)],
) -> Result<Result<T, String>, ClientError> {
    let map_err = |source: reqwest::Error| ClientError::Http {
        url: url.to_string(),
        source: Box::new(source),
    };
    let response = client.post(url).form(form).send().await.map_err(map_err)?;
    if response.status().is_client_error() {
        let error: TokenErrorResponse = response.json().await.map_err(map_err)?;
        return Ok(Err(error.error));
    }
    let response = response.error_for_status().map_err(map_err)?;
    Ok(Ok(response.json().await.map_err(map_err)?))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn token_cache_path(name: &str) -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
                .join(".local")
                .join("state")
        });
    base.join("herdr-eternal")
        .join("tokens")
        .join(format!("{name}.json"))
}

fn store_tokens(name: &str, tokens: &TokenResponse) -> Result<(), ClientError> {
    let cached = CachedTokens {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        expires_at: now_unix() + tokens.expires_in,
    };
    let path = token_cache_path(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let contents = serde_json::to_vec_pretty(&cached).expect("serialize token cache");
    // Tokens are secrets: create the file with owner-only permissions.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&contents)?;
    Ok(())
}

fn load_tokens(name: &str) -> Result<Option<CachedTokens>, ClientError> {
    let path = token_cache_path(name);
    let contents = match std::fs::read(&path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    Ok(serde_json::from_slice(&contents).ok())
}
