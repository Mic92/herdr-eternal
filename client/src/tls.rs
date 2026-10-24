//! TLS client configuration shared by QUIC, WebSocket and OIDC requests.

use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use rustls_pki_types::pem::PemObject;

use crate::ClientError;

/// System trust anchors, parsed once per process. On NixOS
/// `load_native_certs` reads the same bundle three times via the probed
/// cert directories; the bundle file alone holds every root.
fn native_roots() -> &'static rustls::RootCertStore {
    static ROOTS: OnceLock<rustls::RootCertStore> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let explicit = ["SSL_CERT_FILE", "SSL_CERT_DIR"]
            .iter()
            .any(|var| std::env::var_os(var).is_some());
        let probed = openssl_probe::probe();
        let certs = match probed.cert_file {
            Some(file) if !explicit => {
                rustls_native_certs::load_certs_from_paths(Some(&file), None).certs
            }
            _ => rustls_native_certs::load_native_certs().certs,
        };
        let mut seen = HashSet::new();
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            if seen.insert(cert.to_vec()) {
                roots.add(cert).ok();
            }
        }
        roots
    })
}

/// Client config trusting the system roots plus an optional extra CA
/// (self-signed setups, tests).
pub(crate) fn client_config(extra_ca: Option<&Path>) -> Result<rustls::ClientConfig, ClientError> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let mut roots = native_roots().clone();
    if let Some(path) = extra_ca {
        for cert in
            rustls_pki_types::CertificateDer::pem_file_iter(path).map_err(std::io::Error::other)?
        {
            roots
                .add(cert.map_err(std::io::Error::other)?)
                .map_err(std::io::Error::other)?;
        }
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

pub(crate) fn http_client() -> Result<reqwest::Client, ClientError> {
    Ok(reqwest::Client::builder()
        .use_preconfigured_tls(client_config(None)?)
        .build()
        .map_err(std::io::Error::other)?)
}
