//! Direct QUIC listener: TLS from PEM files (typically the ACME cert nginx
//! already has) and ALPN pinned to the protocol identifier.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use herdr_eternal_proto as proto;
use rustls_pki_types::pem::PemObject;

use crate::ServerError;

/// Matches the WebSocket path's keepalive characteristics: dead peers are
/// noticed by the transport instead of application pings.
pub(crate) const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(45);

/// Where the UDP socket comes from: bound by us or inherited from systemd
/// socket activation (so the port stays open across restarts).
pub(crate) enum QuicSocket {
    Addr(SocketAddr),
    Inherited(std::net::UdpSocket),
}

pub(crate) fn listen(
    socket: QuicSocket,
    cert_pem: &Path,
    key_pem: &Path,
) -> Result<quinn::Endpoint, ServerError> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let certs = rustls_pki_types::CertificateDer::pem_file_iter(cert_pem)
        .map_err(std::io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(std::io::Error::other)?;
    let key =
        rustls_pki_types::PrivateKeyDer::from_pem_file(key_pem).map_err(std::io::Error::other)?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(std::io::Error::other)?;
    tls.alpn_protocols = vec![proto::PROTOCOL.as_bytes().to_vec()];

    let quic_tls =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(std::io::Error::other)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    transport.max_idle_timeout(Some(
        IDLE_TIMEOUT.try_into().map_err(std::io::Error::other)?,
    ));
    config.transport_config(Arc::new(transport));

    match socket {
        QuicSocket::Addr(addr) => Ok(quinn::Endpoint::server(config, addr)?),
        QuicSocket::Inherited(socket) => {
            socket.set_nonblocking(true)?;
            let runtime = quinn::default_runtime()
                .ok_or_else(|| std::io::Error::other("no async runtime for quinn"))?;
            Ok(quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(config),
                socket,
                runtime,
            )?)
        }
    }
}
