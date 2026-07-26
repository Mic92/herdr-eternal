//! Client transport: QUIC (direct, preferred when configured) with WebSocket
//! (behind nginx) as the fallback. Both carry the same postcard frames; on
//! QUIC each frame is length-prefixed on a single bidirectional stream.

use std::path::Path;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use herdr_eternal_proto as proto;
use rustls_pki_types::pem::PemObject;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::{ClientError, Target};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Upper bound for a single QUIC frame; stdio chunks are 16 KiB.
const MAX_FRAME: u32 = 1024 * 1024;

pub(crate) enum Conn {
    Ws(Box<Ws>),
    Quic {
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        /// Keep the connection and its endpoint (whose driver carries the
        /// connection's traffic) alive for as long as the channel is used.
        _connection: quinn::Connection,
        _endpoint: quinn::Endpoint,
    },
}

/// What the connection produced next, uniform across transports.
pub(crate) enum Event {
    Frame(Vec<u8>),
    /// The connection closed or failed; the resume loop decides what's next.
    Disconnected,
}

impl Conn {
    /// Connects to the target: QUIC when `quic_addr` is configured and
    /// reachable, otherwise the WebSocket URL.
    pub(crate) async fn connect(target: &Target) -> Result<Self, ClientError> {
        if let Some(addr) = &target.quic_addr {
            // Give the QUIC attempt only part of the connect budget so an
            // unreachable UDP path still leaves time for the fallback.
            let attempt =
                tokio::time::timeout(target.connect_timeout / 2, connect_quic(target, addr));
            match attempt.await.unwrap_or(Err(ClientError::ConnectTimeout)) {
                Ok(conn) => return Ok(conn),
                Err(err) => {
                    tracing::debug!(
                        "quic connect to {addr} failed, falling back to websocket: {err}"
                    );
                }
            }
        }
        let (ws, _) = tokio_tungstenite::connect_async(&target.url)
            .await
            .map_err(Box::new)?;
        Ok(Conn::Ws(Box::new(ws)))
    }

    pub(crate) async fn send<T: serde::Serialize>(&mut self, msg: &T) -> Result<(), ClientError> {
        let bytes = proto::encode(msg)?;
        match self {
            Conn::Ws(ws) => ws.send(Message::Binary(bytes)).await.map_err(Box::new)?,
            Conn::Quic { send, .. } => {
                send.write_all(&(bytes.len() as u32).to_be_bytes())
                    .await
                    .map_err(std::io::Error::other)?;
                send.write_all(&bytes)
                    .await
                    .map_err(std::io::Error::other)?;
            }
        }
        Ok(())
    }

    /// Receives one message during the handshake; a lost connection there is
    /// a hard error.
    pub(crate) async fn recv<T: serde::de::DeserializeOwned>(&mut self) -> Result<T, ClientError> {
        match self.next().await? {
            Event::Frame(bytes) => Ok(proto::decode(&bytes)?),
            Event::Disconnected => Err(ClientError::ConnectionClosed),
        }
    }

    /// Waits for the next protocol frame, skipping transport-internal
    /// messages (WebSocket ping/pong/text). Errors are protocol errors;
    /// transport failures surface as `Disconnected`.
    pub(crate) async fn next(&mut self) -> Result<Event, ClientError> {
        match self {
            Conn::Ws(ws) => loop {
                match ws.next().await {
                    Some(Ok(Message::Binary(bytes))) => return Ok(Event::Frame(bytes)),
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                        return Ok(Event::Disconnected);
                    }
                    Some(Ok(_)) => continue,
                }
            },
            Conn::Quic { recv, .. } => {
                let mut len = [0_u8; 4];
                if recv.read_exact(&mut len).await.is_err() {
                    return Ok(Event::Disconnected);
                }
                let len = u32::from_be_bytes(len);
                if len > MAX_FRAME {
                    return Ok(Event::Disconnected);
                }
                let mut bytes = vec![0; len as usize];
                if recv.read_exact(&mut bytes).await.is_err() {
                    return Ok(Event::Disconnected);
                }
                Ok(Event::Frame(bytes))
            }
        }
    }

    /// Whether the client has to probe liveness itself. QUIC connections
    /// carry their own keepalive and idle timeout.
    pub(crate) fn needs_ping(&self) -> bool {
        matches!(self, Conn::Ws(_))
    }

    /// Best-effort liveness probe; failures show up as a disconnect.
    pub(crate) async fn ping(&mut self) -> Result<(), ()> {
        match self {
            Conn::Ws(ws) => ws.send(Message::Ping(Vec::new())).await.map_err(|_| ()),
            Conn::Quic { .. } => Ok(()),
        }
    }
}

/// TLS roots for the QUIC path: the system store plus an optional extra CA
/// (self-signed setups, tests).
fn quic_roots(extra_ca: Option<&Path>) -> Result<rustls::RootCertStore, ClientError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        roots.add(cert).ok();
    }
    if let Some(path) = extra_ca {
        for cert in
            rustls_pki_types::CertificateDer::pem_file_iter(path).map_err(std::io::Error::other)?
        {
            roots
                .add(cert.map_err(std::io::Error::other)?)
                .map_err(std::io::Error::other)?;
        }
    }
    Ok(roots)
}

async fn connect_quic(target: &Target, addr: &str) -> Result<Conn, ClientError> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let (host, _port) = addr
        .rsplit_once(':')
        .ok_or_else(|| std::io::Error::other(format!("quic_addr {addr:?} is not host:port")))?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(quic_roots(target.quic_ca.as_deref())?)
        .with_no_client_auth();
    tls.alpn_protocols = vec![proto::PROTOCOL.as_bytes().to_vec()];

    let quic_tls =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(std::io::Error::other)?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(target.keepalive_interval));
    transport.max_idle_timeout(Some(
        target
            .keepalive_timeout
            .try_into()
            .map_err(std::io::Error::other)?,
    ));
    config.transport_config(Arc::new(transport));

    let remote = tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| std::io::Error::other(format!("cannot resolve {addr}")))?;
    let local: std::net::SocketAddr = if remote.is_ipv4() {
        "0.0.0.0:0".parse().expect("static address")
    } else {
        "[::]:0".parse().expect("static address")
    };
    let mut endpoint = quinn::Endpoint::client(local)?;
    endpoint.set_default_client_config(config);
    let connection = endpoint
        .connect(remote, host)
        .map_err(std::io::Error::other)?
        .await
        .map_err(std::io::Error::other)?;
    let (send, recv) = connection.open_bi().await.map_err(std::io::Error::other)?;
    Ok(Conn::Quic {
        send,
        recv,
        _connection: connection,
        _endpoint: endpoint,
    })
}
