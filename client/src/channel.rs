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

pub(crate) enum Conn {
    Ws(Box<Ws>),
    Quic {
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        /// Holds partially received frames across cancelled `next()` calls.
        decoder: proto::FrameDecoder,
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
        // Keystroke-sized frames must not sit in Nagle's buffer.
        let stream = match ws.get_ref() {
            MaybeTlsStream::Plain(stream) => Some(stream),
            MaybeTlsStream::Rustls(tls) => Some(tls.get_ref().0),
            _ => None,
        };
        if let Some(stream) = stream {
            stream.set_nodelay(true).ok();
        }
        Ok(Conn::Ws(Box::new(ws)))
    }

    pub(crate) async fn send<T: serde::Serialize>(&mut self, msg: &T) -> Result<(), ClientError> {
        match self {
            Conn::Ws(ws) => ws
                .send(Message::Binary(proto::encode(msg)?))
                .await
                .map_err(Box::new)?,
            Conn::Quic { send, .. } => {
                send.write_all(&proto::encode_frame(msg)?)
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
    ///
    /// Cancel-safe: the exec loop polls this inside `tokio::select!`.
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
            Conn::Quic { recv, decoder, .. } => loop {
                match decoder.next_frame() {
                    Ok(Some(frame)) => return Ok(Event::Frame(frame)),
                    Ok(None) => {}
                    Err(_) => return Ok(Event::Disconnected),
                }
                match recv.read_chunk(64 * 1024, true).await {
                    Ok(Some(chunk)) => decoder.push(&chunk.bytes),
                    Ok(None) | Err(_) => return Ok(Event::Disconnected),
                }
            },
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
        decoder: proto::FrameDecoder::new(),
        _connection: connection,
        _endpoint: endpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-process QUIC pair: (client Conn, server-side send stream).
    async fn quic_pair() -> (Conn, quinn::SendStream) {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key = rustls_pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![cert_der.clone()], key.into()).unwrap();
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        let accept = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (send, _recv) = conn.accept_bi().await.unwrap();
            (server, conn, send)
        });
        let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut send, recv) = connection.open_bi().await.unwrap();
        // The peer only sees the stream once something was written on it.
        send.write_all(&proto::encode_frame(&proto::ChannelMessage::Ack { seq: 0 }).unwrap())
            .await
            .unwrap();
        let (server, server_conn, server_send) = accept.await.unwrap();
        // Keep the server side alive for the test's duration.
        std::mem::forget(server);
        std::mem::forget(server_conn);
        let conn = Conn::Quic {
            send,
            recv,
            decoder: proto::FrameDecoder::new(),
            _connection: connection,
            _endpoint: endpoint,
        };
        (conn, server_send)
    }

    /// Regression test: the exec loop polls `next()` inside `select!` next to
    /// stdin. On a WAN link frames straddle packets, so a pending read gets
    /// dropped half-way through a frame whenever stdin wins the race. That
    /// used to lose the bytes read so far and desync the stream (herdr:
    /// "reconnecting", or a fatal decode error).
    #[tokio::test]
    async fn quic_next_is_cancel_safe() {
        let (mut conn, mut server_send) = quic_pair().await;
        let message = proto::ChannelMessage::Stdout {
            seq: 7,
            data: b"split across reads".to_vec(),
        };
        let frame = proto::encode_frame(&message).unwrap();

        server_send.write_all(&frame[..10]).await.unwrap();
        // Let next() consume the first part, then cancel it mid-frame.
        let pending =
            tokio::time::timeout(std::time::Duration::from_millis(200), conn.next()).await;
        assert!(
            pending.is_err(),
            "next() returned before the frame was complete"
        );

        server_send.write_all(&frame[10..]).await.unwrap();
        match conn.next().await.unwrap() {
            Event::Frame(bytes) => {
                let decoded: proto::ChannelMessage = proto::decode(&bytes).unwrap();
                assert!(matches!(
                    decoded,
                    proto::ChannelMessage::Stdout { seq: 7, .. }
                ));
            }
            Event::Disconnected => panic!("stream desynced after a cancelled read"),
        }
    }
}
