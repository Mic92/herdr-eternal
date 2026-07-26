//! WebSocket exec listener: accepts authenticated connections and runs
//! commands through the user's shell, relaying framed stdio (see PLAN.md).
//!
//! Every exec becomes a session that owns the child process and an outbound
//! message log. Connections only attach to sessions: a resumable session
//! survives a lost connection and a later `Resume { last_seq_seen }` replays
//! everything the client has not seen yet, byte-exactly.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use herdr_eternal_proto as proto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

mod auth;
pub use auth::{Auth, AuthError, OidcConfig};
#[cfg(feature = "test-util")]
pub mod test_oidc;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("websocket error: {0}")]
    WebSocket(#[from] Box<tokio_tungstenite::tungstenite::Error>),
    #[error("protocol error: {0}")]
    Protocol(#[from] proto::ProtocolError),
    #[error("client closed the connection during handshake")]
    HandshakeClosed,
    #[error("authentication failed: {0}")]
    Auth(#[from] AuthError),
    #[error("unknown resume token")]
    UnknownResumeToken,
    #[error("session ended without an exit code")]
    SessionAborted,
}

pub struct Server {
    listener: TcpListener,
    auth: Arc<Auth>,
    shell: String,
    sessions: SessionRegistry,
}

impl Server {
    pub async fn bind(addr: &str, auth: Auth, shell: String) -> Result<Self, ServerError> {
        let listener = TcpListener::bind(addr).await?;
        info!(addr = %listener.local_addr()?, "listening");
        Ok(Self {
            listener,
            auth: Arc::new(auth),
            shell,
            sessions: SessionRegistry::default(),
        })
    }

    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ServerError> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn run(self) -> Result<(), ServerError> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let auth = Arc::clone(&self.auth);
            let shell = self.shell.clone();
            let sessions = self.sessions.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_connection(stream, &auth, &shell, sessions).await {
                    warn!(%peer, "connection failed: {err}");
                }
            });
        }
    }
}

/// Outbound messages (Stdout/Stderr/Exit) of a session. Entry `i` carries
/// sequence number `i + 1`, so replay after `last_seq_seen` is an index.
#[derive(Default)]
struct OutboundLog {
    entries: Mutex<Vec<proto::ChannelMessage>>,
    latest: watch::Sender<u64>,
}

impl OutboundLog {
    fn push(&self, message: proto::ChannelMessage) {
        let mut entries = self.entries.lock().unwrap();
        entries.push(message);
        let seq = entries.len() as u64;
        drop(entries);
        self.latest.send_replace(seq);
    }

    fn after(&self, seq: u64) -> Vec<proto::ChannelMessage> {
        self.entries.lock().unwrap()[seq as usize..].to_vec()
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.latest.subscribe()
    }
}

enum SessionInput {
    Message(proto::ChannelMessage),
    /// The attached client went away and the session is not resumable.
    Abort,
}

struct Session {
    inbound: mpsc::UnboundedSender<SessionInput>,
    log: Arc<OutboundLog>,
    resumable: bool,
}

#[derive(Clone, Default)]
struct SessionRegistry(Arc<Mutex<HashMap<String, Arc<Session>>>>);

impl SessionRegistry {
    fn insert(&self, token: String, session: Arc<Session>) {
        self.0.lock().unwrap().insert(token, session);
    }

    fn get(&self, token: &str) -> Option<Arc<Session>> {
        self.0.lock().unwrap().get(token).cloned()
    }

    fn remove(&self, token: &str) {
        self.0.lock().unwrap().remove(token);
    }
}

fn new_resume_token() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    )
}

async fn handle_connection(
    stream: TcpStream,
    auth: &Auth,
    shell: &str,
    sessions: SessionRegistry,
) -> Result<(), ServerError> {
    let mut ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(Box::new)?;

    let hello: proto::Hello = recv(&mut ws).await?;
    if let Err(err) = auth.verify(&hello.token).await {
        ws.close(None).await.ok();
        return Err(err.into());
    }
    send(
        &mut ws,
        &proto::Welcome {
            user: std::env::var("USER").unwrap_or_default(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )
    .await?;

    let (session_token, session, last_seq_seen) = match recv(&mut ws).await? {
        proto::ExecRequest::Exec { command, resumable } => {
            debug!(%command, resumable, "exec");
            let session = start_session(shell, &command, resumable)?;
            let session_token = new_resume_token();
            sessions.insert(session_token.clone(), Arc::clone(&session));
            (session_token, session, 0)
        }
        proto::ExecRequest::Resume {
            resume_token,
            last_seq_seen,
        } => {
            debug!(%resume_token, last_seq_seen, "resume");
            let Some(session) = sessions.get(&resume_token) else {
                ws.close(None).await.ok();
                return Err(ServerError::UnknownResumeToken);
            };
            (resume_token, session, last_seq_seen)
        }
    };

    attach(ws, &sessions, &session_token, session, last_seq_seen).await
}

/// Spawns the child and the session task that owns it.
fn start_session(shell: &str, command: &str, resumable: bool) -> Result<Arc<Session>, ServerError> {
    let mut child = tokio::process::Command::new(shell)
        .arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let log = Arc::new(OutboundLog::default());
    let session = Arc::new(Session {
        inbound: inbound_tx,
        log: Arc::clone(&log),
        resumable,
    });

    // Kept in an Option so StdinEof can drop it: dropping closes the pipe and
    // is the only way the child sees EOF (AsyncWrite::shutdown does not).
    let child_stdin = child.stdin.take();
    tokio::spawn(session_task(child, child_stdin, inbound_rx, log));
    Ok(session)
}

/// Owns the child process: pumps its stdout/stderr into the outbound log and
/// applies deduplicated stdin from whichever connection is currently attached.
async fn session_task(
    mut child: tokio::process::Child,
    mut child_stdin: Option<tokio::process::ChildStdin>,
    mut inbound: mpsc::UnboundedReceiver<SessionInput>,
    log: Arc<OutboundLog>,
) {
    let mut child_stdout = child.stdout.take().expect("piped stdout");
    let mut child_stderr = child.stderr.take().expect("piped stderr");
    let mut stdout_buf = [0_u8; 16 * 1024];
    let mut stderr_buf = [0_u8; 16 * 1024];
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut exit_code = None;
    let mut seq: u64 = 0;
    // Highest client sequence number applied; duplicates from a resend after
    // resume are dropped here.
    let mut last_client_seq: u64 = 0;

    loop {
        tokio::select! {
            read = child_stdout.read(&mut stdout_buf), if stdout_open => {
                match read {
                    Ok(0) | Err(_) => stdout_open = false,
                    Ok(n) => {
                        seq += 1;
                        log.push(proto::ChannelMessage::Stdout { seq, data: stdout_buf[..n].to_vec() });
                    }
                }
            }
            read = child_stderr.read(&mut stderr_buf), if stderr_open => {
                match read {
                    Ok(0) | Err(_) => stderr_open = false,
                    Ok(n) => {
                        seq += 1;
                        log.push(proto::ChannelMessage::Stderr { seq, data: stderr_buf[..n].to_vec() });
                    }
                }
            }
            status = child.wait(), if exit_code.is_none() => {
                exit_code = Some(status.map(|s| s.code().unwrap_or(255)).unwrap_or(255));
            }
            input = inbound.recv() => {
                match input {
                    Some(SessionInput::Message(proto::ChannelMessage::Stdin { seq, data })) => {
                        if seq > last_client_seq {
                            last_client_seq = seq;
                            if let Some(stdin) = child_stdin.as_mut() {
                                if stdin.write_all(&data).await.is_err() || stdin.flush().await.is_err() {
                                    child_stdin = None;
                                }
                            }
                        }
                    }
                    Some(SessionInput::Message(proto::ChannelMessage::StdinEof { seq })) => {
                        if seq > last_client_seq {
                            last_client_seq = seq;
                            child_stdin = None;
                        }
                    }
                    Some(SessionInput::Message(other)) => {
                        debug!(?other, "ignoring unexpected channel message");
                    }
                    Some(SessionInput::Abort) => {
                        child.start_kill().ok();
                        return;
                    }
                    None => {
                        // All connections and the registry dropped the session.
                        child.start_kill().ok();
                        return;
                    }
                }
            }
        }

        if let Some(code) = exit_code {
            if !stdout_open && !stderr_open {
                seq += 1;
                log.push(proto::ChannelMessage::Exit { seq, code });
                return;
            }
        }
    }
}

/// Streams the session's outbound log to this connection (starting after
/// `sent_up_to`) and forwards its inbound messages to the session.
async fn attach(
    mut ws: WebSocketStream<TcpStream>,
    sessions: &SessionRegistry,
    session_token: &str,
    session: Arc<Session>,
    mut sent_up_to: u64,
) -> Result<(), ServerError> {
    send(
        &mut ws,
        &proto::ChannelMessage::Started {
            resume_token: session.resumable.then(|| session_token.to_string()),
        },
    )
    .await?;

    let mut latest = session.log.subscribe();
    loop {
        for message in session.log.after(sent_up_to) {
            let is_exit = matches!(message, proto::ChannelMessage::Exit { .. });
            send(&mut ws, &message).await?;
            sent_up_to += 1;
            if is_exit {
                sessions.remove(session_token);
                ws.close(None).await.ok();
                // Drain until the peer closes: dropping the socket with unread
                // client data sends a TCP RST, which can discard the Exit
                // frame before the client reads it.
                while let Some(message) = ws.next().await {
                    if message.is_err() {
                        break;
                    }
                }
                return Ok(());
            }
        }

        tokio::select! {
            changed = latest.changed() => {
                if changed.is_err() && session.log.after(sent_up_to).is_empty() {
                    // Session task ended without an Exit message.
                    sessions.remove(session_token);
                    ws.close(None).await.ok();
                    return Err(ServerError::SessionAborted);
                }
            }
            message = ws.next() => {
                match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        let message = proto::decode(&bytes)?;
                        session.inbound.send(SessionInput::Message(message)).ok();
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        if !session.resumable {
                            sessions.remove(session_token);
                            session.inbound.send(SessionInput::Abort).ok();
                        }
                        return Ok(());
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        if !session.resumable {
                            sessions.remove(session_token);
                            session.inbound.send(SessionInput::Abort).ok();
                        }
                        return Err(Box::new(err).into());
                    }
                }
            }
        }
    }
}

async fn send<T: serde::Serialize>(
    ws: &mut WebSocketStream<TcpStream>,
    msg: &T,
) -> Result<(), ServerError> {
    ws.send(Message::Binary(proto::encode(msg)?))
        .await
        .map_err(Box::new)?;
    Ok(())
}

async fn recv<T: serde::de::DeserializeOwned>(
    ws: &mut WebSocketStream<TcpStream>,
) -> Result<T, ServerError> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => return Ok(proto::decode(&bytes)?),
            Some(Ok(Message::Close(_))) | None => return Err(ServerError::HandshakeClosed),
            Some(Ok(_)) => continue,
            Some(Err(err)) => return Err(Box::new(err).into()),
        }
    }
}
