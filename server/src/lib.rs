//! WebSocket exec listener: accepts authenticated connections and runs
//! commands through the user's shell, relaying framed stdio (see PLAN.md).
//!
//! Every exec becomes a session that owns the child process and an outbound
//! message log. Connections only attach to sessions: a resumable session
//! survives a lost connection and a later `Resume { last_seq_seen }` replays
//! everything the client has not seen yet, byte-exactly.

use std::collections::{HashMap, VecDeque};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use herdr_eternal_proto as proto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

mod agent;
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
    #[error("agent forwarding was not requested for this session")]
    AgentNotEnabled,
    #[error("session ended without an exit code")]
    SessionAborted,
}

/// How long a resumable session may stay disconnected before it is killed.
/// Long enough that a suspended laptop can come back days later; bounded so
/// a client that crashed for good does not leak a child process forever.
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

pub struct Server {
    listener: TcpListener,
    auth: Arc<Auth>,
    shell: String,
    sessions: SessionRegistry,
    session_timeout: Duration,
    agent: agent::SharedAgentHub,
    /// Extra variables applied on top of the sshd-like session environment;
    /// tests use this to confine sessions to a scratch HOME.
    session_env: Arc<Vec<(String, String)>>,
}

impl Server {
    pub async fn bind(addr: &str, auth: Auth, shell: String) -> Result<Self, ServerError> {
        let listener = TcpListener::bind(addr).await?;
        Self::with_listener(listener, auth, shell)
    }

    /// Serves on an already-bound listener, e.g. one passed in through
    /// systemd socket activation.
    pub fn from_std_listener(
        listener: std::net::TcpListener,
        auth: Auth,
        shell: String,
    ) -> Result<Self, ServerError> {
        listener.set_nonblocking(true)?;
        Self::with_listener(TcpListener::from_std(listener)?, auth, shell)
    }

    fn with_listener(
        listener: TcpListener,
        auth: Auth,
        shell: String,
    ) -> Result<Self, ServerError> {
        info!(addr = %listener.local_addr()?, "listening");
        Ok(Self {
            listener,
            auth: Arc::new(auth),
            shell,
            sessions: SessionRegistry::default(),
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            agent: agent::SharedAgentHub::default(),
            session_env: Arc::default(),
        })
    }

    pub fn set_session_timeout(&mut self, timeout: Duration) {
        self.session_timeout = timeout;
    }

    /// Overrides environment variables of spawned sessions (on top of the
    /// sshd-like defaults). Intended for tests that must confine sessions to
    /// a scratch HOME.
    pub fn set_session_env(&mut self, env: Vec<(String, String)>) {
        self.session_env = Arc::new(env);
    }

    /// Puts the forwarded agent socket at a stable path in `dir` (instead of
    /// a per-server temporary directory), so long-lived programs inside
    /// sessions keep a working `SSH_AUTH_SOCK` across daemon restarts.
    pub fn set_agent_runtime_dir(&mut self, dir: std::path::PathBuf) {
        self.agent = agent::SharedAgentHub::new(Some(dir));
    }

    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ServerError> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn run(self) -> Result<(), ServerError> {
        tokio::spawn(expire_sessions(self.sessions.clone(), self.session_timeout));
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let auth = Arc::clone(&self.auth);
            let shell = self.shell.clone();
            let sessions = self.sessions.clone();
            let agent = self.agent.clone();
            let session_env = Arc::clone(&self.session_env);
            tokio::spawn(async move {
                if let Err(err) =
                    handle_connection(stream, &auth, &shell, sessions, agent, &session_env).await
                {
                    warn!(%peer, "connection failed: {err}");
                }
            });
        }
    }
}

/// Outbound messages (Stdout/Stderr/Exit) of a session, kept for replay after
/// a resume. The entry at buffer index `i` carries sequence number
/// `trimmed + i + 1`; entries the client acknowledged are dropped.
#[derive(Default)]
struct OutboundLog {
    entries: Mutex<LogEntries>,
    latest: watch::Sender<u64>,
}

#[derive(Default)]
struct LogEntries {
    buffer: VecDeque<proto::ChannelMessage>,
    /// Number of leading entries dropped after the client acknowledged them.
    trimmed: u64,
}

impl OutboundLog {
    fn push(&self, message: proto::ChannelMessage) {
        let mut entries = self.entries.lock().unwrap();
        entries.buffer.push_back(message);
        let seq = entries.trimmed + entries.buffer.len() as u64;
        drop(entries);
        self.latest.send_replace(seq);
    }

    fn after(&self, seq: u64) -> Vec<proto::ChannelMessage> {
        let entries = self.entries.lock().unwrap();
        let skip = seq.saturating_sub(entries.trimmed) as usize;
        entries.buffer.iter().skip(skip).cloned().collect()
    }

    /// Drops entries up to and including `seq`; the client persisted them.
    fn trim(&self, seq: u64) {
        let mut entries = self.entries.lock().unwrap();
        while entries.trimmed < seq && !entries.buffer.is_empty() {
            entries.buffer.pop_front();
            entries.trimmed += 1;
        }
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
    /// Highest stdin sequence number the session task has applied; reported
    /// back to the client so it can trim its resend buffer.
    stdin_applied: Arc<AtomicU64>,
    /// Present when the client asked for agent forwarding.
    agent: Option<Arc<agent::AgentHub>>,
    /// Number of currently attached connections (a lingering blackholed
    /// connection can overlap with its own resume).
    attached: AtomicUsize,
    /// When the last connection detached; `None` while a client is attached.
    /// Drives the disconnected-session timeout.
    detached_at: Mutex<Option<tokio::time::Instant>>,
    resumable: bool,
}

/// Marks the session as attached for its lifetime and records the detach
/// time when the last connection goes away, whichever way `attach` returns.
struct AttachGuard(Arc<Session>);

impl AttachGuard {
    fn new(session: Arc<Session>) -> Self {
        session.attached.fetch_add(1, Ordering::SeqCst);
        *session.detached_at.lock().unwrap() = None;
        Self(session)
    }
}

impl Drop for AttachGuard {
    fn drop(&mut self) {
        if self.0.attached.fetch_sub(1, Ordering::SeqCst) == 1 {
            *self.0.detached_at.lock().unwrap() = Some(tokio::time::Instant::now());
        }
    }
}

/// Kills sessions whose client has been gone longer than `timeout`.
async fn expire_sessions(sessions: SessionRegistry, timeout: Duration) {
    let mut sweep = tokio::time::interval((timeout / 10).max(Duration::from_millis(10)));
    loop {
        sweep.tick().await;
        for (token, session) in sessions.expired(timeout) {
            info!(%token, "expiring disconnected session");
            sessions.remove(&token);
            session.inbound.send(SessionInput::Abort).ok();
        }
    }
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

    /// Sessions that have had no attached connection for longer than `timeout`.
    fn expired(&self, timeout: Duration) -> Vec<(String, Arc<Session>)> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, session)| {
                session
                    .detached_at
                    .lock()
                    .unwrap()
                    .is_some_and(|detached| detached.elapsed() >= timeout)
            })
            .map(|(token, session)| (token.clone(), Arc::clone(session)))
            .collect()
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
    agent: agent::SharedAgentHub,
    session_env: &[(String, String)],
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
        proto::ExecRequest::Exec {
            command,
            resumable,
            forward_agent,
        } => {
            debug!(%command, resumable, forward_agent, "exec");
            let agent = forward_agent.then(|| agent.get_or_start()).transpose()?;
            let session = start_session(shell, &command, resumable, agent, session_env)?;
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
        proto::ExecRequest::AgentChannel { resume_token } => {
            debug!(%resume_token, "agent channel");
            let Some(session) = sessions.get(&resume_token) else {
                ws.close(None).await.ok();
                return Err(ServerError::UnknownResumeToken);
            };
            let Some(hub) = session.agent.clone() else {
                ws.close(None).await.ok();
                return Err(ServerError::AgentNotEnabled);
            };
            // Keep the session attached while its agent channel is, so it is
            // not expired away underneath a purely idle (but connected) client.
            let _attached = AttachGuard::new(session);
            return agent::handle_agent_channel(ws, hub).await;
        }
    };

    attach(ws, &sessions, &session_token, session, last_seq_seen).await
}

/// Gives the command a login-like environment, the way sshd does: identity
/// and shell from the passwd database, PATH and locale carried over, and
/// nothing else, so daemon internals (systemd variables, credentials paths)
/// do not leak into sessions. Everything further comes from the shell's own
/// startup files.
fn session_environment(cmd: &mut tokio::process::Command, shell: &str) {
    cmd.env_clear();
    cmd.env("SHELL", shell);
    cmd.env(
        "PATH",
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string()),
    );
    if let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::getuid()) {
        cmd.env("USER", &user.name);
        cmd.env("LOGNAME", &user.name);
        cmd.env("HOME", &user.dir);
    }
    for (key, value) in std::env::vars() {
        if key == "LANG" || key == "TZ" || key.starts_with("LC_") {
            cmd.env(key, value);
        }
    }
}

/// Spawns the child and the session task that owns it.
fn start_session(
    shell: &str,
    command: &str,
    resumable: bool,
    agent: Option<Arc<agent::AgentHub>>,
    session_env: &[(String, String)],
) -> Result<Arc<Session>, ServerError> {
    let mut cmd = tokio::process::Command::new(shell);
    cmd.arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    session_environment(&mut cmd, shell);
    cmd.envs(session_env.iter().map(|(key, value)| (key, value)));
    if let Some(agent) = &agent {
        cmd.env("SSH_AUTH_SOCK", agent.socket_path());
    }
    let mut child = cmd.spawn()?;

    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let log = Arc::new(OutboundLog::default());
    let stdin_applied = Arc::new(AtomicU64::new(0));
    let session = Arc::new(Session {
        inbound: inbound_tx,
        log: Arc::clone(&log),
        stdin_applied: Arc::clone(&stdin_applied),
        agent,
        attached: AtomicUsize::new(0),
        detached_at: Mutex::new(Some(tokio::time::Instant::now())),
        resumable,
    });

    // Kept in an Option so StdinEof can drop it: dropping closes the pipe and
    // is the only way the child sees EOF (AsyncWrite::shutdown does not).
    let child_stdin = child.stdin.take();
    tokio::spawn(session_task(
        child,
        child_stdin,
        inbound_rx,
        log,
        stdin_applied,
    ));
    Ok(session)
}

/// Owns the child process: pumps its stdout/stderr into the outbound log and
/// applies deduplicated stdin from whichever connection is currently attached.
async fn session_task(
    mut child: tokio::process::Child,
    mut child_stdin: Option<tokio::process::ChildStdin>,
    mut inbound: mpsc::UnboundedReceiver<SessionInput>,
    log: Arc<OutboundLog>,
    stdin_applied: Arc<AtomicU64>,
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
                            stdin_applied.store(last_client_seq, Ordering::Relaxed);
                        }
                    }
                    Some(SessionInput::Message(proto::ChannelMessage::StdinEof { seq })) => {
                        if seq > last_client_seq {
                            last_client_seq = seq;
                            child_stdin = None;
                            stdin_applied.store(last_client_seq, Ordering::Relaxed);
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
    let _attached = AttachGuard::new(Arc::clone(&session));
    send(
        &mut ws,
        &proto::ChannelMessage::Started {
            resume_token: session.resumable.then(|| session_token.to_string()),
        },
    )
    .await?;

    // Detects clients that vanished without closing the connection (NAT
    // timeout, suspend): ping regularly and give up when nothing comes back.
    const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
    const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(45);
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_activity = tokio::time::Instant::now();
    // Last stdin ack sent to the client; only resent when it advances.
    let mut acked_stdin: u64 = 0;
    // Sequence number of the Exit message once it went out on this
    // connection. The session is only removed when the client acknowledges
    // it; a blackholed connection may lose the Exit and needs to resume.
    let mut exit_seq: Option<u64> = None;

    let mut latest = session.log.subscribe();
    loop {
        for message in session.log.after(sent_up_to) {
            if let proto::ChannelMessage::Exit { seq, .. } = message {
                exit_seq = Some(seq);
            }
            send(&mut ws, &message).await?;
            sent_up_to += 1;
        }

        let stdin_applied = session.stdin_applied.load(Ordering::Relaxed);
        if stdin_applied > acked_stdin {
            acked_stdin = stdin_applied;
            send(&mut ws, &proto::ChannelMessage::Ack { seq: acked_stdin }).await?;
        }

        tokio::select! {
            _ = keepalive.tick() => {
                if last_activity.elapsed() >= KEEPALIVE_TIMEOUT {
                    if !session.resumable {
                        sessions.remove(session_token);
                        session.inbound.send(SessionInput::Abort).ok();
                    }
                    return Ok(());
                }
                ws.send(Message::Ping(Vec::new())).await.map_err(Box::new)?;
            }
            changed = latest.changed(), if exit_seq.is_none() => {
                if changed.is_err() && session.log.after(sent_up_to).is_empty() {
                    // Session task ended without an Exit message.
                    sessions.remove(session_token);
                    ws.close(None).await.ok();
                    return Err(ServerError::SessionAborted);
                }
            }
            message = ws.next() => {
                last_activity = tokio::time::Instant::now();
                match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        match proto::decode(&bytes)? {
                            proto::ChannelMessage::Ack { seq } => {
                                session.log.trim(seq);
                                if exit_seq.is_some_and(|exit| seq >= exit) {
                                    // Exit delivered; the session is complete.
                                    sessions.remove(session_token);
                                    ws.close(None).await.ok();
                                    return Ok(());
                                }
                            }
                            message => {
                                session.inbound.send(SessionInput::Message(message)).ok();
                            }
                        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_log_replays_after_trim() {
        let log = OutboundLog::default();
        for seq in 1..=3 {
            log.push(proto::ChannelMessage::Stdout {
                seq,
                data: vec![seq as u8],
            });
        }

        // The client acknowledged seq 2: those entries are dropped, and any
        // replay can only return what is still buffered (seq 3).
        log.trim(2);
        for last_seen in [0, 2] {
            let replay = log.after(last_seen);
            assert_eq!(replay.len(), 1);
            assert!(matches!(
                replay[0],
                proto::ChannelMessage::Stdout { seq: 3, .. }
            ));
        }
        assert!(log.after(3).is_empty());
    }
}
