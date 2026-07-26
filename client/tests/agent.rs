//! End-to-end SSH agent forwarding: a program on the server connects to the
//! forwarded SSH_AUTH_SOCK and its request is answered by the client's local
//! agent.

use herdr_eternal_server::{Auth, Server};
use herdr_eternal_ssh::{Target, run_exec};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// Minimal stand-in for ssh-agent: answers every request with a fixed prefix
/// followed by the request bytes.
async fn fake_agent(listener: UnixListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut request = [0_u8; 256];
            let Ok(n) = stream.read(&mut request).await else {
                return;
            };
            let mut response = b"agent-reply:".to_vec();
            response.extend_from_slice(&request[..n]);
            stream.write_all(&response).await.ok();
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_program_reaches_local_agent() {
    let server = Server::bind(
        "127.0.0.1:0",
        Auth::static_token("secret".into()),
        "/bin/sh".into(),
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());

    let agent_dir = tempfile::tempdir().unwrap();
    let agent_socket = agent_dir.path().join("agent.sock");
    tokio::spawn(fake_agent(UnixListener::bind(&agent_socket).unwrap()));

    let mut target = Target::new(format!("ws://{addr}"), "secret".into());
    target.agent_socket = Some(agent_socket);

    // The command prints the forwarded socket path and stays alive long
    // enough for the test to talk to it.
    let stdin: &[u8] = b"echo $SSH_AUTH_SOCK; sleep 2\n";
    let (stdout_writer, stdout_reader) = tokio::io::duplex(4096);
    let mut stderr = Vec::new();
    let exec = tokio::spawn(async move {
        run_exec(&target, "/bin/sh -s", stdin, stdout_writer, &mut stderr).await
    });

    let mut lines = BufReader::new(stdout_reader).lines();
    let forwarded_socket = lines.next_line().await.unwrap().unwrap();
    assert!(forwarded_socket.ends_with("agent.sock"));

    // Talk to the forwarded socket like ssh would; the reply must come from
    // the fake agent on the client side.
    let mut agent = UnixStream::connect(&forwarded_socket).await.unwrap();
    agent.write_all(b"sign-me").await.unwrap();
    let mut reply = [0_u8; 256];
    let n = agent.read(&mut reply).await.unwrap();
    assert_eq!(&reply[..n], b"agent-reply:sign-me");

    assert_eq!(exec.await.unwrap().unwrap(), 0);
}
