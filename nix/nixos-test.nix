# End-to-end NixOS test: server behind nginx (WebSocket proxying), client
# exec through the proxy as a regular user.
{
  pkgs,
  nixosModule,
  package,
}:
let
  # Self-signed cert for the QUIC listener; only used inside the test VM.
  quicCert = pkgs.runCommand "herdr-eternal-test-cert" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p $out
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 36500 \
      -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
      -addext basicConstraints=critical,CA:FALSE \
      -keyout $out/key.pem -out $out/cert.pem
  '';
in
pkgs.testers.runNixOSTest {
  name = "herdr-eternal-server";

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ nixosModule ];

      # Not the default shell: exec commands and $SHELL must use the login
      # shell from the passwd database, like sshd.
      programs.zsh.enable = true;
      users.users.alice = {
        shell = pkgs.zsh;
        isNormalUser = true;
      };

      services.herdr-eternal-server = {
        enable = true;
        user = "alice";
        tokenFile = pkgs.writeText "herdr-eternal-token" "test-token";
        quic = {
          enable = true;
          certFile = "${quicCert}/cert.pem";
          keyFile = "${quicCert}/key.pem";
        };
        nginx = {
          enable = true;
          hostName = "localhost";
        };
      };

      services.nginx.enable = true;

      # Target for real ssh authentication through the forwarded agent.
      services.openssh.enable = true;

      environment.systemPackages = [
        package
        pkgs.curl
      ];
    };

  testScript = ''
    machine.wait_for_unit("herdr-eternal-server.service")
    machine.wait_for_unit("nginx.service")
    machine.wait_for_open_port(80)

    machine.succeed(
        "mkdir -p /root/.config/herdr-eternal",
        "printf '[targets.testbox]\nurl = \"ws://localhost/herdr-eternal\"\ntoken = \"test-token\"\nforward_agent = true\n"
        "[targets.testbox-quic]\nurl = \"ws://127.0.0.1:1\"\nquic_addr = \"127.0.0.1:7443\"\nquic_ca = \"${quicCert}/cert.pem\"\ntoken = \"test-token\"\n' "
        "> /root/.config/herdr-eternal/config.toml",
    )

    # Sessions get a login-like environment: identity from passwd, a working
    # PATH, and no systemd internals from the daemon.
    output = machine.succeed(
        "herdr-eternal-ssh -T testbox "
        "'id -un; echo $SHELL; echo $USER; echo $LOGNAME; echo $HOME; "
        "curl --version > /dev/null && echo curl-ok; echo systemd=$RUNTIME_DIRECTORY$LISTEN_FDS$INVOCATION_ID' < /dev/null"
    )
    lines = output.splitlines()
    assert lines[0] == "alice" and lines[1].endswith("/bin/zsh"), repr(output)
    assert lines[2:] == ["alice", "alice", "/home/alice", "curl-ok", "systemd="], repr(output)

    # Exit codes must be propagated through nginx as well.
    machine.fail("herdr-eternal-ssh -T testbox 'exit 3' < /dev/null")

    # The direct QUIC path: the target's WebSocket URL points nowhere, so
    # only the QUIC listener can have answered.
    output = machine.succeed("herdr-eternal-ssh -T testbox-quic 'echo over-quic' < /dev/null")
    assert output == "over-quic\n", repr(output)

    # A restart mid-session must lose neither output nor the exit code
    # (handover through the systemd fd store).
    machine.succeed(
        "cat > /root/restart-client.sh <<'EOF'\n"
        "${package}/bin/herdr-eternal-ssh -T testbox 'echo before; sleep 5; echo after; exit 5' </dev/null > /root/restart-out\n"
        "echo rc=$? >> /root/restart-out\n"
        "EOF",
        "systemd-run --unit=restart-client --setenv=HOME=/root sh /root/restart-client.sh",
    )
    machine.wait_until_succeeds("grep -q before /root/restart-out", timeout=30)
    old_pid = machine.succeed("systemctl show -p MainPID --value herdr-eternal-server").strip()
    machine.succeed("systemctl restart herdr-eternal-server")
    new_pid = machine.succeed("systemctl show -p MainPID --value herdr-eternal-server").strip()
    assert old_pid != new_pid, f"daemon did not restart: {old_pid} vs {new_pid}"
    machine.wait_until_succeeds("grep -q rc= /root/restart-out", timeout=60)
    restart_out = machine.succeed("cat /root/restart-out")
    assert restart_out == "before\nafter\nrc=5\n", repr(restart_out)
    machine.succeed("journalctl -u herdr-eternal-server | grep -q 'restored handed-over session'")

    # Real ssh must be able to authenticate via the forwarded agent: the key
    # only exists in root's local agent, the session runs as alice.
    machine.succeed(
        "ssh-keygen -t ed25519 -N \"\" -f /root/agent-key",
        "install -d -m 700 -o alice -g users /home/alice/.ssh",
        "install -m 600 -o alice -g users /root/agent-key.pub /home/alice/.ssh/authorized_keys",
        "rm /root/agent-key.pub",
    )
    output = machine.succeed(
        "ssh-agent sh -c 'ssh-add /root/agent-key && rm /root/agent-key && "
        "herdr-eternal-ssh -T testbox \"ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes alice@localhost id -un\"' < /dev/null"
    )
    assert output.splitlines()[-1] == "alice", repr(output)
  '';
}
