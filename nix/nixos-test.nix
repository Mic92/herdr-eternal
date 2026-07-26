# End-to-end NixOS test: server behind nginx (WebSocket proxying), client
# exec through the proxy as a regular user.
{
  pkgs,
  nixosModule,
  package,
}:
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
        nginx = {
          enable = true;
          hostName = "localhost";
        };
      };

      services.nginx.enable = true;

      # Target for real ssh authentication through the forwarded agent.
      services.openssh.enable = true;

      environment.systemPackages = [ package ];
    };

  testScript = ''
    machine.wait_for_unit("herdr-eternal-server.service")
    machine.wait_for_unit("nginx.service")
    machine.wait_for_open_port(80)

    machine.succeed(
        "mkdir -p /root/.config/herdr-eternal",
        "printf '[targets.testbox]\nurl = \"ws://localhost/herdr-eternal\"\ntoken = \"test-token\"\nforward_agent = true\n' > /root/.config/herdr-eternal/config.toml",
    )

    output = machine.succeed("herdr-eternal-ssh -T testbox 'id -un; echo $SHELL' < /dev/null")
    user, shell = output.splitlines()
    assert user == "alice" and shell.endswith("/bin/zsh"), repr(output)

    # Exit codes must be propagated through nginx as well.
    machine.fail("herdr-eternal-ssh -T testbox 'exit 3' < /dev/null")

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
