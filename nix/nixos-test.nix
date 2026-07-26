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

      users.users.alice = {
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

      environment.systemPackages = [ package ];
    };

  testScript = ''
    machine.wait_for_unit("herdr-eternal-server.service")
    machine.wait_for_unit("nginx.service")
    machine.wait_for_open_port(80)

    machine.succeed(
        "mkdir -p /root/.config/herdr-eternal",
        "printf '[targets.testbox]\nurl = \"ws://localhost/herdr-eternal\"\ntoken = \"test-token\"\n' > /root/.config/herdr-eternal/config.toml",
    )

    output = machine.succeed("herdr-eternal-ssh -T testbox 'id -un; echo $SHELL' < /dev/null")
    assert output == "alice\n/run/current-system/sw/bin/bash\n", repr(output)

    # Exit codes must be propagated through nginx as well.
    machine.fail("herdr-eternal-ssh -T testbox 'exit 3' < /dev/null")
  '';
}
