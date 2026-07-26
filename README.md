# herdr-eternal

Roaming-friendly transport for `herdr --remote`. OpenSSH connections die on
network changes, suspend, or flaky Wi-Fi and take the herdr remote session
down with them. herdr-eternal replaces ssh as herdr's transport with a
WebSocket channel that reconnects and resumes byte-exactly, so a netsplit is
invisible to herdr.

## Components

- `herdr-eternal-server` — daemon on the remote machine. Accepts
  authenticated WebSocket connections (put nginx/TLS in front) and runs exec
  channels through the user's shell. Sessions survive dropped connections.
- `herdr-eternal-ssh` — drop-in for the ssh invocation herdr makes. herdr
  points at it via the `remote.ssh_command` config option
  (`nix/patches/0001-remote-make-ssh-transport-program-configurable.patch`
  until it is upstream).
- `herdr-eternal-proto` — shared wire protocol (postcard-framed messages,
  sequence-numbered stdio, resume tokens).

## Server deployment (NixOS)

```nix
{
  imports = [ herdr-eternal.nixosModules.default ];

  services.herdr-eternal-server = {
    enable = true;
    user = "joerg";                       # exec channels run as this user
    tokenFile = config.sops.secrets.herdr-eternal-token.path;
    nginx = {
      enable = true;
      hostName = "example.com";           # existing TLS-terminating vhost
      location = "/herdr-eternal";
    };
  };
}
```

The server only listens on localhost; nginx terminates TLS and proxies the
WebSocket upgrade.

## Client configuration

`~/.config/herdr-eternal/config.toml`:

```toml
[targets.mybox]
url = "wss://example.com/herdr-eternal"
token = "..."
```

herdr config:

```toml
[remote]
ssh_command = "herdr-eternal-ssh"
manage_ssh_config = false
```

Then use `herdr --remote mybox` as usual; the target name is looked up in the
client config instead of ssh_config.

## Development

```console
$ nix develop
$ cargo test --workspace
$ nix flake check   # clippy, tests (incl. patched-herdr e2e), NixOS VM test
```

## Status / roadmap

- [x] Exec channels with framed stdio and exit codes
- [x] Byte-exact resume after connection loss (client retries for 60s)
- [x] End-to-end test driving a patched `herdr --remote`
- [x] NixOS module + nginx integration + VM test
- [ ] OIDC device-code login instead of pre-shared tokens
- [ ] Bounded replay buffers, session expiry, keepalives for silent drops
- [ ] Optional QUIC direct path (connection migration)
