{
  config,
  lib,
  ...
}:
let
  cfg = config.services.herdr-eternal-server;
in
{
  options.services.herdr-eternal-server = {
    enable = lib.mkEnableOption "herdr-eternal-server, roaming-friendly transport for herdr --remote";

    package = lib.mkOption {
      type = lib.types.package;
      description = "herdr-eternal package providing the server binary.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      description = ''
        User to run the server as. Exec channels run commands as this user
        through their shell, so this is the account you want herdr sessions
        to live under.
      '';
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:7433";
      description = "Address the WebSocket listener binds to. Keep it local and put nginx in front.";
    };

    tokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File containing the pre-shared token clients may present.
        Loaded via systemd credentials, so a sops-nix/agenix secret path works.
      '';
    };

    oidc = {
      issuer = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "https://auth.example.com";
        description = "OIDC issuer URL. Setting it enables bearer-token authentication.";
      };

      clientId = lib.mkOption {
        type = lib.types.str;
        default = "herdr-eternal";
        description = "OAuth client id expected in the token audience.";
      };

      allowedSub = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Only tokens with this sub claim are accepted (single-user daemon).";
      };
    };

    nginx = {
      enable = lib.mkEnableOption "an nginx location proxying WebSocket traffic to the server";

      hostName = lib.mkOption {
        type = lib.types.str;
        description = "nginx virtual host to attach the location to.";
      };

      location = lib.mkOption {
        type = lib.types.str;
        default = "/herdr-eternal";
        description = "Location under which the exec endpoint is exposed.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.tokenFile != null || cfg.oidc.issuer != null;
        message = "services.herdr-eternal-server needs tokenFile and/or oidc.issuer";
      }
      {
        assertion = (cfg.oidc.issuer == null) == (cfg.oidc.allowedSub == null);
        message = "services.herdr-eternal-server: set oidc.issuer and oidc.allowedSub together";
      }
    ];

    systemd.services.herdr-eternal-server = {
      description = "Roaming-friendly transport for herdr --remote";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        # Stable location for the forwarded SSH agent socket.
        RuntimeDirectory = "herdr-eternal-server";
        RuntimeDirectoryMode = "0700";
        ExecStart = lib.concatStringsSep " " (
          [
            (lib.getExe' cfg.package "herdr-eternal-server")
            "--listen ${cfg.listenAddress}"
          ]
          ++ lib.optional (cfg.tokenFile != null) "--token-file %d/token"
          ++ lib.optionals (cfg.oidc.issuer != null) [
            "--oidc-issuer ${cfg.oidc.issuer}"
            "--oidc-client-id ${cfg.oidc.clientId}"
            "--oidc-allowed-sub ${cfg.oidc.allowedSub}"
          ]
        );
        LoadCredential = lib.optional (cfg.tokenFile != null) "token:${cfg.tokenFile}";
        User = cfg.user;
        Restart = "on-failure";
        RestartSec = 2;
      };
    };

    services.nginx.virtualHosts.${cfg.nginx.hostName} = lib.mkIf cfg.nginx.enable {
      locations.${cfg.nginx.location} = {
        proxyPass = "http://${cfg.listenAddress}";
        proxyWebsockets = true;
        extraConfig = ''
          # Exec channels are long-lived; do not let nginx cut them.
          proxy_read_timeout 1h;
          proxy_send_timeout 1h;
          proxy_buffering off;
        '';
      };
    };
  };
}
