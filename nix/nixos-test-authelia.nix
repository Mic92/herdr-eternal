# Compatibility test against a real OIDC provider: Authelia issues a
# JWT-profile access token via the client_credentials grant and the server
# must accept it (discovery, JWKS, issuer/audience/sub validation) while
# rejecting garbage. TLS is terminated by nginx with a test CA that is added
# to the system trust store.
{
  pkgs,
  nixosModule,
  package,
}:
let
  clientId = "herdr-eternal";
  clientSecret = "test-client-secret";
  # authelia crypto hash generate pbkdf2 --password test-client-secret
  clientSecretDigest = "$pbkdf2-sha512$310000$hwJospoe8gmzKACXrnAwVA$j/xIArpdNflxwWz2Qdyvu3p7GTQUNV4APVB1FrR6Yw7syB5CCUcdOfoL/9lg2LYVsT.GE2KkrGWbngH24JJK/g";

  certs = pkgs.runCommand "herdr-eternal-test-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p $out
    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
      -keyout $out/ca.key -out $out/ca.crt -subj '/CN=herdr-eternal test CA'
    openssl req -newkey rsa:2048 -nodes -keyout $out/server.key -out server.csr \
      -subj '/CN=auth.example.com' -addext 'subjectAltName=DNS:auth.example.com'
    openssl x509 -req -in server.csr -CA $out/ca.crt -CAkey $out/ca.key \
      -CAcreateserial -days 3650 -copy_extensions copy -out $out/server.crt
    # Authelia's OIDC issuer signing key.
    openssl genrsa -out $out/oidc-issuer.pem 2048
  '';
in
pkgs.testers.runNixOSTest {
  name = "herdr-eternal-server-authelia";

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ nixosModule ];

      networking.hosts."127.0.0.1" = [ "auth.example.com" ];
      security.pki.certificateFiles = [ "${certs}/ca.crt" ];

      users.users.alice.isNormalUser = true;

      services.herdr-eternal-server = {
        enable = true;
        user = "alice";
        oidc = {
          issuer = "https://auth.example.com";
          inherit clientId;
          # RFC 9068: client_credentials tokens carry the client id as sub.
          allowedSub = clientId;
        };
        nginx = {
          enable = true;
          hostName = "localhost";
        };
      };

      services.nginx = {
        enable = true;
        # Authelia needs X-Forwarded-Proto to determine the effective issuer.
        recommendedProxySettings = true;
        virtualHosts."auth.example.com" = {
          onlySSL = true;
          sslCertificate = "${certs}/server.crt";
          sslCertificateKey = "${certs}/server.key";
          locations."/".proxyPass = "http://127.0.0.1:9091";
        };
      };

      services.authelia.instances.main = {
        enable = true;
        secrets = {
          storageEncryptionKeyFile = "${pkgs.writeText "storage-key" "an_insecure_test_only_storage_encryption_key_1234"}";
          jwtSecretFile = "${pkgs.writeText "jwt-secret" "an_insecure_test_only_jwt_secret_123456789012345678"}";
          sessionSecretFile = "${pkgs.writeText "session-secret" "an_insecure_test_only_session_secret_1234567890123"}";
          oidcHmacSecretFile = "${pkgs.writeText "hmac-secret" "an_insecure_test_only_oidc_hmac_secret_123456789012345678901234"}";
          oidcIssuerPrivateKeyFile = "${certs}/oidc-issuer.pem";
        };
        settings = {
          # An authentication backend is mandatory even though the
          # client_credentials grant never authenticates a user.
          authentication_backend.file.path = pkgs.writeText "users.yml" ''
            users:
              alice:
                disabled: false
                displayname: alice
                # password of password
                password: $argon2id$v=19$m=65536,t=3,p=4$2ohUAfh9yetl+utr4tLcCQ$AsXx0VlwjvNnCsa70u4HKZvFkC8Gwajr2pHGKcND/xs
                email: alice@example.com
                groups: [ admin ]
          '';
          access_control.default_policy = "one_factor";
          session.cookies = [
            {
              domain = "example.com";
              authelia_url = "https://auth.example.com";
            }
          ];
          storage.local.path = "/var/lib/authelia-main/db.sqlite3";
          notifier.filesystem.filename = "/var/lib/authelia-main/notifications.txt";
          identity_providers.oidc.clients = [
            {
              client_id = clientId;
              client_secret = clientSecretDigest;
              grant_types = [ "client_credentials" ];
              scopes = [ "herdr" ];
              audience = [ clientId ];
              # JWT-profile access tokens so the server can validate offline.
              access_token_signed_response_alg = "RS256";
              token_endpoint_auth_method = "client_secret_post";
            }
          ];
        };
      };

      environment.systemPackages = [
        package
        pkgs.jq
      ];
    };

  testScript = ''
    machine.wait_for_unit("authelia-main.service")
    machine.wait_for_unit("herdr-eternal-server.service")
    machine.wait_for_unit("nginx.service")
    # The unit reports active before the listener is up.
    machine.wait_for_open_port(9091)
    machine.wait_for_open_port(443)
    machine.wait_for_open_port(80)

    token = machine.succeed(
        "curl -sf https://auth.example.com/api/oidc/token"
        " -d grant_type=client_credentials"
        " -d client_id=${clientId}"
        " -d client_secret=${clientSecret}"
        " -d scope=herdr"
        " -d audience=${clientId}"
        " | jq -re .access_token"
    ).strip()
    # Authelia omits sub on client_credentials tokens; the server falls back
    # to client_id, so make sure this test keeps exercising that path.
    claims = machine.succeed(f"echo '{token}' | cut -d. -f2 | base64 -d 2>/dev/null || true")
    assert '"client_id":"${clientId}"' in claims and '"sub"' not in claims, claims

    machine.succeed("mkdir -p /root/.config/herdr-eternal")
    machine.succeed(
        "printf '[targets.authbox]\nurl = \"ws://localhost/herdr-eternal\"\ntoken = \"%s\"\n' '"
        + token
        + "' > /root/.config/herdr-eternal/config.toml"
    )
    output = machine.succeed("herdr-eternal-ssh -T authbox 'id -un' < /dev/null")
    assert output == "alice\n", repr(output)

    # Garbage tokens must be rejected.
    machine.succeed(
        "printf '[targets.authbox]\nurl = \"ws://localhost/herdr-eternal\"\ntoken = \"garbage\"\n' > /root/.config/herdr-eternal/config.toml"
    )
    machine.fail("herdr-eternal-ssh -T authbox 'id -un' < /dev/null")
  '';
}
