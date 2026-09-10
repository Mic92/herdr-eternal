{
  description = "Roaming-friendly transport for herdr --remote (WebSocket/QUIC + OIDC)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
    crane.url = "github:ipetkov/crane";
    # Pinned to the commit the remote.ssh_command patch applies to.
    herdr.url = "github:ogulcancelik/herdr/702aa1e45527509bec73dad9b8d443f449c0379b";
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
      crane,
      herdr,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      inherit (nixpkgs) lib;
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      treefmtEval = forAllSystems (
        pkgs:
        treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.nixfmt.enable = true;
          programs.rustfmt.enable = true;
        }
      );

      perSystem = forAllSystems (
        pkgs:
        let
          craneLib = crane.mkLib pkgs;
          # herdr with the remote.ssh_command option, used by the herdr-driven
          # integration test in client/tests/.
          herdrPatched = herdr.packages.${pkgs.stdenv.hostPlatform.system}.herdr.overrideAttrs (old: {
            patches = (old.patches or [ ]) ++ [
              ./nix/patches/0001-remote-make-ssh-transport-program-configurable.patch
            ];
          });
          commonArgs = {
            src = craneLib.cleanCargoSource ./.;
            strictDeps = true;
            # Virtual workspace: no [package] in the root Cargo.toml.
            pname = "herdr-eternal";
            version = "0.1.0";
          };
          # Build dependencies once and reuse them for the workspace, clippy and tests.
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          workspace = craneLib.buildPackage (commonArgs // { inherit cargoArtifacts; });
        in
        {
          inherit
            craneLib
            herdrPatched
            commonArgs
            cargoArtifacts
            workspace
            ;
        }
      );
    in
    {
      nixosModules.default =
        { pkgs, lib, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.herdr-eternal-server.package =
            lib.mkDefault
              self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };

      packages = forAllSystems (
        pkgs: with perSystem.${pkgs.stdenv.hostPlatform.system}; {
          default = workspace;
          herdr-eternal = workspace;
        }
      );

      checks = forAllSystems (
        pkgs:
        with perSystem.${pkgs.stdenv.hostPlatform.system};
        {
          inherit workspace;
          formatting = treefmtEval.${pkgs.stdenv.hostPlatform.system}.config.build.check self;
          clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- -D warnings";
            }
          );
          tests = craneLib.cargoTest (
            commonArgs
            // {
              inherit cargoArtifacts;
              # The herdr-driven end-to-end test needs herdr in PATH.
              nativeCheckInputs = [ herdrPatched ];
            }
          );
        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          # Full deployment path: NixOS module, nginx WebSocket proxying,
          # client exec through the proxy.
          nixos = pkgs.callPackage ./nix/nixos-test.nix {
            nixosModule = self.nixosModules.default;
            package = workspace;
          };
          # Compatibility with a real OIDC provider.
          nixos-authelia = pkgs.callPackage ./nix/nixos-test-authelia.nix {
            nixosModule = self.nixosModules.default;
            package = workspace;
          };
        }
      );

      devShells = forAllSystems (
        pkgs: with perSystem.${pkgs.stdenv.hostPlatform.system}; {
          default = craneLib.devShell {
            packages = [
              pkgs.clippy
              pkgs.rustfmt
              pkgs.rust-analyzer
              herdrPatched
            ];
          };
        }
      );

      formatter = forAllSystems (
        pkgs: treefmtEval.${pkgs.stdenv.hostPlatform.system}.config.build.wrapper
      );
    };
}
