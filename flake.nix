{
  description = "Roaming-friendly transport for herdr --remote (WebSocket/QUIC + OIDC)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
    crane.url = "github:ipetkov/crane";
    # Pinned to the commit the remote.ssh_command patch applies to.
    herdr.url = "github:ogulcancelik/herdr/e7fc85bfdb51f89488430adbfe5bbced3be79c2f";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      imports = [ inputs.treefmt-nix.flakeModule ];
      perSystem =
        { pkgs, ... }:
        let
          craneLib = inputs.crane.mkLib pkgs;
          # herdr with the remote.ssh_command option, used by the herdr-driven
          # integration test in client/tests/.
          herdrPatched = inputs.herdr.packages.${pkgs.stdenv.hostPlatform.system}.herdr.overrideAttrs (old: {
            patches = (old.patches or [ ]) ++ [
              ./nix/patches/0001-remote-make-ssh-transport-program-configurable.patch
            ];
          });
          src = craneLib.cleanCargoSource ./.;
          commonArgs = {
            inherit src;
            strictDeps = true;
          };
          # Build dependencies once and reuse them for the workspace, clippy and tests.
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          workspace = craneLib.buildPackage (commonArgs // { inherit cargoArtifacts; });
        in
        {
          packages = {
            default = workspace;
            herdr-eternal = workspace;
          };

          checks = {
            inherit workspace;
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
          };

          devShells.default = craneLib.devShell {
            packages = [
              pkgs.clippy
              pkgs.rustfmt
              pkgs.rust-analyzer
              herdrPatched
            ];
          };

          treefmt = {
            projectRootFile = "flake.nix";
            programs.nixfmt.enable = true;
            programs.rustfmt.enable = true;
          };
        };
    };
}
