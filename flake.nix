{
  description = "secret-sauce, a secret manager for NixOS";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forSystems (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "sauce";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [
            "--package"
            "sauce"
          ];
          doCheck = false;
          meta.mainProgram = "sauce";
        };
      });

      devShells = forSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            clippy
            rustc
            rustfmt
          ];
        };
      });

      checks = forSystems (
        pkgs:
        let
          cargoCheck =
            name: tools: script:
            pkgs.rustPlatform.buildRustPackage {
              pname = "sauce-${name}";
              version = "0";
              src = self;
              cargoLock.lockFile = ./Cargo.lock;
              nativeBuildInputs = tools;
              doCheck = false;
              buildPhase = ''
                runHook preBuild
                ${script}
                runHook postBuild
              '';
              installPhase = "touch $out";
            };
        in
        {
          build = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          fmt = cargoCheck "fmt" [ pkgs.cargo pkgs.rustfmt ] "cargo fmt --check";
          clippy = cargoCheck "clippy" [
            pkgs.clippy
          ] "cargo clippy --all-targets --offline -- -D warnings";
          test = cargoCheck "test" [ ] "cargo test --offline";
        }
      );
    };
}
