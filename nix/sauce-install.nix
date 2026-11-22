{ lib, rustPlatform }:
rustPlatform.buildRustPackage {
  pname = "sauce-install";
  version = (lib.importTOML ../Cargo.toml).workspace.package.version;
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../clippy.toml
      ../crates
    ];
  };
  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [
    "--package"
    "sauce-install"
  ];
  doCheck = false;
  meta = {
    license = lib.licenses.gpl3Only;
    mainProgram = "sauce-install";
  };
}
