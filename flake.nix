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
      nixosModules.default = ./nix/module.nix;

      packages = forSystems (pkgs: {
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.sauce;
        sauce = pkgs.rustPlatform.buildRustPackage {
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
            (python3.withPackages (ps: [ ps.cryptography ]))
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

          inherit (nixpkgs) lib;

          exampleFlake = (import ./example/flake.nix).outputs {
            self = exampleFlake;
            inherit nixpkgs;
            sauce = self;
          };
          example = lib.mapAttrs (_: machine: machine.config) exampleFlake.nixosConfigurations;

          manifest = name: example.${name}.sauce.manifest;
          manifests = pkgs.writeText "manifests.json" (
            builtins.toJSON (lib.mapAttrs (name: _: manifest name) example)
          );
          # `offsite` also reads `ddclient/api-token`, so a `sauce generate` back to `manifests` marks it `revoke`.
          widerManifests = pkgs.writeText "manifests.json" (
            builtins.toJSON (
              lib.mapAttrs (name: _: manifest name) example
              // {
                offsite = manifest "offsite" // {
                  read = (manifest "offsite").read ++ [ "ddclient/api-token" ];
                };
              }
            )
          );

          facts = [
            {
              ok = lib.all (name: builtins.toJSON (manifest name) != "") (lib.attrNames example);
              message = "The manifest of every machine of example/ evaluates.";
            }
            {
              ok =
                (manifest "notes").secrets."hedgedoc/db-password".file
                == "example/secrets/hedgedoc/db-password.sauce";
              message = "A secret with no file gets <name>.sauce in sauce.defaultDir, relative to the root of the flake.";
            }
            {
              ok = lib.all (name: (manifest "notes").secrets ? ${name}) [
                "sso/hedgedoc"
                "sso/miniflux"
              ];
              message = "Secret names that a loop computes are in the manifest.";
            }
            {
              ok =
                (manifest "offsite").read == [ "restic/password" ]
                && !((manifest "offsite").secrets ? "restic/password")
                && example.offsite.sauce.secrets."restic/password".path == "/run/sauce/restic/password";
              message = "A name in sauce.read has a path on the machine and is read, not defined, in its manifest.";
            }
            {
              ok = (manifest "backup").secrets."backup/ssh-key" == (manifest "offsite").secrets."backup/ssh-key";
              message = "Two machines that import one module give its secret the same definition.";
            }
            {
              ok = lib.any (
                check:
                !check.assertion
                && lib.hasPrefix "sauce.secrets.\"backup/ssh-key\" has no file at example/secrets/backup/ssh-key.sauce. Run `sauce generate`, or `sauce set backup/ssh-key`" check.message
                && lib.hasInfix "`git add` the file" check.message
              ) example.backup.assertions;
              message = "A machine whose .sauce file is missing has a failed assertion that names the secret, its path, `sauce generate`, `sauce set` and `git add`.";
            }
            {
              ok =
                let
                  broken = exampleFlake.nixosConfigurations.backup.extendModules {
                    modules = [
                      {
                        sauce.defaultDir = lib.mkForce null;
                        sauce.templates."Backup Env".content = "";
                      }
                    ];
                  };
                  failed = map (check: check.message) (lib.filter (check: !check.assertion) broken.config.assertions);
                in
                lib.all (prefix: lib.any (lib.hasPrefix prefix) failed) [
                  "sauce.secrets.\"backup/ssh-key\" has no file, because it sets no `file`"
                  "sauce.templates.\"Backup Env\" has a name that sauce-install refuses."
                ];
              message = "A secret with no file and no sauce.defaultDir, and a template name that sauce-install refuses, each have a failed assertion.";
            }
          ];
          failed = lib.filter (fact: !fact.ok) facts;
        in
        {
          build = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          fmt = cargoCheck "fmt" [ pkgs.cargo pkgs.rustfmt ] "cargo fmt --check";
          clippy = cargoCheck "clippy" [
            pkgs.clippy
          ] "cargo clippy --all-targets --offline -- -D warnings";
          test = cargoCheck "test" [ ] "cargo test --offline";
          decrypt = cargoCheck "decrypt" [ (pkgs.python3.withPackages (ps: [ ps.cryptography ])) ] ''
            cargo run --offline --quiet --example decrypt_fixture -- example/snakeoil/admin.key > secret.sauce
            python tools/sauce-decrypt.py secret.sauce example/snakeoil/admin.key --name test/secret > actual
            printf 'name: test/secret\nversion: 4\nset: 2026-11-10\nissued: 2026-11-01\nexpires: 2027-02-10\ngenerator: %s\nformerly: old/name\nrevoke: true\nlength: 13\n' \
              0707070707070707070707070707070707070707070707070707070707070707 > expected
            cmp expected actual
            python tools/sauce-decrypt.py secret.sauce example/snakeoil/admin.key --print > actual
            printf 'name: test/secret\nversion: 4\nset: 2026-11-10\nissued: 2026-11-01\nexpires: 2027-02-10\ngenerator: %s\nformerly: old/name\nrevoke: true\nvalue: correct horse\n' \
              0707070707070707070707070707070707070707070707070707070707070707 > expected
            cmp expected actual
            python -c 'from pathlib import Path; s = Path("secret.sauce").read_text(); i = s.index("      - X25519 ") + len("      - X25519 "); j = s.index(" ", i); Path("damaged.sauce").write_text(s[:i] + "AA" + s[j:])'
            python tools/sauce-decrypt.py damaged.sauce example/snakeoil/admin.key --print > actual
            cmp expected actual
            python -c 'from pathlib import Path; s = Path("secret.sauce").read_bytes(); Path("crlf.sauce").write_bytes(s.replace(b"\n", b"\r\n"))'
            if python tools/sauce-decrypt.py crlf.sauce example/snakeoil/admin.key > actual; then exit 1; fi
            test ! -s actual
            if python tools/sauce-decrypt.py secret.sauce example/snakeoil/admin.key --name wrong > actual; then exit 1; fi
            test ! -s actual
            python -c 'from pathlib import Path; p = Path("secret.sauce"); p.write_text(p.read_text().replace("name: test/secret", "name: test/other"))'
            if python tools/sauce-decrypt.py secret.sauce example/snakeoil/admin.key > actual; then exit 1; fi
            test ! -s actual
            cargo run --offline --quiet --example decrypt_fixture -- example/snakeoil/admin.key > secret.sauce
            python -c 'from pathlib import Path; p = Path("secret.sauce"); s = p.read_text(); i = s.index("commitment: ") + len("commitment: "); p.write_text(s[:i] + ("A" if s[i] != "A" else "B") + s[i+1:])'
            if python tools/sauce-decrypt.py secret.sauce example/snakeoil/admin.key > actual; then exit 1; fi
            test ! -s actual
          '';
          example = pkgs.runCommand "sauce-example" { } (
            if failed == [ ] then
              "touch $out"
            else
              "echo ${lib.escapeShellArg (lib.concatMapStringsSep "\n" (fact: fact.message) failed)} >&2; exit 1"
          );
          list =
            pkgs.runCommand "sauce-list"
              {
                nativeBuildInputs = [
                  self.packages.${pkgs.stdenv.hostPlatform.system}.sauce
                  pkgs.gitMinimal
                  pkgs.nix
                ];
              }
              ''
                cd ${self}
                sauce list --manifest ${manifests} 2> "$TMPDIR/stderr" | tee $out
                grep -F 'are not checked, because no private key of an admin is set' "$TMPDIR/stderr"
                test "$(tail -n +2 $out | wc -l)" -eq 7
                grep -E '^SECRET +MACHINES +MADE BY +STATE$' $out
                grep -E '^backup/ssh-key +backup,offsite +ssh-ed25519 +✗$' $out
                grep -E '^ddclient/api-token +notes +set +✗$' $out
                grep -E '^hedgedoc/db-password +notes +alphanum, 40<48 +✗$' $out
                grep -E '^restic/password +notes,offsite +once hex, 32 B +✗$' $out

                cd "$TMPDIR"
                mkdir checkout
                cp -r ${self}/example checkout/
                chmod -R u+w checkout
                cd checkout
                flags="--manifest ${manifests}"
                sauce generate $flags
                printf token | sauce set ddclient/api-token --expires "$(date -d '+10 days' +%F)" $flags

                sauce list $flags 2> /dev/null | tee without
                [[ $(grep -c '✓$' without) -eq 7 ]]

                SAUCE_IDENTITY=example/snakeoil/admin.key sauce list $flags 2> stderr | tee with
                test ! -s stderr
                [[ $(grep -c '✓$' with) -eq 6 ]]
                grep -E '^ddclient/api-token +notes +set +⚠$' with
                grep -E '^restic/password +notes,offsite +once hex, 32 B +✓$' with
                if sauce list $flags --identity example/snakeoil/missing.key; then
                  exit 1
                fi

                export HOME="$TMPDIR/home"
                export XDG_CACHE_HOME="$HOME/.cache"
                export NIX_REMOTE="local?root=$TMPDIR/manifest-store"
                export NIX_CONFIG="experimental-features = nix-command flakes"
                mkdir -p "$HOME" "$TMPDIR/tracked-flake"
                cd "$TMPDIR/tracked-flake"
                git init -q
                cat > flake.nix <<'EOF'
                {
                  outputs = { self }: {
                    nixosConfigurations.fixture = {
                      options.sauce = {};
                      config.sauce.manifest = {
                        recipient = "${(manifest "backup").recipient}";
                        adminRecipients = [];
                        secrets.''${import ./declaration.nix} = {
                          file = "fixture.sauce";
                          once = { encoding = "hex"; bytes = 16; };
                        };
                        read = [];
                      };
                    };
                    nixosConfigurations.broken =
                      if import ./broken.nix then throw "fixture eval failure" else { options = {}; };
                  };
                }
                EOF
                printf '"test/before"\n' > declaration.nix
                printf 'false\n' > broken.nix
                git add flake.nix declaration.nix broken.nix
                sauce list | grep '^test/before '
                cache=("$XDG_CACHE_HOME"/sauce/*.json)
                before=$(stat -c %i "$cache")
                sauce list > /dev/null
                test "$(stat -c %i "$cache")" = "$before"
                printf '"test/after"\n' > declaration.nix
                sauce list > current
                grep '^test/after ' current
                ! grep '^test/before ' current

                cp "$cache" complete-cache
                printf 'true\n' > broken.nix
                if sauce list > partial 2> failed; then exit 1; fi
                grep '^test/after ' partial
                cmp complete-cache "$cache"
                if sauce generate > /dev/null 2> failed; then exit 1; fi
                grep -F '"broken"' failed
                test ! -e fixture.sauce
              '';
          generate =
            pkgs.runCommand "sauce-generate"
              { nativeBuildInputs = [ self.packages.${pkgs.stdenv.hostPlatform.system}.sauce ]; }
              ''
                mkdir checkout
                cp -r ${self}/example checkout/
                chmod -R u+w checkout
                cd checkout
                flags="--manifest ${manifests}"
                keys=example/snakeoil

                mkdir -p example/secrets
                sauce generate --dry-run $flags --identity "$keys/missing.key" </dev/null > preview
                test -z "$(find example/secrets -mindepth 1 -print -quit)"
                sauce generate $flags > generated
                diff generated <(tail -n +2 preview)
                find example/secrets -type f | sort | xargs sha256sum > first
                sauce generate $flags
                find example/secrets -type f | sort | xargs sha256sum | diff first -

                value=$(sauce get hedgedoc/db-password --print $flags --identity $keys/admin.key)
                [[ $value =~ ^[A-Za-z0-9]{40,48}$ ]]
                if sauce get hedgedoc/db-password --print $flags --identity $keys/backup.key; then
                  exit 1
                fi

                if head -c 253 /dev/zero | tr '\0' a | sauce set ddclient/api-token $flags; then
                  exit 1
                fi
                touch $out
              '';
          daily =
            pkgs.runCommand "sauce-daily"
              {
                nativeBuildInputs = [
                  self.packages.${pkgs.stdenv.hostPlatform.system}.sauce
                  pkgs.util-linux
                ];
              }
              ''
                mkdir checkout
                cp -r ${self}/example checkout/
                chmod -R u+w checkout
                cd checkout
                flags="--manifest ${manifests}"
                export SAUCE_IDENTITY=example/snakeoil/admin.key
                sauce generate $flags
                files() { find example/secrets -type f | sort | xargs sha256sum; }

                files > before
                hedgedoc=$(sauce get sso/hedgedoc --print $flags)
                miniflux=$(sauce get sso/miniflux --print $flags)
                echo y | sauce rotate 'sso/*' $flags
                files > after
                diff <(sed 's/^[0-9a-f]* *//' before) <(sed 's/^[0-9a-f]* *//' after)
                grep -vxFf before after | sed 's/^[0-9a-f]* *//' > changed
                printf '%s\n' example/secrets/sso/hedgedoc.sauce example/secrets/sso/miniflux.sauce | diff - changed
                sauce get sso/hedgedoc $flags | grep -x 'version: 2'
                sauce get sso/miniflux $flags | grep -x 'version: 2'
                [[ $(sauce get sso/hedgedoc --print $flags) != "$hedgedoc" ]]
                [[ $(sauce get sso/miniflux --print $flags) != "$miniflux" ]]
                if sauce rotate restic/password $flags; then
                  exit 1
                fi

                lastyear=$(( $(date +%Y) - 1 ))-06-01
                printf token | sauce set ddclient/api-token --expires $lastyear $flags
                sauce status $flags | grep -E "^ddclient/api-token +expired on $lastyear"

                mkdir -m 700 /dev/shm/run
                export XDG_RUNTIME_DIR=/dev/shm/run
                echo 'printf edited-token > "$1"' > editor
                EDITOR="sh $PWD/editor" sauce edit ddclient/api-token $flags
                [[ $(sauce get ddclient/api-token --print $flags) == edited-token ]]
                sauce get ddclient/api-token $flags | grep -x 'note: API token for the DNS zone example.com, made in the dashboard of the DNS provider.'
                [[ -z $(ls /dev/shm/run) ]]

                files > before
                sauce generate --dry-run --manifest ${widerManifests} --identity example/snakeoil/missing.key </dev/null > preview
                grep -Fx 're-encrypted ddclient/api-token' preview
                diff before <(files)

                script -qec "sauce generate --manifest ${widerManifests}" /dev/null <<< y
                script -qec "sauce generate $flags" /dev/null <<< y
                printf edited-token | sauce set ddclient/api-token $flags | grep -x 'ddclient/api-token stays marked revoke, because the value is the same as before'

                printf '%s\n' sso/hedgedoc sso/miniflux | diff - <(sauce search sso $flags)
                if copied=$(sauce get sso/hedgedoc --copy $flags); then
                  exit 1
                fi
                [[ -z $copied ]]
                touch $out
              '';
        }
        // lib.optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
          # Without "kvm" in requiredSystemFeatures, a builder with no KVM runs the test on emulation, slowly.
          vm =
            (import ./nix/vm-test.nix {
              inherit pkgs;
              sauce = self;
              example = exampleFlake;
              sealed = pkgs.callPackage ./nix/seal.nix {
                sauce = self.packages.${pkgs.stdenv.hostPlatform.system}.sauce;
              };
              machines = example;
            }).overrideTestDerivation
              { requiredSystemFeatures = [ "nixos-test" ]; };
        }
      );
    };
}
