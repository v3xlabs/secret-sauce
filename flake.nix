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
          meta = {
            license = pkgs.lib.licenses.gpl3Only;
            mainProgram = "sauce";
          };
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
          longManifests = pkgs.writeText "long-manifests.json" (
            builtins.toJSON (lib.mapAttrs (name: machine: if name == "notes" then
              (machine.extendModules {
                modules = [ { sauce.secrets."ddclient/api-token".maxLength = 4096; } ];
              }).config.sauce.manifest
            else manifest name) exampleFlake.nixosConfigurations)
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
                == "example/secrets/hedgedoc/db-password.sauce.yaml";
              message = "A secret with no file gets <name>.sauce.yaml in sauce.defaultDir, relative to the root of the flake.";
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
              ok =
                let
                  broken = exampleFlake.nixosConfigurations.notes.extendModules {
                    modules = [ { sauce.secrets."hedgedoc/db-password".maxLength = 4096; } ];
                  };
                in
                !(builtins.tryEval (builtins.deepSeq broken.config.sauce.manifest true)).success;
              message = "maxLength with a generator is refused.";
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
            cargo run --offline --quiet --example decrypt_fixture -- example/snakeoil/admin.key > secret.sauce.yaml
            python tools/sauce-decrypt.py secret.sauce.yaml example/snakeoil/admin.key --name test/secret > actual
            printf 'name: test/secret\nversion: 4\nset: 2026-11-10\nissued: 2026-11-01\nexpires: 2027-02-10\ngenerator: %s\nformerly: old/name\nrevoke: true\nlength: 13\n' \
              0707070707070707070707070707070707070707070707070707070707070707 > expected
            cmp expected actual
            python tools/sauce-decrypt.py secret.sauce.yaml example/snakeoil/admin.key --print > actual
            printf 'name: test/secret\nversion: 4\nset: 2026-11-10\nissued: 2026-11-01\nexpires: 2027-02-10\ngenerator: %s\nformerly: old/name\nrevoke: true\nvalue: correct horse\n' \
              0707070707070707070707070707070707070707070707070707070707070707 > expected
            cmp expected actual
            python -c 'from pathlib import Path; s = Path("secret.sauce.yaml").read_text(); i = s.index("      - X25519 ") + len("      - X25519 "); j = s.index(" ", i); Path("damaged.sauce.yaml").write_text(s[:i] + "AA" + s[j:])'
            python tools/sauce-decrypt.py damaged.sauce.yaml example/snakeoil/admin.key --print > actual
            cmp expected actual
            python -c 'from pathlib import Path; s = Path("secret.sauce.yaml").read_bytes(); Path("crlf.sauce.yaml").write_bytes(s.replace(b"\n", b"\r\n"))'
            if python tools/sauce-decrypt.py crlf.sauce.yaml example/snakeoil/admin.key > actual; then exit 1; fi
            test ! -s actual
            if python tools/sauce-decrypt.py secret.sauce.yaml example/snakeoil/admin.key --name wrong > actual; then exit 1; fi
            test ! -s actual
            python -c 'from pathlib import Path; p = Path("secret.sauce.yaml"); p.write_text(p.read_text().replace("name: test/secret", "name: test/other"))'
            if python tools/sauce-decrypt.py secret.sauce.yaml example/snakeoil/admin.key > actual; then exit 1; fi
            test ! -s actual
            cargo run --offline --quiet --example decrypt_fixture -- example/snakeoil/admin.key > secret.sauce.yaml
            python -c 'from pathlib import Path; p = Path("secret.sauce.yaml"); s = p.read_text(); i = s.index("commitment: ") + len("commitment: "); p.write_text(s[:i] + ("A" if s[i] != "A" else "B") + s[i+1:])'
            if python tools/sauce-decrypt.py secret.sauce.yaml example/snakeoil/admin.key > actual; then exit 1; fi
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
                test "$(tail -n +2 $out | wc -l)" -eq 8
                grep -E '^SECRET +MACHINES +MADE BY +SET +EXPIRES +STATE$' $out
                grep -E '^backup/ssh-key +backup,offsite +ssh-ed25519 +✗$' $out
                grep -E '^ddclient/api-token +notes +set +✗$' $out
                grep -E '^hedgedoc/db-password +notes +alphanum, 40<48 +✗$' $out
                grep -E '^hedgedoc/session-secret +notes +base64url, 32 B +✗$' $out
                grep -E '^restic/password +notes,offsite +once alphanum, 40<48 +✗$' $out

                cd "$TMPDIR"
                mkdir checkout
                cp -r ${self}/example checkout/
                chmod -R u+w checkout
                cd checkout
                flags="--manifest ${manifests}"
                sauce generate $flags
                printf token | sauce set ddclient/api-token --expires "$(date -u -d '+10 days' +%F)" $flags

                sauce list $flags 2> /dev/null | tee without
                [[ $(grep -c '✓$' without) -eq 8 ]]
                grep -E '^ddclient/api-token +notes +set +✓$' without

                SAUCE_IDENTITY=example/snakeoil/admin.key sauce list $flags 2> stderr | tee with
                test ! -s stderr
                [[ $(grep -c '✓$' with) -eq 7 ]]
                grep -E '^ddclient/api-token +notes +set +(today|1d ago) +in (9|10)d +⚠$' with
                grep -E '^restic/password +notes,offsite +once alphanum, 40<48 +(today|1d ago) +✓$' with
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
                          file = "fixture.sauce.yaml";
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
                test ! -e fixture.sauce.yaml
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
                test -f example/secrets/backup/ssh-key.sauce.yaml
                test -f example/secrets/backup/ssh-key.pub
                test ! -e example/secrets/backup/ssh-key.sauce.pub
                find example/secrets -type f | sort | xargs sha256sum > first
                sauce generate $flags
                find example/secrets -type f | sort | xargs sha256sum | diff first -

                value=$(sauce get hedgedoc/db-password --print $flags --identity $keys/admin.key)
                [[ $value =~ ^[A-Za-z0-9]{40,48}$ ]]
                sauce get restic/password --print $flags --identity $keys/admin.key | grep -Eqx '[A-Za-z0-9]{40,48}'
                [[ $(sauce get hedgedoc/session-secret --print $flags --identity $keys/admin.key) =~ ^[A-Za-z0-9_-]{43}$ ]]
                if sauce get hedgedoc/db-password --print $flags --identity $keys/backup.key; then
                  exit 1
                fi

                if head -c 253 /dev/zero | tr '\0' a | sauce set ddclient/api-token $flags; then
                  exit 1
                fi
                longFlags="--manifest ${longManifests}"
                if head -c 4097 /dev/zero | tr '\0' a | sauce set ddclient/api-token $longFlags 2> error; then
                  exit 1
                fi
                grep -F '4096' error
                head -c 4096 /dev/zero | tr '\0' a | sauce set ddclient/api-token $longFlags
                [[ $(grep '^value: ' example/secrets/ddclient/api-token.sauce.yaml | cut -d' ' -f2 | base64 -d | wc -c) -eq 8208 ]]
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
                printf '%s\n' example/secrets/sso/hedgedoc.sauce.yaml example/secrets/sso/miniflux.sauce.yaml | diff - changed
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
          import =
            pkgs.runCommand "sauce-import"
              {
                nativeBuildInputs = [
                  self.packages.${pkgs.stdenv.hostPlatform.system}.sauce
                  pkgs.age
                  pkgs.sops
                ];
              }
              ''
                export HOME="$TMPDIR/home"
                mkdir -p "$HOME"
                mkdir checkout
                cp -r ${self}/example checkout/
                chmod -R u+w checkout
                cd checkout
                flags="--manifest ${manifests}"
                admin=example/snakeoil/admin.key

                # A throwaway sops key and file, made here so that no vector is committed.
                age-keygen -o "$TMPDIR/sops.key" 2> /dev/null
                export SOPS_AGE_KEY_FILE="$TMPDIR/sops.key"
                password=Kq1vT0bWx9Lm4tYcR8zPa2Nd6Hf3Js7Ge5Ub0Wo1Xy
                printf 'ddclient_token: |\n  line one\n  line two\nhedgedoc_db: %s\nport: 8080\nunused: other-value\n' "$password" > plain.yaml
                sops encrypt --age "$(age-keygen -y "$SOPS_AGE_KEY_FILE")" --input-type yaml --output-type yaml plain.yaml > secrets.sops.yaml
                rm plain.yaml
                printf '{\n  "ddclient_token": "ddclient/api-token",\n  "hedgedoc_db": "hedgedoc/db-password"\n}\n' > import.json

                # Fails the check when the output of sauce holds any value of the sops file.
                leaks() {
                  if grep -q -e "$password" -e 'line one' -e other-value -e changed "$1"; then
                    echo "a value of the sops file reached the output of sauce" >&2
                    exit 1
                  fi
                }
                sums() { find example -name '*.sauce.yaml' | sort | xargs -r sha256sum; }

                sauce import secrets.sops.yaml import.json --dry-run $flags > out 2>&1
                leaks out
                cat out
                grep -x 'import "ddclient_token" as ddclient/api-token' out
                grep -x 'import "hedgedoc_db" as hedgedoc/db-password' out
                [[ -z $(sums) ]]

                # A secret that sauce cannot stage stops the import before any secret is in place.
                mkdir -p example/secrets/hedgedoc
                chmod 555 example/secrets/hedgedoc
                if sauce import secrets.sops.yaml import.json $flags > out 2>&1; then
                  exit 1
                fi
                leaks out
                cat out
                [[ -z $(sums) ]]
                chmod 755 example/secrets/hedgedoc

                # A symbolic link at the name that sauce once staged at, and its target, stay as they are.
                mkdir -p example/secrets/ddclient
                echo untouched > "$TMPDIR/target"
                ln -s "$TMPDIR/target" example/secrets/ddclient/api-token.sauce.yaml.new
                sauce import secrets.sops.yaml import.json $flags > out 2>&1
                leaks out
                cat out
                [[ $(cat "$TMPDIR/target") == untouched ]]
                [[ -L example/secrets/ddclient/api-token.sauce.yaml.new && ! -L example/secrets/ddclient/api-token.sauce.yaml ]]
                printf 'line one\nline two\n' > expected
                sauce get ddclient/api-token --print $flags --identity $admin > actual
                cmp expected actual
                [[ $(sauce get hedgedoc/db-password --print $flags --identity $admin) == "$password" ]]
                sums > before

                # New values for the same keys change no file that exists.
                printf 'ddclient_token: changed\nhedgedoc_db: changed\n' > plain.yaml
                sops encrypt --age "$(age-keygen -y "$SOPS_AGE_KEY_FILE")" --input-type yaml --output-type yaml plain.yaml > changed.sops.yaml
                rm plain.yaml
                sauce import changed.sops.yaml import.json $flags > out 2>&1
                leaks out
                grep -x 'skip "ddclient_token": ddclient/api-token has a .sauce.yaml file, which sauce keeps, and sauce did not compare the values' out
                grep -x 'skip "hedgedoc_db": hedgedoc/db-password has a .sauce.yaml file, which sauce keeps, and sauce did not compare the values' out
                sums | diff before -

                # A folder in the place of a .sauce.yaml file is refused, and not skipped.
                mkdir -p example/secrets/sso/hedgedoc.sauce.yaml
                printf '{ "unused": "sso/hedgedoc" }\n' > folder.json
                if sauce import secrets.sops.yaml folder.json $flags > out 2>&1; then
                  exit 1
                fi
                leaks out
                cat out
                grep -x 'refuse "unused": .*/example/secrets/sso/hedgedoc.sauce.yaml is not a file' out
                rmdir example/secrets/sso/hedgedoc.sauce.yaml

                # A folder that is a symbolic link stops the import, in a dry run too, and nothing lands where it points.
                rmdir example/secrets/sso
                mkdir "$TMPDIR/elsewhere"
                ln -s "$TMPDIR/elsewhere" example/secrets/sso
                for dry in --dry-run ""; do
                  if sauce import secrets.sops.yaml folder.json $dry $flags > out 2>&1; then
                    exit 1
                  fi
                  leaks out
                  cat out
                  grep -x 'refuse "unused": the folder .*/example/secrets/sso of sso/hedgedoc is a symbolic link' out
                done
                [[ -z $(ls -A "$TMPDIR/elsewhere") ]]
                rm example/secrets/sso

                # A mapping file over 1 MiB stops the import, even when its content is fine.
                { printf '{ "unused": "sso/hedgedoc"'; head -c 1048576 /dev/zero | tr '\0' ' '; printf '}\n'; } > large.json
                if sauce import secrets.sops.yaml large.json --dry-run $flags > out 2>&1; then
                  exit 1
                fi
                leaks out
                cat out
                grep -x 'error: the mapping file large.json is larger than 1048576 bytes' out

                # A credential in a target field can be lowercase hex, which is a valid name, so only a declared target is printed.
                hex=4f2a9c0d7e1b6a35c8f04e92d17b3a6c
                printf '{\n  "port": "kanidm/idm-admin-password",\n  "missing": "sso/hedgedoc",\n  "unused": "sso/miniflux",\n  "hedgedoc_db": "sso/miniflux",\n  "unused": "kanidm/idm-admin-password",\n  "ddclient_token": "Bad Name",\n  "absent": "Bad Name",\n  "stray": "%s",\n  "stray_again": "%s",\n  "clear\\u001b[2J\\nimport hedgedoc_db as sso/hedgedoc": "restic/password"\n}\n' "$hex" "$hex" > bad.json
                if sauce import secrets.sops.yaml bad.json $flags > out 2>&1; then
                  exit 1
                fi
                leaks out
                cat out
                grep -x 'refuse "port": the value is not a string at the top level of the sops file' out
                grep -x 'refuse "missing": the sops file has no such key' out
                grep -x 'refuse "hedgedoc_db": an earlier sops key also maps to sso/miniflux' out
                grep -x 'refuse "unused": the mapping names this sops key twice' out
                grep -x 'refuse "ddclient_token": no machine declares the target' out
                grep -x 'refuse "absent": no machine declares the target' out
                grep -x 'refuse "stray": no machine declares the target' out
                grep -x 'refuse "stray_again": no machine declares the target' out
                # A sops key with control characters stays on one line, and sends no escape sequence to the terminal.
                grep -xF 'refuse "clear\u{1b}[2J\nimport hedgedoc_db as sso/hedgedoc": the sops file has no such key' out
                if grep -q $'\e' out; then
                  exit 1
                fi
                if grep -q -e 'Bad Name' -e "$hex" out; then
                  exit 1
                fi
                sums | diff before -

                # Each duplicate refusal names only its own key, so a long first key appears once and not once for each duplicate.
                long=$(head -c 100000 /dev/zero | tr '\0' a)
                { printf '{ "%s": "sso/hedgedoc"' "$long"; for i in $(seq 20); do printf ', "k%s": "sso/hedgedoc"' "$i"; done; printf ' }\n'; } > many.json
                if sauce import secrets.sops.yaml many.json $flags > out 2>&1; then
                  exit 1
                fi
                leaks out
                grep -x 'refuse "k20": an earlier sops key also maps to sso/hedgedoc' out
                (( $(wc -c < out) < 200000 ))

                # A failed sops writes nothing, and its stderr, which can quote a value, stays hidden.
                age-keygen -o "$TMPDIR/other.key" 2> /dev/null
                if SOPS_AGE_KEY_FILE="$TMPDIR/other.key" sauce import secrets.sops.yaml import.json $flags > out 2>&1; then
                  exit 1
                fi
                # The output is compared byte for byte and never printed, so any other output of sops fails the check without reaching the log.
                printf 'error: sops decrypt failed with exit status: 128, and sauce does not show its message, which can quote a value\n' | cmp -s - out
                sums | diff before -

                # A failed write to stdout after a link names the secrets in place on stderr, and leaves no staged file.
                printf '{ "unused": "sso/miniflux", "hedgedoc_db": "kanidm/idm-admin-password" }\n' > full.json
                if sauce import secrets.sops.yaml full.json $flags > /dev/full 2> out; then
                  exit 1
                fi
                leaks out
                cat out
                grep -x 'imported "unused" as sso/miniflux' out
                [[ -f example/secrets/sso/miniflux.sauce.yaml && ! -e example/secrets/kanidm/idm-admin-password.sauce.yaml ]]
                [[ -z $(find example -name '*.new' ! -name api-token.sauce.yaml.new) ]]
                touch $out
              '';
          gpg =
            pkgs.runCommand "sauce-gpg"
              {
                nativeBuildInputs = [
                  self.packages.${pkgs.stdenv.hostPlatform.system}.sauce
                  pkgs.age
                  pkgs.jq
                  pkgs.sops
                  (pkgs.python3.withPackages (ps: [ ps.cryptography ]))
                ];
              }
              ''
                export HOME="$TMPDIR/home" GNUPGHOME="$TMPDIR/gnupg"
                mkdir -p "$HOME"
                mkdir -m 700 "$GNUPGHOME"
                # A gpg on PATH that records each run, so the check sees which commands start gpg.
                # It also records the name of each variable for an age private key that gpg gets, so the check sees none reach it.
                mkdir bin
                printf '#!/bin/sh\necho "$*" >> %s\nenv | grep -oE "^(SOPS_AGE_KEY|SOPS_AGE_KEY_FILE|SAUCE_IDENTITY)=" >> %s\nexec %s "$@"\n' "$TMPDIR/runs" "$TMPDIR/keys" ${pkgs.gnupg}/bin/gpg > bin/gpg
                chmod +x bin/gpg
                export PATH="$PWD/bin:$PATH"

                gpg --batch --passphrase "" --quick-gen-key "throwaway <throwaway@example.invalid>" ed25519 sign never
                fingerprint=$(gpg --with-colons --list-keys throwaway | awk -F: '/^fpr/ { print $10; exit }')
                gpg --batch --passphrase "" --quick-add-key "$fingerprint" cv25519 encr never
                gpg --batch --passphrase "" --quick-gen-key "other <other@example.invalid>" ed25519 sign never
                other=$(gpg --with-colons --list-keys other | awk -F: '/^fpr/ { print $10; exit }')
                gpg --batch --passphrase "" --quick-add-key "$other" cv25519 encr never

                mkdir checkout
                cp -r ${self}/example checkout/
                chmod -R u+w checkout
                cd checkout
                jq --arg key "$fingerprint" 'map_values(.adminRecipients += [$key])' ${manifests} > gpg.json
                flags="--manifest gpg.json"
                admin=example/snakeoil/admin.key
                file=example/secrets/hedgedoc/db-password.sauce.yaml

                sauce generate $flags
                grep -x "    pgp: $fingerprint" $file
                [[ $(grep -rlx "    pgp: $fingerprint" example/secrets | wc -l) -eq $(find example/secrets -name '*.sauce.yaml' | wc -l) ]]

                : > "$TMPDIR/runs"
                value=$(sauce get hedgedoc/db-password --print $flags --identity $admin)
                [[ $value =~ ^[A-Za-z0-9]{40,48}$ ]]
                test ! -s "$TMPDIR/runs"

                [[ $(sauce get hedgedoc/db-password --print $flags) == "$value" ]]
                grep -- --unwrap "$TMPDIR/runs"

                # sauce import wraps for the GPG reader too, so its file opens with gpg alone.
                # The sops key comes in SOPS_AGE_KEY, and gpg never gets it.
                age-keygen -o "$TMPDIR/sops.key" 2> /dev/null
                printf 'ddclient_token: imported-token\n' > plain.yaml
                sops encrypt --age "$(age-keygen -y "$TMPDIR/sops.key")" --input-type yaml --output-type yaml plain.yaml > secrets.sops.yaml
                rm plain.yaml
                printf '{ "ddclient_token": "ddclient/api-token" }\n' > import.json
                : > "$TMPDIR/runs"
                # A dry run of an import starts no gpg, as one of generate does.
                SOPS_AGE_KEY="$(cat "$TMPDIR/sops.key")" sauce import secrets.sops.yaml import.json --dry-run $flags | grep -x 'import "ddclient_token" as ddclient/api-token'
                test ! -s "$TMPDIR/runs"
                test ! -e example/secrets/ddclient/api-token.sauce.yaml
                SOPS_AGE_KEY="$(cat "$TMPDIR/sops.key")" sauce import secrets.sops.yaml import.json $flags
                grep -- --encrypt "$TMPDIR/runs"
                test ! -s "$TMPDIR/keys"
                grep -x "    pgp: $fingerprint" example/secrets/ddclient/api-token.sauce.yaml
                [[ $(sauce get ddclient/api-token --print $flags) == imported-token ]]

                printf token | sauce set ddclient/api-token $flags
                printf other-token | sauce set ddclient/api-token $flags
                [[ $(sauce get ddclient/api-token --print $flags) == other-token ]]
                [[ $(sauce get ddclient/api-token --print $flags --identity $admin) == other-token ]]

                : > "$TMPDIR/runs"
                sauce list $flags 2> stderr
                grep -F 'are not checked, because no private key of an admin is set' stderr
                sauce status $flags 2> stderr
                grep -F 'are not checked, because no private key of an admin is set' stderr
                SAUCE_IDENTITY=$admin sauce list $flags
                test ! -s "$TMPDIR/runs"

                python ${self}/tools/sauce-decrypt.py $file $admin --print | grep -x "value: $value"

                # A damaged age wrap stops only its own reader, so the GPG reader still opens the file.
                # gpg gets neither the identity file nor the key file of sops.
                # The last character of a 32-byte share in base64 has its low two bits zero, so A and Q are both canonical.
                python -c 'import sys; from pathlib import Path; p = Path(sys.argv[1]); s = p.read_text(); i = s.index("      - X25519 "); j = s.index("\n", i) - 1; p.write_text(s[:j] + ("A" if s[j] != "A" else "Q") + s[j + 1:])' $file
                : > "$TMPDIR/runs"
                [[ $(SAUCE_IDENTITY=$admin SOPS_AGE_KEY_FILE="$TMPDIR/sops.key" sauce get hedgedoc/db-password --print $flags) == "$value" ]]
                grep -- --unwrap "$TMPDIR/runs"
                test ! -s "$TMPDIR/keys"

                # A wrap for another local key is refused before gpg uses any private key.
                hostile=$(head -c 16 /dev/urandom | gpg --no-options --batch --trust-model always --compress-algo none --no-literal --recipient "$other" --encrypt | base64 -w 0 | tr -d =)
                python -c 'import sys; from pathlib import Path; p = Path(sys.argv[1]); s = p.read_text(); i = s.index("    pgp: " + sys.argv[2]); i = s.index("    wrap: ", i) + len("    wrap: "); j = s.index("\n", i); p.write_text(s[:i] + sys.argv[3] + s[j:])' example/secrets/sso/hedgedoc.sauce.yaml "$fingerprint" "$hostile"
                : > "$TMPDIR/runs"
                if sauce get sso/hedgedoc --print $flags 2> stderr; then
                  exit 1
                fi
                grep -F "the wrap is not for one encryption key of $fingerprint" stderr
                [[ $(grep -- --unwrap "$TMPDIR/runs" | grep -vc -- --list-only) -eq 0 ]]

                # A message for a passphrase inside the encrypted data is refused for its length, and gpg never reads it.
                hostile=$(head -c 16 /dev/urandom \
                  | gpg --no-options --batch --pinentry-mode loopback --passphrase hunter2 --compress-algo none --symmetric \
                  | gpg --no-options --batch --trust-model always --compress-algo none --no-literal --recipient "$fingerprint" --encrypt \
                  | base64 -w 0 | tr -d =)
                python -c 'import sys; from pathlib import Path; p = Path(sys.argv[1]); s = p.read_text(); i = s.index("    pgp: " + sys.argv[2]); i = s.index("    wrap: ", i) + len("    wrap: "); j = s.index("\n", i); p.write_text(s[:i] + sys.argv[3] + s[j:])' example/secrets/sso/miniflux.sauce.yaml "$fingerprint" "$hostile"
                if sauce get sso/miniflux --print $flags 2> stderr; then
                  exit 1
                fi
                grep -F "gpg did not give a file key of 16 bytes" stderr

                # gpg encrypts to the fingerprint of a subkey, but a read never matches it, so a write refuses it.
                subkey=$(gpg --with-colons --list-keys throwaway | awk -F: '/^sub/ { seen = 1; next } seen && /^fpr/ { print $10; exit }')
                jq --arg key "$subkey" 'map_values(.adminRecipients += [$key])' ${manifests} > subkey.json
                if printf token | sauce set ddclient/api-token --manifest subkey.json --identity $admin 2> stderr; then
                  exit 1
                fi
                grep -F "$subkey is not the fingerprint of a primary key" stderr
                ${pkgs.gnupg}/bin/gpgconf --kill gpg-agent
                touch $out
              '';
        }
        // lib.optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
          # Without "kvm" in requiredSystemFeatures, a builder with no KVM runs the test on emulation, slowly.
          vm =
            (import ./nix/vm-test.nix {
              inherit pkgs;
              sauce = self;
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
