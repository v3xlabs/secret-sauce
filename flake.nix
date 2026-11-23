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
      python = pkgs: pkgs.python3.withPackages (ps: [ ps.bech32 ps.cryptography ]);
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
          # `sauce` answers each Tab itself, so the scripts only register it, under the name `sauce` that the shell finds on its PATH.
          postInstall = ''
            mkdir -p $out/share/bash-completion/completions $out/share/zsh/site-functions $out/share/fish/vendor_completions.d
            export PATH="$out/bin:$PATH"
            # The script fills COMPREPLY from an unquoted command substitution, which would expand the `*` of a pattern or drop it under nullglob, so it turns pathname expansion off for the call.
            SAUCE_COMPLETE=bash sauce | sed '/^    local IFS=/a\    if local - 2> /dev/null; then set -f; fi' > $out/share/bash-completion/completions/sauce
            SAUCE_COMPLETE=zsh sauce > $out/share/zsh/site-functions/_sauce
            # The file is the body of the function that zsh autoloads, so it must also call the completer for the first Tab.
            echo '_clap_dynamic_completer_sauce "$@"' >> $out/share/zsh/site-functions/_sauce
            SAUCE_COMPLETE=fish sauce > $out/share/fish/vendor_completions.d/sauce.fish
          '';
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
            (python pkgs)
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
          # `hedgedoc/db-password` makes 40 to 48 characters and takes a value of up to `maxLength` bytes.
          boundManifests =
            maxLength:
            pkgs.writeText "bound-${toString maxLength}-manifests.json" (
              builtins.toJSON (lib.mapAttrs (name: machine: if name == "notes" then
                (machine.extendModules {
                  modules = [ { sauce.secrets."hedgedoc/db-password".maxLength = maxLength; } ];
                }).config.sauce.manifest
              else manifest name) exampleFlake.nixosConfigurations)
            );
          # Self-signed certificates that end in 2031, 2033 and 2099, and one that never ends, made here with fixed inputs so that the bytes repeat.
          # The key of each is made from its name, the serial number is fixed, and Ed25519 signs without a random number.
          # Python writes a year from 2050 on as a GeneralizedTime and the other years as a UTCTime.
          certificates =
            pkgs.runCommand "certificates"
              { nativeBuildInputs = [ (pkgs.python3.withPackages (ps: [ ps.cryptography ])) ]; }
              ''
                mkdir $out
                python - <<'EOF'
                import datetime, hashlib, os
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import ed25519
                from cryptography.x509.oid import NameOID

                def make(name, not_after):
                    key = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(name.encode()).digest())
                    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
                    certificate = (
                        x509.CertificateBuilder()
                        .subject_name(subject)
                        .issuer_name(subject)
                        .public_key(key.public_key())
                        .serial_number(1)
                        .not_valid_before(datetime.datetime(2025, 1, 1))
                        .not_valid_after(not_after)
                        .sign(key, None)
                    )
                    with open(os.path.join(os.environ["out"], name + ".pem"), "wb") as file:
                        file.write(certificate.public_bytes(serialization.Encoding.PEM))

                make("first", datetime.datetime(2031, 3, 4, 12, 30, 45))
                make("second", datetime.datetime(2033, 5, 6, 12, 30, 45))
                make("late", datetime.datetime(2099, 6, 7, 12, 30, 45))
                make("never", datetime.datetime(9999, 12, 31, 23, 59, 59))
                EOF
              '';
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
          # `notes` declares none of `sso/miniflux`, `ddclient/api-token` and `hedgedoc/session-secret`, so their files are left over.
          leftoverManifests = pkgs.writeText "leftover-manifests.json" (
            builtins.toJSON (
              lib.mapAttrs (name: _: manifest name) example
              // {
                notes = manifest "notes" // {
                  secrets = removeAttrs (manifest "notes").secrets [
                    "sso/miniflux"
                    "ddclient/api-token"
                    "hedgedoc/session-secret"
                  ];
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
                  evaluates =
                    machine: secrets:
                    (builtins.tryEval (
                      builtins.deepSeq
                        (exampleFlake.nixosConfigurations.${machine}.extendModules {
                          modules = [ { sauce.secrets = secrets; } ];
                        }).config.sauce.manifest
                        true
                    )).success;
                in
                evaluates "notes" { "hedgedoc/db-password".maxLength = 48; }
                && !evaluates "notes" { "hedgedoc/db-password".maxLength = 47; }
                && evaluates "notes" { "hedgedoc/session-secret".maxLength = 43; }
                && !evaluates "notes" { "hedgedoc/session-secret".maxLength = 42; }
                # The key pair is 387 bytes, as `ED25519_BYTES` in `crates/sauce/src/make.rs`.
                && evaluates "backup" { "backup/ssh-key".maxLength = 387; }
                && !evaluates "backup" { "backup/ssh-key".maxLength = 386; }
                # A generator that mixes `max` and `bytes` is left to sauce, which refuses its shape.
                && evaluates "notes" {
                  "hedgedoc/db-password" = {
                    generator.bytes = 4;
                    maxLength = 1;
                  };
                };
              message = "maxLength next to a generator holds its longest value, max, the encoded length of bytes or the 387 bytes of an ssh-ed25519 key pair, or the evaluation fails.";
            }
            {
              ok =
                let
                  # The adminRecipients of the manifest of notes, or null when the evaluation fails.
                  emitted =
                    modules:
                    let
                      manifest = (exampleFlake.nixosConfigurations.notes.extendModules { inherit modules; }).config.sauce.manifest;
                      result = builtins.tryEval (builtins.deepSeq manifest manifest.adminRecipients);
                    in
                    if result.success then result.value else null;
                  admins = age: pgp: emitted [
                    {
                      sauce.adminRecipients.age = lib.mkForce age;
                      sauce.adminRecipients.pgp = lib.mkForce pgp;
                    }
                  ];
                  keeps = age: pgp: admins age pgp == { inherit age pgp; };
                  age = "age1kv6aj53yzlf5wyu32qnv39wh68apzgkqpv49c0g0zvh5fzpjqcyscym83z";
                  fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567";
                in
                keeps [ age ] [ fingerprint ]
                && keeps [ ] [ fingerprint ]
                && keeps [ "age1pq1abc" "age1yubikey1abc" ] [ ]
                && admins [ fingerprint ] [ ] == null
                && admins [ ] [ age ] == null
                && admins [ ] [ (lib.toLower fingerprint) ] == null
                && admins [ ] [ ] == null
                && emitted [ { sauce.adminRecipients = [ age ]; } ] == null;
              message = "Admin keys go by type in sauce.adminRecipients.age and .pgp, a key in the wrong list, both lists empty or the old flat list fails the evaluation, and post-quantum and plugin keys go in .age.";
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
          decrypt = cargoCheck "decrypt" [ (python pkgs) ] ''
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
                grep -E '^NAME +MACHINES +MADE BY +SET +EXPIRES +STATE$' $out
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
                printf '%s\n' \
                  'NAME                       MACHINES        MADE BY               SET  EXPIRES  STATE' \
                  'backup/ssh-key             backup,offsite  ssh-ed25519                         ✓' \
                  | cmp - <(head -n 2 without)
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
                        adminRecipients = { age = [ "${lib.head (manifest "backup").adminRecipients.age}" ]; pgp = []; };
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
                printf 'false\n' > broken.nix
                printf '"db"\n' > declaration.nix
                sauce list > short 2> /dev/null
                printf '%s\n' \
                  'NAME  MACHINES  MADE BY         SET  EXPIRES  STATE' \
                  'db    fixture   once hex, 16 B                ✗' \
                  | cmp - short

                # The flake of a dry run has an input that needs a lock file, which a run that removes writes and a dry run leaves out.
                mkdir "$TMPDIR/dep"
                printf '{ outputs = _: { }; }\n' > "$TMPDIR/dep/flake.nix"
                sed -i "s|outputs = { self }:|inputs.dep.url = \"path:$TMPDIR/dep\"; outputs = { self, ... }:|" flake.nix
                git add flake.nix
                cp "$TMPDIR/checkout/example/secrets/sso/miniflux.sauce.yaml" leftover.sauce.yaml
                sauce remove sso/miniflux --dry-run | grep -F leftover.sauce.yaml
                test ! -e flake.lock
                test -e leftover.sauce.yaml
                sauce remove sso/miniflux --yes
                test -e flake.lock
                test ! -e leftover.sauce.yaml
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

                # Each source of the admin key alone opens a file, and a source beats every source after it, in the order of sops.
                good=$PWD/$keys/admin.key
                wrong=$PWD/$keys/backup.key
                export HOME="$TMPDIR/home" XDG_CONFIG_HOME="$TMPDIR/config"
                mkdir -p "$HOME/.config/sops/age" "$XDG_CONFIG_HOME/sops/age"
                clear() { rm -f "$HOME/.config/sops/age/keys.txt" "$XDG_CONFIG_HOME/sops/age/keys.txt"; assign=(); }
                add() {
                  case $1 in
                    0) assign+=("SAUCE_IDENTITY=$2") ;;
                    1) assign+=("SOPS_AGE_KEY=$(cat "$2")") ;;
                    2) assign+=("SOPS_AGE_KEY_FILE=$2") ;;
                    3) assign+=("SOPS_AGE_KEY_CMD=cat $2") ;;
                    4) cp "$2" "$XDG_CONFIG_HOME/sops/age/keys.txt" ;;
                    5) cp "$2" "$HOME/.config/sops/age/keys.txt" ;;
                  esac
                }
                opens() { env "''${assign[@]}" sauce get hedgedoc/db-password --print $flags; }
                for i in 0 1 2 3 4 5; do
                  clear; add $i $good
                  [[ $(opens) == "$value" ]]
                  for j in 0 1 2 3 4 5; do
                    (( j > i )) || continue
                    clear; add $i $good; add $j $wrong
                    [[ $(opens) == "$value" ]]
                    clear; add $i $wrong; add $j $good
                    if opens; then
                      exit 1
                    fi
                  done
                done
                clear

                goodkey=$(grep AGE-SECRET-KEY $good)
                wrongkey=$(grep AGE-SECRET-KEY $wrong)
                [[ $(SOPS_AGE_KEY="$wrongkey $goodkey" sauce get hedgedoc/db-password --print $flags) == "$value" ]]
                [[ $(SOPS_AGE_KEY= SOPS_AGE_KEY_FILE=$good sauce get hedgedoc/db-password --print $flags) == "$value" ]]

                # An error names the source, and shows no key.
                bogus=AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
                for key in "$bogus" "$wrongkey"; do
                  if SOPS_AGE_KEY=$key sauce get hedgedoc/db-password --print $flags > out 2> error; then
                    exit 1
                  fi
                  grep -F SOPS_AGE_KEY error
                  if grep -F "$key" out error; then
                    exit 1
                  fi
                done

                # The command starts with no shell, shows its stderr, and its stdout stays out of the output.
                printf '#!/bin/sh\necho from-command >&2\ncat %s\nexit 3\n' "$good" > key-command
                chmod +x key-command
                if SOPS_AGE_KEY_CMD=$PWD/key-command sauce get hedgedoc/db-password --print $flags > out 2> error; then
                  exit 1
                fi
                grep -F from-command error
                grep -F SOPS_AGE_KEY_CMD error
                if grep -F "$goodkey" out error; then
                  exit 1
                fi
                if SOPS_AGE_KEY_CMD="cat $good; touch $PWD/shell-ran" sauce get hedgedoc/db-password --print $flags 2> error; then
                  exit 1
                fi
                grep -F SOPS_AGE_KEY_CMD error
                test ! -e shell-ran
                # The output is a good key and then more than 64 KiB of empty lines, so only the limit refuses it.
                cat > key-long <<EOF
                #!/bin/sh
                cat $good
                head -c 131072 /dev/zero | tr '\0' '\n'
                EOF
                chmod +x key-long
                if SOPS_AGE_KEY_CMD=$PWD/key-long sauce get hedgedoc/db-password --print $flags 2> error; then
                  exit 1
                fi
                grep -F SOPS_AGE_KEY_CMD error

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

                # A certificate gives its notAfter as the expiry date, from a UTCTime and from a GeneralizedTime, unless --expires is given.
                certs=${certificates}
                export SAUCE_IDENTITY=$keys/admin.key
                # The facts must open, so that an expiry that is missing is a fact and not a failed read.
                show() { facts=$(sauce get ddclient/api-token $longFlags); grep -q '^version: ' <<< "$facts"; }
                fact() { grep '^expires:' <<< "$facts" || true; }
                expect() { show; [[ $(fact) == "$1" ]]; }
                sauce set ddclient/api-token $longFlags < $certs/first.pem
                expect 'expires: 2031-03-04'
                sauce set ddclient/api-token $longFlags < $certs/late.pem
                expect 'expires: 2099-06-07'
                # The countdown is the days to the date, and the day may change between the two readings of the clock.
                first=$(( ( $(date -u -d 2099-06-07 +%s) - $(date -u -d "$(date -u +%F)" +%s) ) / 86400 ))
                listed=$(sauce list $longFlags | grep '^ddclient/api-token ')
                second=$(( ( $(date -u -d 2099-06-07 +%s) - $(date -u -d "$(date -u +%F)" +%s) ) / 86400 ))
                grep -E " in ($first|$second)d " <<< "$listed"
                cat $certs/first.pem $certs/second.pem | sauce set ddclient/api-token $longFlags
                expect 'expires: 2031-03-04'
                { printf -- '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n'; cat $certs/second.pem; } | sauce set ddclient/api-token $longFlags
                expect 'expires: 2033-05-06'
                sauce set ddclient/api-token $longFlags --expires 2040-01-02 < $certs/first.pem
                expect 'expires: 2040-01-02'
                printf 'plain text' | sauce set ddclient/api-token $longFlags
                expect ""
                printf -- '-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n' | sauce set ddclient/api-token $longFlags
                expect ""
                [[ $(sauce get ddclient/api-token --print $longFlags | head -n 1) == '-----BEGIN CERTIFICATE-----' ]]
                sauce set ddclient/api-token $longFlags < $certs/never.pem
                expect ""

                # An edit that saves a certificate takes its date, a certificate that never ends clears it, and other text keeps it.
                mkdir -m 700 /dev/shm/run
                export XDG_RUNTIME_DIR=/dev/shm/run
                printf 'cat %s > "$1"\n' $certs/second.pem > certificate-editor
                EDITOR="sh $PWD/certificate-editor" sauce edit ddclient/api-token $longFlags
                expect 'expires: 2033-05-06'
                echo 'printf changed > "$1"' > text-editor
                EDITOR="sh $PWD/text-editor" sauce edit ddclient/api-token $longFlags
                [[ $(sauce get ddclient/api-token --print $longFlags) == changed ]]
                expect 'expires: 2033-05-06'
                printf 'cat %s > "$1"\n' $certs/never.pem > never-editor
                EDITOR="sh $PWD/never-editor" sauce edit ddclient/api-token $longFlags
                expect ""
                touch $out
              '';
          readers =
            pkgs.runCommand "sauce-readers"
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
                wider="--manifest ${widerManifests}"
                export SAUCE_IDENTITY=example/snakeoil/admin.key
                files() { find example/secrets -type f | sort | xargs sha256sum; }
                sauce generate $flags
                printf token | sauce set ddclient/api-token $flags
                files > before

                if printf token | sauce set ddclient/api-token $wider 2> error; then exit 1; fi
                diff - error <<'EOF'
                These readers change. A key that gets access learns a value that exists:
                  offsite (age) age1gxja8jf28w6scdug3ncevhr929uht3qggyhuptedv7sghn52ug4sqzqgt8  gets 1
                    └─ ddclient/api-token
                error: reader changes not approved; no files changed, and --yes approves them with no terminal
                EOF
                diff before <(files)
                if script -qec "sauce set ddclient/api-token $wider" /dev/null <<< n > refused; then exit 1; fi
                grep -F 'Encrypt the value for these readers? [y/N]' refused
                diff before <(files)

                script -qec "sauce set ddclient/api-token $wider" /dev/null <<< $'y\ntoken' > approved
                grep -F 'set ddclient/api-token, version 2' approved
                [[ $(sauce get ddclient/api-token --print $wider --identity example/snakeoil/offsite.key) == token ]]

                printf token | sauce set ddclient/api-token --yes $flags 2> error > out
                diff - error <<'EOF'
                These readers change. A key that gets access learns a value that exists:
                  offsite (age) age1gxja8jf28w6scdug3ncevhr929uht3qggyhuptedv7sghn52ug4sqzqgt8  loses 1
                    └─ ddclient/api-token
                EOF
                grep -x 'ddclient/api-token is marked revoke, because the value is the same and a former reader knows it' out
                sauce get ddclient/api-token $flags | grep -x 'revoke: a former reader knows this value'

                script -qec "sauce set ddclient/api-token $wider" /dev/null <<< $'y\ntoken' > approved
                script -qec "sauce set ddclient/api-token $flags" /dev/null <<< $'y\nfresh' > approved
                if grep -F 'is marked revoke' approved; then exit 1; fi
                sauce get ddclient/api-token $flags > facts
                grep -x 'version: 5' facts
                if grep '^revoke:' facts; then exit 1; fi
                [[ $(sauce get ddclient/api-token --print $flags) == fresh ]]
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

                # Only the date changes, and every other fact and the value stay.
                soon=$(date -u -d '+90 days' +%F)
                sauce get ddclient/api-token $flags | grep -v '^expires:' > facts
                files > before
                if sauce expire ddclient/api-token $soon $flags --identity example/snakeoil/missing.key; then
                  exit 1
                fi
                diff before <(files)
                sauce get ddclient/api-token $flags | grep -x "expires: $lastyear"
                sauce expire ddclient/api-token $soon $flags
                sauce list $flags | grep -E '^ddclient/api-token .* in (89|90)d '
                sauce get ddclient/api-token $flags | grep -x "expires: $soon"
                sauce get ddclient/api-token $flags | grep -v '^expires:' | diff facts -
                [[ $(sauce get ddclient/api-token --print $flags) == token ]]
                sauce expire ddclient/api-token --clear $flags
                if sauce get ddclient/api-token $flags | grep '^expires:'; then
                  exit 1
                fi
                sauce get ddclient/api-token $flags | grep -v '^expires:' | diff facts -
                [[ $(sauce get ddclient/api-token --print $flags) == token ]]

                # A declaration that takes another padding step than the file stops the command, and `sauce generate` fixes that first.
                files > before
                if sauce expire hedgedoc/db-password 2030-01-01 --manifest ${boundManifests 253} 2> error; then
                  exit 1
                fi
                grep -F hedgedoc/db-password error
                diff before <(files)

                mkdir -m 700 /dev/shm/run
                export XDG_RUNTIME_DIR=/dev/shm/run
                echo 'printf edited-token > "$1"' > editor
                EDITOR="sh $PWD/editor" sauce edit ddclient/api-token $flags
                [[ $(sauce get ddclient/api-token --print $flags) == edited-token ]]
                sauce get ddclient/api-token $flags | grep -x 'note: API token for the DNS zone example.com, made in the dashboard of the DNS provider.'
                [[ -z $(ls /dev/shm/run) ]]

                # An inline key in the environment of sauce stays out of the editor that it starts.
                cat > editor-env <<'EOF'
                printf %s "''${SOPS_AGE_KEY-unset}" > seen
                printf edited-token > "$1"
                EOF
                SOPS_AGE_KEY=not-a-key EDITOR="sh $PWD/editor-env" sauce edit ddclient/api-token $flags
                [[ $(cat seen) == unset ]]

                files > before
                sauce generate --dry-run --manifest ${widerManifests} --identity example/snakeoil/missing.key </dev/null > preview
                grep -Fx 're-encrypted ddclient/api-token' preview
                diff before <(files)

                script -qec "sauce generate --manifest ${widerManifests}" /dev/null <<< y
                script -qec "sauce generate $flags" /dev/null <<< y
                printf edited-token | sauce set ddclient/api-token $flags | grep -x 'ddclient/api-token is marked revoke, because the value is the same and a former reader knows it'

                printf '%s\n' sso/hedgedoc sso/miniflux | diff - <(sauce search sso $flags)
                if copied=$(sauce get sso/hedgedoc --copy $flags); then
                  exit 1
                fi
                [[ -z $copied ]]

                leftover="--manifest ${leftoverManifests}"
                files > before
                if sauce remove restic/password --yes $flags 2> error; then
                  exit 1
                fi
                grep -F restic/password error
                grep -F notes error
                grep -F offsite error
                diff before <(files)
                sauce remove 'sso/*' --dry-run $leftover | tee preview
                grep -F example/secrets/sso/miniflux.sauce.yaml preview
                if grep -F hedgedoc.sauce.yaml preview; then
                  exit 1
                fi
                diff before <(files)

                # A file that changes while the question is open stops the removal there, and the error names it and every file removed before it.
                for name in ddclient/api-token hedgedoc/session-secret sso/miniflux; do
                  cp example/secrets/$name.sauce.yaml "$TMPDIR/$(basename $name).bak"
                done
                status=0
                {
                  if timeout 30 sh -c 'until grep -qF "Remove them?" asked; do sleep 0.1; done'; then
                    printf x > example/secrets/sso/miniflux.sauce.yaml
                    echo y
                  else
                    echo n
                  fi
                } | timeout 120 script -qec "sauce remove '*/*' $leftover" /dev/null > asked 2>&1 || status=$?
                [[ $status -eq 1 ]]
                test ! -e example/secrets/ddclient/api-token.sauce.yaml
                test ! -e example/secrets/hedgedoc/session-secret.sauce.yaml
                test -e example/secrets/sso/miniflux.sauce.yaml
                stopped=$(grep '^error:' asked)
                [[ $stopped != *'nothing was removed'* ]]
                at=''${stopped%%removed*}
                earlier=''${stopped#*removed}
                [[ $at == *example/secrets/sso/miniflux.sauce.yaml* && $at != *ddclient* && $at != *session-secret* ]]
                [[ $earlier == *example/secrets/ddclient/api-token.sauce.yaml* && $earlier == *example/secrets/hedgedoc/session-secret.sauce.yaml* ]]
                for name in ddclient/api-token hedgedoc/session-secret sso/miniflux; do
                  cp "$TMPDIR/$(basename $name).bak" example/secrets/$name.sauce.yaml
                done
                diff before <(files)
                if sauce remove ddclient/api-token $leftover < /dev/null 2> error; then
                  exit 1
                fi
                grep -F -- '--yes' error
                diff before <(files)
                if script -qec "sauce remove ddclient/api-token $leftover" /dev/null <<< n; then
                  exit 1
                fi
                diff before <(files)
                script -qec "sauce remove ddclient/api-token $leftover" /dev/null <<< y
                test ! -e example/secrets/ddclient/api-token.sauce.yaml
                sauce remove 'sso/*' --yes $leftover
                test ! -e example/secrets/sso/miniflux.sauce.yaml
                test -e example/secrets/sso/hedgedoc.sauce.yaml

                mkdir "$TMPDIR/outside"
                mv example/secrets/hedgedoc/session-secret.sauce.yaml "$TMPDIR/outside"
                ln -s "$TMPDIR/outside" example/secrets/hedgedoc/linked
                sum=$(sha256sum < "$TMPDIR/outside/session-secret.sauce.yaml")
                if sauce remove hedgedoc/session-secret --yes $leftover; then
                  exit 1
                fi
                [[ $(sha256sum < "$TMPDIR/outside/session-secret.sauce.yaml") == "$sum" ]]
                touch $out
              '';
          import =
            pkgs.runCommand "sauce-import"
              {
                nativeBuildInputs = [
                  self.packages.${pkgs.stdenv.hostPlatform.system}.sauce
                  pkgs.age
                  pkgs.jq
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

                # With maxLength = 64, a generated secret takes 64 bytes from sauce import and sauce set, refuses 65, and sauce rotate still makes 40 to 48 characters.
                boundFlags="--manifest ${boundManifests 64}"
                rm example/secrets/hedgedoc/db-password.sauce.yaml
                fits=$(head -c 64 /dev/zero | tr '\0' b)
                printf 'fits: %s\nlonger: %sb\n' "$fits" "$fits" > plain.yaml
                sops encrypt --age "$(age-keygen -y "$SOPS_AGE_KEY_FILE")" --input-type yaml --output-type yaml plain.yaml > bound.sops.yaml
                rm plain.yaml
                printf '{ "longer": "hedgedoc/db-password" }\n' > longer.json
                if sauce import bound.sops.yaml longer.json $boundFlags > out 2>&1; then
                  exit 1
                fi
                cat out
                grep -x 'refuse "longer": the value is longer than the bound of hedgedoc/db-password, 64 bytes' out
                printf '{ "fits": "hedgedoc/db-password" }\n' > fits.json
                sauce import bound.sops.yaml fits.json $boundFlags
                [[ $(sauce get hedgedoc/db-password --print $boundFlags --identity $admin) == "$fits" ]]
                if printf '%sc' "$fits" | sauce set hedgedoc/db-password $boundFlags --identity $admin; then
                  exit 1
                fi
                printf '%s' "$fits" | tr b c | sauce set hedgedoc/db-password $boundFlags --identity $admin
                [[ $(sauce get hedgedoc/db-password --print $boundFlags --identity $admin) == "$(printf '%s' "$fits" | tr b c)" ]]
                sauce rotate hedgedoc/db-password $boundFlags --identity $admin
                [[ $(sauce get hedgedoc/db-password --print $boundFlags --identity $admin) =~ ^[A-Za-z0-9]{40,48}$ ]]
                # The generator fact leaves maxLength out, so the declaration without it names the generator that made this value.
                sauce get hedgedoc/db-password $flags --identity $admin | grep -x 'made by: generator encoding=alphanum min=40 max=48'

                # A maxLength of 253 takes the 1 KiB step, and sauce generate and sauce rotate pad the value of the generator to it.
                wideFlags="--manifest ${boundManifests 253}"
                file=example/secrets/hedgedoc/db-password.sauce.yaml
                stored() { grep '^value: ' $file | cut -d' ' -f2 | base64 -d | wc -c; }
                [[ $(stored) -eq 272 ]]
                rm $file
                sauce generate $wideFlags
                [[ $(stored) -eq 1040 ]]
                sauce rotate hedgedoc/db-password $wideFlags --identity $admin
                [[ $(stored) -eq 1040 ]]
                [[ $(sauce get hedgedoc/db-password --print $wideFlags --identity $admin) =~ ^[A-Za-z0-9]{40,48}$ ]]

                # A bound in another step makes sauce generate encrypt the same value again, in the step of the bound, with no prompt.
                value=$(sauce get hedgedoc/db-password --print $wideFlags --identity $admin)
                sauce generate $flags --identity $admin < /dev/null > out
                cat out
                grep -x 're-encrypted hedgedoc/db-password' out
                [[ $(stored) -eq 272 ]]
                [[ $(sauce get hedgedoc/db-password --print $flags --identity $admin) == "$value" ]]

                # A stored value longer than the bound in the other step stops sauce generate, and the file stays as it is.
                head -c 200 /dev/zero | tr '\0' d | sauce set hedgedoc/db-password $wideFlags --identity $admin
                sum=$(sha256sum < $file)
                if sauce generate $flags --identity $admin < /dev/null > out 2>&1; then
                  exit 1
                fi
                cat out
                grep -xF 'error: hedgedoc/db-password has a value longer than its bound of 48 bytes, so sauce generate does not encrypt it again; give it a shorter value with `sauce set hedgedoc/db-password`, or raise its maxLength' out
                [[ $(sha256sum < $file) == "$sum" ]]

                # A --manifest file skips the evaluation, so sauce refuses a recipe longer than maxLength itself.
                jq '.notes.secrets."hedgedoc/db-password".maxLength = 47' ${manifests} > short.json
                if sauce generate --dry-run --manifest short.json < /dev/null > out 2>&1; then
                  exit 1
                fi
                cat out
                grep -F 'makes values of up to 48 bytes, more than its maxLength of 47' out

                # A --manifest file where one machine has no admin key stops the write, so no file opens only for hosts.
                jq '.notes.adminRecipients = { age: [], pgp: [] }' ${manifests} > noadmin.json
                rm example/secrets/ddclient/api-token.sauce.yaml
                if printf token | sauce set ddclient/api-token --manifest noadmin.json > out 2>&1; then
                  exit 1
                fi
                cat out
                grep -x 'error: notes: sauce.adminRecipients.age and sauce.adminRecipients.pgp are both empty, and every secret needs the key of an admin' out
                test ! -e example/secrets/ddclient/api-token.sauce.yaml

                # A certificate in a sops file gets its notAfter as the expiry date.
                longFlags="--manifest ${longManifests}"
                { printf 'certificate: |\n'; sed 's/^/  /' ${certificates}/first.pem; } > plain.yaml
                sops encrypt --age "$(age-keygen -y "$SOPS_AGE_KEY_FILE")" --input-type yaml --output-type yaml plain.yaml > cert.sops.yaml
                rm plain.yaml
                printf '{ "certificate": "ddclient/api-token" }\n' > cert.json
                sauce import cert.sops.yaml cert.json $longFlags
                [[ $(sauce get ddclient/api-token $longFlags --identity $admin | grep '^expires:') == 'expires: 2031-03-04' ]]
                touch $out
              '';
          symlink =
            pkgs.runCommand "sauce-symlink"
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
                export SAUCE_IDENTITY=example/snakeoil/admin.key
                sauce generate $flags

                # The folder sso is a link to a folder outside the checkout, where sso/miniflux has a file and sso/hedgedoc has none.
                mv example/secrets/sso "$TMPDIR/elsewhere"
                rm "$TMPDIR/elsewhere/hedgedoc.sauce.yaml"
                ln -s "$TMPDIR/elsewhere" example/secrets/sso
                files() { find "$TMPDIR/elsewhere" -type f | sort | xargs sha256sum; }
                files > before
                refused() {
                  cat out
                  grep -x "$1the folder .*/example/secrets/sso of $2 is a symbolic link" out
                }

                age-keygen -o "$TMPDIR/sops.key" 2> /dev/null
                export SOPS_AGE_KEY_FILE="$TMPDIR/sops.key"
                printf 'hedgedoc: imported-value\nminiflux: imported-value\n' > plain.yaml
                sops encrypt --age "$(age-keygen -y "$SOPS_AGE_KEY_FILE")" --input-type yaml --output-type yaml plain.yaml > secrets.sops.yaml
                rm plain.yaml
                printf '{ "hedgedoc": "sso/hedgedoc", "miniflux": "sso/miniflux" }\n' > import.json
                for dry in --dry-run ""; do
                  if sauce import secrets.sops.yaml import.json $dry $flags > out 2>&1; then
                    exit 1
                  fi
                  refused 'refuse "hedgedoc": ' sso/hedgedoc
                  refused 'refuse "miniflux": ' sso/miniflux
                done

                if printf new-value | sauce set sso/hedgedoc $flags > out 2>&1; then
                  exit 1
                fi
                refused 'error: ' sso/hedgedoc
                if printf new-value | sauce set sso/miniflux $flags > out 2>&1; then
                  exit 1
                fi
                refused 'error: ' sso/miniflux

                export XDG_RUNTIME_DIR=$(mktemp -d -p /dev/shm)
                echo 'printf edited-value > "$1"' > editor
                if EDITOR="sh $PWD/editor" sauce edit sso/miniflux $flags > out 2>&1; then
                  exit 1
                fi
                refused 'error: ' sso/miniflux

                if sauce rotate sso/miniflux $flags > out 2>&1; then
                  exit 1
                fi
                refused 'error: ' sso/miniflux

                # sso/hedgedoc comes first, and generate would make its file.
                if sauce generate $flags > out 2>&1; then
                  exit 1
                fi
                refused 'error: ' sso/hedgedoc

                files | diff before -
                touch $out
              '';
          completion =
            pkgs.runCommand "sauce-completion"
              {
                nativeBuildInputs = [
                  self.packages.${pkgs.stdenv.hostPlatform.system}.sauce
                  pkgs.jq
                  pkgs.gitMinimal
                  pkgs.nix
                  pkgs.zsh
                  pkgs.fish
                ];
              }
              ''
                export HOME="$TMPDIR/home" XDG_CACHE_HOME="$TMPDIR/cache"
                mkdir -p "$HOME" bin
                # A nix on PATH that records each run and fails, so the check sees that a completion never starts it.
                printf '#!/bin/sh\necho "$*" >> %s\nexit 1\n' "$TMPDIR/nix-runs" > bin/nix
                chmod +x bin/nix
                export PATH="$PWD/bin:$PATH"

                mkdir checkout
                cp -r ${self}/example checkout/
                chmod -R u+w checkout
                cd checkout

                # The installed script registers the completion of bash under the name sauce.
                # The builtin complete of an interactive bash only registers the function, which the check calls by hand, so a no-op stands in for it.
                complete() { :; }
                source ${self.packages.${pkgs.stdenv.hostPlatform.system}.sauce}/share/bash-completion/completions/sauce
                candidates() {
                  COMP_WORDS=("$@")
                  COMP_CWORD=$(( $# - 1 ))
                  COMP_TYPE=9
                  COMPREPLY=()
                  _clap_complete_sauce sauce "''${COMP_WORDS[COMP_CWORD]}" 2> /dev/null
                  printf '%s\n' "''${COMPREPLY[@]}"
                }

                # A normal command ignores COMPLETE, which other programs set.
                [[ $(COMPLETE=bash sauce list --manifest ${manifests} 2> /dev/null | wc -l) -eq 9 ]]

                # With no file and no saved evaluation there is no name, and the flags and the commands still complete.
                [[ -z $(candidates sauce get h) ]]
                candidates sauce get --pr | grep -x -- '--print'
                candidates sauce ed | grep -x edit

                # A real evaluation by `sauce list` saves the declared names, and a later completion reads them with no file on disk and no nix.
                mkdir "$TMPDIR/evaluated"
                (
                  cd "$TMPDIR/evaluated"
                  git init -q
                  cat > flake.nix <<'EOF'
                {
                  outputs = { self }: {
                    nixosConfigurations.fixture = {
                      options.sauce = {};
                      config.sauce.manifest = {
                        recipient = "${(manifest "backup").recipient}";
                        adminRecipients = { age = [ "${lib.head (manifest "backup").adminRecipients.age}" ]; pgp = []; };
                        secrets = {
                          "hedgedoc/db-password".file = "secrets/hedgedoc/db-password.sauce.yaml";
                          "hedgedoc/session-secret".file = "secrets/hedgedoc/session-secret.sauce.yaml";
                          "sso/hedgedoc".file = "secrets/sso/hedgedoc.sauce.yaml";
                          "sso/miniflux".file = "secrets/sso/miniflux.sauce.yaml";
                        };
                        read = [];
                      };
                    };
                  };
                }
                EOF
                  git add flake.nix
                  NIX_REMOTE="local?root=$TMPDIR/manifest-store" NIX_CONFIG="experimental-features = nix-command flakes" \
                    PATH="${pkgs.nix}/bin:$PATH" sauce list > /dev/null 2>&1
                  ls "$XDG_CACHE_HOME"/sauce/*.json
                  printf '%s\n' hedgedoc/db-password hedgedoc/session-secret | diff - <(candidates sauce get hedgedoc/)
                  printf '%s\n' hedgedoc/ | diff - <(candidates sauce get h)
                  printf '%s\n' sso/ 'sso/\*' | diff - <(candidates sauce edit s)
                  printf '%s\n' 'sso/\*' sso/hedgedoc sso/miniflux | diff - <(candidates sauce rotate sso/)
                  printf '%s\n' "'sso/hedgedoc" "'sso/miniflux" | diff - <(candidates sauce rotate "'sso/")
                  # A secret that is only declared has no file to remove.
                  [[ -z $(candidates sauce remove s) ]]
                )
                rm -r "$XDG_CACHE_HOME/sauce"
                key=$(printf %s "$(pwd -P)" | sha256sum | cut -d' ' -f1)

                # The .sauce.yaml files on disk give their names with no saved evaluation.
                sauce generate --manifest ${manifests} > /dev/null
                printf '%s\n' hedgedoc/db-password hedgedoc/session-secret | diff - <(candidates sauce get hedgedoc/)
                printf '%s\n' sso/ 'sso/\*' | diff - <(candidates sauce remove s)
                printf '%s\n' backup/ssh-key | diff - <(candidates sauce expire backup/)
                printf '%s\n' restic/password | diff - <(candidates sauce set restic/)
                # Bash keeps an open quote in the candidate, and zsh and fish get the name with no quote, which they match and insert themselves.
                printf '%s\n' '"sso/hedgedoc' | diff - <(candidates sauce get '"sso/h')
                # Inside a quote bash gets full names, because readline closes the quote after a folder that it takes for a finished word.
                printf '%s\n' '"hedgedoc/db-password' '"hedgedoc/session-secret' | diff - <(candidates sauce get '"hed')
                [[ $(_CLAP_IFS=$'\n' _CLAP_COMPLETE_INDEX=2 SAUCE_COMPLETE=zsh sauce -- sauce get '"sso/h') == sso/hedgedoc ]]

                # A file that no machine declares is offered to remove, next to declared files that are not, once the saved evaluation says what is declared.
                mkdir example/secrets/old
                sed 's|^name: .*|name: old/thing|' example/secrets/sso/hedgedoc.sauce.yaml > example/secrets/old/thing.sauce.yaml
                mkdir -p -m 700 "$XDG_CACHE_HOME/sauce"
                jq '{ key: "unchecked", machines: . }' ${manifests} > "$XDG_CACHE_HOME/sauce/$key.json"
                chmod 600 "$XDG_CACHE_HOME/sauce/$key.json"
                printf '%s\n' old/ 'old/\*' | diff - <(candidates sauce remove o)
                [[ -z $(candidates sauce remove s) ]]
                # A declared file stays declared when its secret was renamed, so its old name in the file is not offered either.
                sed -i 's|^name: .*|name: renamed/x|' example/secrets/sso/hedgedoc.sauce.yaml
                [[ -z $(candidates sauce remove r) ]]
                # The same from a folder inside the source root, which a .git marks, where the saved evaluation keeps each path relative to that root.
                mkdir .git
                (
                  cd example
                  inner=$(printf %s "$(pwd -P)" | sha256sum | cut -d' ' -f1)
                  jq '{ key: "unchecked", machines: . }' ${manifests} > "$XDG_CACHE_HOME/sauce/$inner.json"
                  chmod 600 "$XDG_CACHE_HOME/sauce/$inner.json"
                  [[ -z $(candidates sauce remove r) ]]
                  # The walk starts at the source root, so a leftover outside this folder is offered, and remove --dry-run accepts the name that completion gives.
                  mkdir ../other
                  sed 's|^name: .*|name: stray/one|' secrets/sso/miniflux.sauce.yaml > ../other/one.sauce.yaml
                  printf '%s\n' stray/ 'stray/\*' | diff - <(candidates sauce remove st)
                  printf '%s\n' stray/one | diff - <(candidates sauce remove stray/ | grep -v '\\\*')
                  sauce remove stray/one --dry-run --manifest ${manifests} | grep -F one.sauce.yaml
                )
                rm -r "$XDG_CACHE_HOME/sauce"

                # zsh runs the completer on the first Tab, from the file that its fpath gives, and fish reads its script, and both get the pattern with no backslash.
                zsh -f -c '
                  fpath=(${self.packages.${pkgs.stdenv.hostPlatform.system}.sauce}/share/zsh/site-functions $fpath)
                  autoload -Uz _sauce
                  compdef() { :; }
                  _describe() { print -rl -- "''${(P@)3}"; }
                  words=(sauce edit s)
                  CURRENT=3
                  _sauce
                ' > zsh-out
                printf '%s\n' sso stray 'sso/*' 'stray/*' | diff - zsh-out
                fish -c 'source ${self.packages.${pkgs.stdenv.hostPlatform.system}.sauce}/share/fish/vendor_completions.d/sauce.fish; complete -C "sauce edit s"' > fish-out
                grep -Fx 'sso/*' fish-out

                test ! -e "$TMPDIR/nix-runs"
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
                  (python pkgs)
                ];
              }
              ''
                export HOME="$TMPDIR/home" GNUPGHOME="$TMPDIR/gnupg"
                mkdir -p "$HOME"
                mkdir -m 700 "$GNUPGHOME"
                # A gpg on PATH that records each run, so the check sees which commands start gpg.
                # It also records the name of each variable for an age private key that gpg gets, so the check sees none reach it.
                mkdir bin
                printf '#!/bin/sh\necho "$*" >> %s\nenv | grep -oE "^(SOPS_AGE_KEY|SOPS_AGE_KEY_FILE|SOPS_AGE_KEY_CMD|SAUCE_IDENTITY)=" >> %s\nexec %s "$@"\n' "$TMPDIR/runs" "$TMPDIR/keys" ${pkgs.gnupg}/bin/gpg > bin/gpg
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
                jq --arg key "$fingerprint" 'map_values(.adminRecipients.pgp += [$key])' ${manifests} > gpg.json
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
                [[ $(SAUCE_IDENTITY=$admin SOPS_AGE_KEY_FILE="$TMPDIR/sops.key" SOPS_AGE_KEY_CMD="cat $admin" sauce get hedgedoc/db-password --print $flags) == "$value" ]]
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

                # A subkey fingerprint, as in .sops.yaml, writes a file that gpg alone opens, with a wrap for that subkey alone.
                gpg --batch --passphrase "" --quick-add-key "$fingerprint" cv25519 encr never
                subkey=$(gpg --with-colons --list-keys throwaway | awk -F: '/^sub/ { seen = 1; next } seen && /^fpr/ { print $10; exit }')
                jq --arg key "$subkey" 'map_values(.adminRecipients.pgp += [$key])' ${manifests} > subkey.json
                subflags="--manifest subkey.json"
                subfile=example/secrets/ddclient/api-token.sauce.yaml
                printf subkey-token | sauce set ddclient/api-token --yes $subflags --identity $admin
                grep -x "    pgp: $subkey" $subfile
                if grep -x "    pgp: $fingerprint" $subfile; then
                  exit 1
                fi
                [[ $(sauce get ddclient/api-token --print $subflags) == subkey-token ]]

                # A list and a status count the subkey fingerprint as the reader that the manifests declare, and the files of the primary fingerprint as another reader.
                sauce status $subflags --identity $admin > status
                if grep -E '^ddclient/api-token ' status; then
                  exit 1
                fi
                grep -E '^backup/ssh-key +has other readers' status
                sauce list $subflags --identity $admin > list
                grep -E '^ddclient/api-token .* ✓$' list
                # gpg lists the session key packet and then exits 2 on the encrypted data, which it cannot parse without the key.
                packets=$(python -c 'import base64, sys; from pathlib import Path; s = Path(sys.argv[1]).read_text(); i = s.index("    pgp: " + sys.argv[2]); i = s.index("    wrap: ", i) + len("    wrap: "); w = s[i:s.index("\n", i)]; sys.stdout.buffer.write(base64.b64decode(w + "=" * (-len(w) % 4)))' $subfile "$subkey" | gpg --list-packets 2> /dev/null || true)
                grep -F "keyid $(printf %s "$subkey" | cut -c25-40)" <<< "$packets"

                # The subkey can also be listed as an additional decryption subkey of another certificate, and the file still opens.
                gpg --batch --passphrase "" --quick-add-adsk "$other" "$subkey"
                [[ $(sauce get ddclient/api-token --print $subflags) == subkey-token ]]

                # A read of a subkey fingerprint accepts a wrap for that subkey only, and not one for another subkey of the certificate.
                second=$(gpg --with-colons --list-keys throwaway | awk -F: '/^sub/ { seen = 1; next } seen && /^fpr/ { last = $10; seen = 0 } END { print last }')
                [[ $second != "$subkey" ]]
                hostile=$(head -c 16 /dev/urandom | gpg --no-options --batch --trust-model always --compress-algo none --no-literal --recipient "$second!" --encrypt | base64 -w 0 | tr -d =)
                python -c 'import sys; from pathlib import Path; p = Path(sys.argv[1]); s = p.read_text(); i = s.index("    pgp: " + sys.argv[2]); i = s.index("    wrap: ", i) + len("    wrap: "); j = s.index("\n", i); p.write_text(s[:i] + sys.argv[3] + s[j:])' $subfile "$subkey" "$hostile"
                if sauce get ddclient/api-token --print $subflags 2> stderr; then
                  exit 1
                fi
                grep -F "the wrap is not for one encryption key of $subkey" stderr

                # A fingerprint that is not in the keyring gets its own error.
                absent=0123456789ABCDEF0123456789ABCDEF01234567
                jq --arg key "$absent" 'map_values(.adminRecipients.pgp += [$key])' ${manifests} > absent.json
                if printf token | sauce set ddclient/api-token --yes --manifest absent.json --identity $admin 2> stderr; then
                  exit 1
                fi
                grep -F "$absent is not in the keyring of gpg; import the public key with \`gpg --import\`" stderr

                # A subkey that gpg refuses names the primary key to use, because gpg encrypts to that subkey alone.
                gpg --batch --passphrase "" --quick-add-key "$fingerprint" cv25519 encr never
                expired=$(gpg --with-colons --list-keys throwaway | awk -F: '/^sub/ { seen = 1; next } seen && /^fpr/ { last = $10; seen = 0 } END { print last }')
                gpg --batch --passphrase "" --quick-set-expire "$fingerprint" seconds=1 "$expired"
                sleep 2
                jq --arg key "$expired" 'map_values(.adminRecipients.pgp += [$key])' ${manifests} > expired.json
                if printf token | sauce set ddclient/api-token --yes --manifest expired.json --identity $admin 2> stderr; then
                  exit 1
                fi
                grep -F "$expired is a subkey, so gpg encrypts to that subkey alone" stderr
                grep -F "check that $fingerprint is its primary key" stderr
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
