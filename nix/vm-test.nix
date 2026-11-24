{
  pkgs,
  sauce,
  sealed,
  machines,
}:
let
  inherit (pkgs) lib;

  # Each value is made from its name, so the test knows it and can look for it in the store.
  values = lib.genAttrs [
    "ddclient/api-token"
    "hedgedoc/db-password"
    "hedgedoc/session-secret"
    "kanidm/idm-admin-password"
    "restic/password"
    "sso/hedgedoc"
    "sso/miniflux"
  ] (name: "value-of-${builtins.replaceStrings [ "/" ] [ "-" ] name}");
  changedValue = "changed-value-of-sso-hedgedoc";
  wrongKeyValue = "wrong-key-value-of-sso-hedgedoc";

  # One value for each secret of notes, so a secret that notes adds or drops fails the evaluation here.
  files =
    assert lib.assertMsg (
      lib.attrNames values == lib.attrNames machines.notes.sauce.secrets
    ) "The values of nix/vm-test.nix are not the secrets of the notes machine of example/.";
    sealed machines.notes values;
  changed = "${sealed machines.notes { "sso/hedgedoc" = changedValue; }}/sso/hedgedoc.sauce.yaml";
  wrongKey = "${sealed machines.backup { "sso/hedgedoc" = wrongKeyValue; }}/sso/hedgedoc.sauce.yaml";

  # Throwaway ssh host keys of the machine `host`, which the store holds, so they are for this test only.
  hostKeys = pkgs.runCommand "sauce-vm-host-keys" { nativeBuildInputs = [ pkgs.openssh ]; } ''
    mkdir $out
    ssh-keygen -q -t ed25519 -N "" -C root@host -f $out/ed25519
    ssh-keygen -q -t ed25519 -N "" -C root@host -f $out/other
    ssh-keygen -q -t rsa -b 2048 -N "" -C root@host -f $out/rsa
  '';
  hostValues = {
    "host/for-age" = "value-of-host-for-age";
    "host/for-ssh" = "value-of-host-for-ssh";
  };
  hostManifest =
    name:
    pkgs.writeText "manifests.json" (
      builtins.toJSON {
        host = {
          inherit (machines.notes.sauce.manifest) adminRecipients;
          read = [ ];
          secrets.${name}.file = "${name}.sauce.yaml";
        };
      }
    );
  # One file for the `age1...` that ssh-to-age prints from the public key, as sops-nix users have it, and one for the `ssh-ed25519` line, which sauce converts.
  # ssh-to-age reads the public key only.
  hostFiles =
    pkgs.runCommand "sauce-files-host"
      {
        nativeBuildInputs = [
          sauce.packages.${pkgs.stdenv.hostPlatform.system}.sauce
          pkgs.jq
          pkgs.ssh-to-age
        ];
      }
      ''
        age=$(ssh-to-age -i ${hostKeys}/ed25519.pub)
        jq --arg recipient "$age" '.host.recipient = $recipient' ${hostManifest "host/for-age"} > $TMPDIR/for-age.json
        jq --rawfile recipient ${hostKeys}/ed25519.pub '.host.recipient = $recipient' ${hostManifest "host/for-ssh"} > $TMPDIR/for-ssh.json
        mkdir $out
        cd $out
        printf %s ${hostValues."host/for-age"} | sauce set host/for-age --manifest $TMPDIR/for-age.json
        printf %s ${hostValues."host/for-ssh"} | sauce set host/for-ssh --manifest $TMPDIR/for-ssh.json
        grep -Fx "    age: $age" host/for-age.sauce.yaml
        grep -Fx "    age: $age" host/for-ssh.sauce.yaml
      '';
in
pkgs.testers.runNixOSTest {
  name = "sauce-install";

  nodes.notes =
    { config, lib, ... }:
    let
      notes = machines.notes.sauce;
      delivery = [
        "owner"
        "group"
        "mode"
        "restartUnits"
        "reloadUnits"
      ];
      delivered = lib.attrValues notes.secrets ++ lib.attrValues notes.templates;
      units = lib.unique (
        map (lib.removeSuffix ".service") (lib.concatMap (own: own.restartUnits ++ own.reloadUnits) delivered)
      );
      owners = lib.remove "root" (lib.unique (map (own: own.owner) delivered));
      groups = lib.remove "root" (lib.unique (map (own: own.group) delivered));
    in
    {
      imports = [ sauce.nixosModules.default ];

      sauce = {
        inherit (notes) recipient adminRecipients;
        identityFile = "${../example/snakeoil/notes.key}";
        defaultDir = files;
        secrets = lib.mapAttrs (
          _: secret: lib.getAttrs delivery secret // { neededForUsers = lib.mkDefault secret.neededForUsers; }
        ) notes.secrets;
        templates = lib.mapAttrs (
          _: template: lib.getAttrs (delivery ++ [ "content" ]) template
        ) notes.templates;
      };

      # The owners and groups of the files, which the services of notes make.
      users = {
        users = lib.genAttrs owners (name: {
          isSystemUser = true;
          inherit (machines.notes.users.users.${name}) group;
        });
        groups = lib.genAttrs groups (_: { });
      };

      # sauce-install fails on a unit that does not exist, so each unit that a file restarts has a stand-in.
      # A stand-in reads the templates that restart it at start, as the real unit does.
      systemd.services = lib.genAttrs units (unit: {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "exec";
          ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
          EnvironmentFile = lib.mapAttrsToList (name: _: config.sauce.templates.${name}.path) (
            lib.filterAttrs (_: template: lib.elem "${unit}.service" template.restartUnits) notes.templates
          );
        };
      });

      virtualisation.cores = 2;

      # So that sauce.age.sshKeyPaths takes its default, the ed25519 host key, next to identityFile.
      services.openssh.enable = true;

      specialisation.changed.configuration.sauce.secrets."sso/hedgedoc".file = lib.mkForce changed;
      specialisation.wrong-key.configuration.sauce.secrets."sso/hedgedoc".file = lib.mkForce wrongKey;
      specialisation.for-users.configuration.sauce.secrets."ddclient/api-token".neededForUsers = true;
    };

  nodes.host = {
    imports = [ sauce.nixosModules.default ];

    services.openssh.enable = true;
    # The host keys are there before the first boot, as on a machine where sshd ran before, and sshd keeps a key that is there.
    environment.etc = {
      "ssh/ssh_host_ed25519_key" = {
        source = "${hostKeys}/ed25519";
        mode = "0600";
      };
      "ssh/ssh_host_rsa_key" = {
        source = "${hostKeys}/rsa";
        mode = "0600";
      };
      # A usable ed25519 key that is a reader of no file, so the files open only if sauce-install goes on to the next key.
      "ssh/other_ed25519_key" = {
        source = "${hostKeys}/other";
        mode = "0600";
      };
    };

    sauce = {
      age.sshKeyPaths = [
        "/etc/ssh/ssh_host_rsa_key"
        "/etc/ssh/other_ed25519_key"
        "/etc/ssh/ssh_host_ed25519_key"
      ];
      secrets = lib.mapAttrs (name: _: { file = "${hostFiles}/${name}.sauce.yaml"; }) hostValues;
    };
  };

  testScript =
    { nodes, ... }:
    let
      system = nodes.notes.system.build.toplevel;
      closure = pkgs.closureInfo { rootPaths = [ system ]; };
      # A search of the whole store closure takes about a minute on emulation, and a derivation finds the same files in seconds.
      storeCheck =
        pkgs.runCommand "sauce-vm-store-check"
          {
            toplevel = system;
            values = lib.concatMapStringsSep "\n" lib.id (
              lib.attrValues values
              ++ [
                changedValue
                wrongKeyValue
              ]
            );
            passAsFile = [ "values" ];
          }
          ''
            paths=$(cat ${closure}/store-paths)
            grep -rlFf "$valuesPath" $paths > hits || test $? -eq 1
            if [[ -s hits ]]; then
              cat hits
              exit 1
            fi
            echo "searched $(wc -l < ${closure}/store-paths) store paths of the machine for $(grep -c . "$valuesPath") values, and found none" > $out
          '';
    in
    ''
      def stat(path):
          return notes.succeed(f"stat -L -c '%U %G %a' {path}").strip()

      def read(path):
          return notes.succeed(f"cat {path}")

      notes.wait_for_unit("sauce-install.service")

      with subtest("a secret and a template have their owner, mode and value"):
          fstype, options = notes.succeed("findmnt -n -o FSTYPE,OPTIONS /run/sauce.d").split()
          assert fstype == "tmpfs", fstype
          assert {"size=16384k", "noswap"} <= set(options.split(",")), options
          assert stat("/run/sauce/hedgedoc/db-password") == "postgres postgres 400"
          assert read("/run/sauce/hedgedoc/db-password") == "${values."hedgedoc/db-password"}"
          assert stat("/run/sauce/rendered/hedgedoc-env") == "root root 400"
          env = read("/run/sauce/rendered/hedgedoc-env")
          assert "hedgedoc:${values."hedgedoc/db-password"}@localhost" in env, env
          assert "CMD_OAUTH2_CLIENT_SECRET=${values."sso/hedgedoc"}" in env, env
          assert "CMD_SESSION_SECRET=${values."hedgedoc/session-secret"}" in env, env

      with subtest("no value is in the Nix store of the machine"):
          print(open("${storeCheck}").read())

      with subtest("a changed secret restarts the units of its template"):
          notes.wait_for_unit("hedgedoc.service")
          before = notes.succeed("systemctl show -P InvocationID hedgedoc.service")
          notes.succeed("${system}/specialisation/changed/bin/switch-to-configuration test")
          assert read("/run/sauce/sso/hedgedoc") == "${changedValue}"
          notes.wait_for_unit("hedgedoc.service")
          assert notes.succeed("systemctl show -P InvocationID hedgedoc.service") != before

      with subtest("a file that the key of the machine cannot open fails the activation and keeps the secrets"):
          notes.fail("${system}/specialisation/wrong-key/bin/switch-to-configuration test")
          notes.succeed("systemctl is-failed sauce-install.service")
          notes.succeed("journalctl -u sauce-install.service | grep -F 'sauce.secrets.\"sso/hedgedoc\"'")
          assert read("/run/sauce/sso/hedgedoc") == "${changedValue}"
          assert read("/run/sauce/hedgedoc/db-password") == "${values."hedgedoc/db-password"}"

      with subtest("a machine with no secret for users left keeps no file for users"):
          notes.succeed("${system}/specialisation/for-users/bin/switch-to-configuration test")
          assert read("/run/sauce-for-users/ddclient/api-token") == "${values."ddclient/api-token"}"
          notes.succeed("${system}/bin/switch-to-configuration test")
          notes.fail("findmnt /run/sauce-for-users.d")
          notes.fail("ls -d /run/sauce-for-users /run/sauce-for-users.d")

      with subtest("a failed mount stops the install of the secrets for users"):
          mount_max = notes.succeed("sysctl -n fs.mount-max").strip()
          mounts = notes.succeed("wc -l < /proc/self/mountinfo").strip()
          notes.succeed(f"sysctl fs.mount-max={mounts}")
          notes.fail("${system}/specialisation/for-users/bin/switch-to-configuration test")
          notes.succeed(f"sysctl fs.mount-max={mount_max}")
          notes.fail("ls /run/sauce-for-users")
          notes.succeed("rmdir /run/sauce-for-users.d")

      with subtest("a full tmpfs fails the activation and keeps the secrets"):
          notes.execute("dd if=/dev/zero of=/run/sauce.d/filler bs=1M")
          notes.fail("${system}/specialisation/changed/bin/switch-to-configuration test")
          notes.succeed("journalctl -u sauce-install.service | grep -F '/run/sauce.d is full'")
          assert read("/run/sauce/sso/hedgedoc") == "${values."sso/hedgedoc"}"
          notes.succeed("rm /run/sauce.d/filler")

      with subtest("a crash of sauce-install leaves no core dump"):
          # systemd sets fs.suid_dumpable to 2, which only applies to a process that the kernel marks dumpable for root, so it does not undo PR_SET_DUMPABLE.
          assert notes.succeed("sysctl -n fs.suid_dumpable").strip() == "2"
          # A crashed sleep shows that systemd-coredump keeps the dump of a process that allows one.
          sleep = notes.succeed("sleep 100 > /dev/null 2>&1 & echo $!").strip()
          notes.succeed(f"kill -SEGV {sleep}")
          notes.wait_until_succeeds("coredumpctl --no-pager list sleep")
          # The config is a FIFO with no writer, so sauce-install waits there after it turned off its dumps.
          # It runs as nobody, because /proc/<pid> of a process that is not dumpable belongs to root.
          notes.succeed("mkfifo -m 666 /tmp/config")
          pid = notes.succeed(
              "setpriv --reuid=nobody --regid=nogroup --clear-groups "
              "${pkgs.callPackage ./sauce-install.nix { }}/bin/sauce-install /tmp/config < /dev/null > /dev/null 2>&1 & echo $!"
          ).strip()
          notes.wait_until_succeeds(f"grep -E '^Max core file size +0 +0 ' /proc/{pid}/limits")
          assert notes.succeed(f"stat -c %U /proc/{pid}/status").strip() == "root"
          # Rust catches the first SIGSEGV for its stack guard, and SIGABRT dumps core at once.
          notes.succeed(f"kill -ABRT {pid}")
          # The shell of the test reaps it late, so a zombie counts as gone, and the kernel runs any core handler before that.
          notes.wait_until_succeeds(f"! test -e /proc/{pid} || grep -q '^State:.*zombie' /proc/{pid}/status", timeout=60)
          # A second crashed sleep marks a point in the journal after any handler of the first crash has logged.
          marker = notes.succeed("sleep 100 > /dev/null 2>&1 & echo $!").strip()
          notes.succeed(f"kill -SEGV {marker}")
          notes.wait_until_succeeds(f"journalctl -t systemd-coredump --no-pager | grep -F 'Process {marker} (sleep)'")
          notes.fail(f"journalctl -t systemd-coredump --no-pager | grep -F 'Process {pid} '")
          notes.fail("coredumpctl --no-pager list sauce-install")

      with subtest("a machine with only ssh host keys opens files for the recipient of ssh-to-age and for its ssh-ed25519 line, with the second usable key"):
          host.wait_for_unit("sauce-install.service")
          # The journal can hold back lines of a unit that just ended, so it is written out before any check of it.
          host.succeed("journalctl --sync")
          assert host.succeed("cat /run/sauce/host/for-age") == "${hostValues."host/for-age"}"
          assert host.succeed("cat /run/sauce/host/for-ssh") == "${hostValues."host/for-ssh"}"
          host.succeed("journalctl -u sauce-install.service | grep -F 'cannot use /etc/ssh/ssh_host_rsa_key, because it is a key of type ssh-rsa'")
          # grep exits 1 for no match and 2 for an error, so only 1 passes, and -q keeps the key lines out of the log of the test.
          # The shell of the test stops at the first failing command, so the status is kept before the test of it.
          host.succeed("journalctl -b -o cat > /tmp/journal && test -s /tmp/journal")
          host.succeed("status=0; grep -q -e AGE-SECRET-KEY -e 'PRIVATE KEY' /tmp/journal || status=$?; test $status -eq 1")
          host.succeed("grep -h -v -e ----- /etc/ssh/ssh_host_ed25519_key /etc/ssh/other_ed25519_key /etc/ssh/ssh_host_rsa_key > /tmp/key-lines && test -s /tmp/key-lines")
          host.succeed("status=0; grep -q -F -f /tmp/key-lines /tmp/journal || status=$?; test $status -eq 1")
    '';
}
