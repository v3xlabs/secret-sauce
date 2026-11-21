{
  pkgs,
  sauce,
  example,
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

  files = sealed machines.notes values;
  changed = "${sealed machines.notes { "sso/hedgedoc" = changedValue; }}/sso/hedgedoc.sauce.yaml";
  wrongKey = "${sealed machines.backup { "sso/hedgedoc" = wrongKeyValue; }}/sso/hedgedoc.sauce.yaml";
in
pkgs.testers.runNixOSTest {
  name = "sauce-install";
  node.specialArgs.self = example;

  nodes.notes =
    { lib, ... }:
    {
      imports = [
        sauce.nixosModules.default
        ../example/machines/notes.nix
      ];

      sauce = {
        adminRecipients = [ "age1kv6aj53yzlf5wyu32qnv39wh68apzgkqpv49c0g0zvh5fzpjqcyscym83z" ];
        identityFile = "${../example/snakeoil/notes.key}";
        defaultDir = files;
      };
      # The public half of the key pair of backup does not exist until `sauce generate` runs.
      users.users.root.openssh.authorizedKeys.keyFiles = lib.mkForce [ ];
      virtualisation.memorySize = 2048;
      # The VM has no network, so an ACME order fails and makes every switch fail.
      systemd.services."acme-order-renew-auth.example.com".enable = false;
      systemd.timers."acme-renew-auth.example.com".enable = false;

      specialisation.changed.configuration.sauce.secrets."sso/hedgedoc".file = lib.mkForce changed;
      specialisation.wrong-key.configuration.sauce.secrets."sso/hedgedoc".file = lib.mkForce wrongKey;
      specialisation.for-users.configuration.sauce.secrets."ddclient/api-token".neededForUsers = true;
    };

  testScript =
    { nodes, ... }:
    let
      system = nodes.notes.system.build.toplevel;
      closure = pkgs.closureInfo { rootPaths = [ system ]; };
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
          notes.succeed("printf '%s\\n' ${
            lib.escapeShellArgs (
              lib.attrValues values
              ++ [
                changedValue
                wrongKeyValue
              ]
            )
          } > /tmp/values")
          notes.fail("xargs grep -rlFf /tmp/values < ${closure}/store-paths")

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
    '';
}
