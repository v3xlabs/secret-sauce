{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.sauce;
  users = config.users.users;

  optional =
    type: description:
    mkOption {
      type = types.nullOr type;
      default = null;
      inherit description;
    };

  # A Nix path, a store path or a string with store context each make the store hold the key or keep it as a dependency.
  keyPath = types.addCheck types.externalPath (
    path: !builtins.hasContext path && !lib.hasPrefix "${builtins.storeDir}/" path
  );

  textRecipeOptions = {
    encoding = optional types.str "The encoding of the value: `alphanum`, `hex`, `base64`, `base64url` or `digits`.";
    min = optional types.ints.positive "The least number of random characters.";
    max = optional types.ints.positive "The largest number of random characters.";
    bytes = optional types.ints.positive "The fixed number of random bytes before `hex`, `base64` or `base64url` encoding, instead of `min` and `max`.";
  };

  generator = types.submodule {
    options = textRecipeOptions // {
      keypair = optional types.str "The type of a key pair, such as `ssh-ed25519`.";
    };
  };

  once = types.submodule { options = textRecipeOptions; };

  delivery = own: path: {
    owner = mkOption {
      type = types.str;
      default = "root";
      description = "The owner of the file on the machine.";
    };
    group = mkOption {
      type = types.str;
      default = users.${own.owner}.group;
      defaultText = lib.literalExpression "config.users.users.\${owner}.group";
      description = "The group of the file on the machine.";
    };
    mode = mkOption {
      type = types.str;
      default = "0400";
      description = "The mode of the file on the machine, in octal.";
    };
    restartUnits = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "The units that restart when the file changes.";
    };
    reloadUnits = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "The units that reload when the file changes.";
    };
    path = mkOption {
      type = types.str;
      readOnly = true;
      default = path;
      description = "Where the file is on the machine.";
    };
  };

  secret = types.submodule (
    { name, config, ... }:
    {
      options = {
        generator = optional generator "How `sauce` makes the value, and makes it again on `sauce rotate`.";
        once = optional once "How `sauce` makes the value one time.";
        maxLength = optional (types.ints.between 1 65532) "The maximum length in bytes of the value, which sets its padding step. With `generator` or `once` it must hold the longest value that they make.";
        note = optional types.str "Text that `sauce` shows next to the secret.";
        file = optional types.path "The `.sauce.yaml` file of the secret.";
        neededForUsers = mkOption {
          type = types.bool;
          default = false;
          description = "Install the secret before NixOS makes users and groups, for example for `users.users.<name>.hashedPasswordFile`.";
        };
      }
      // delivery config (
        if config.neededForUsers then "/run/sauce-for-users/${name}" else "/run/sauce/${name}"
      );
    }
  );

  template = types.submodule (
    { name, config, ... }:
    {
      options = {
        content = mkOption {
          type = types.str;
          description = "The text of the file, with `sauce.placeholder.<name>` where a value goes.";
        };
      }
      // delivery config "/run/sauce/rendered/${name}";
    }
  );

  sauceFile =
    name: secret:
    if secret.file != null then
      if builtins.match ".+\\.sauce\\.yaml" (baseNameOf (toString secret.file)) != null then
        secret.file
      else
        throw "sauce.secrets.\"${name}\" sets `file` to ${toString secret.file}, which must end in .sauce.yaml."
    else if cfg.defaultDir != null then
      cfg.defaultDir + "/${name}.sauce.yaml"
    else
      null;

  # A path in a flake evaluates to /nix/store/<hash>-source/<path from the root of the flake source>.
  inSource = "${lib.escapeRegex builtins.storeDir}/[^/]+/(.+)";

  fileOf =
    name: secret:
    let
      declared =
        if sauceFile name secret != null then
          sauceFile name secret
        else
          throw "sauce.secrets.\"${name}\" has no file, and sauce.defaultDir is not set.";
      # A string such as "${self}/secrets/../x.sauce.yaml" keeps its `..`, and adding it to `/.` removes it as Nix does for a path.
      file = toString (/. + builtins.unsafeDiscardStringContext (toString declared));
      relative = builtins.match inSource file;
    in
    if relative == null then
      throw "sauce.secrets.\"${name}\" has the file ${file}, which is not in the source of a flake. Evaluate the machine from its flake, and give the file as a path such as ./${name}.sauce.yaml."
    else
      lib.head relative;

  present = lib.filterAttrs (_: value: value != null);

  # The longest value of a `generator` or `once` in bytes, as `sauce` makes it, or null for a shape that `sauce` refuses.
  longestOf =
    recipe:
    let
      text = [
        "alphanum"
        "hex"
        "base64"
        "base64url"
        "digits"
      ];
      bits =
        if recipe.encoding == null then
          null
        else
          {
            hex = 4;
            base64 = 6;
            base64url = 6;
          }
          .${recipe.encoding} or null;
      characters = (recipe.bytes * 8 + bits - 1) / bits;
    in
    if (recipe.keypair or null) != null then
      # `ED25519_BYTES` in `crates/sauce/src/make.rs`.
      if
        recipe.keypair == "ssh-ed25519"
        && recipe.encoding == null
        && recipe.min == null
        && recipe.max == null
        && recipe.bytes == null
      then
        387
      else
        null
    else if
      recipe.min != null
      && recipe.max != null
      && recipe.bytes == null
      && recipe.min <= recipe.max
      && lib.elem recipe.encoding text
    then
      recipe.max
    else if recipe.min == null && recipe.max == null && recipe.bytes != null && bits != null then
      if recipe.encoding == "base64" then (characters + 3) / 4 * 4 else characters
    else
      null;

  defines =
    name: secret:
    !(lib.elem name cfg.read)
    || lib.any (field: secret.${field} != null) [
      "generator"
      "once"
      "maxLength"
      "note"
      "file"
    ];

  manifestOf =
    name: secret:
    let
      recipe = if secret.generator != null then secret.generator else secret.once;
      longest = if recipe == null then null else longestOf recipe;
    in
    if secret.generator != null && secret.once != null then
      throw "sauce.secrets.\"${name}\" sets both generator and once, and a secret can have one of them or neither."
    else if secret.maxLength != null && longest != null && longest > secret.maxLength then
      throw "sauce.secrets.\"${name}\" makes values of up to ${toString longest} bytes, more than its maxLength of ${toString secret.maxLength}."
    else
      present {
        file = fileOf name secret;
        generator = if secret.generator == null then null else present secret.generator;
        once = if secret.once == null then null else present secret.once;
        inherit (secret) maxLength note;
      };

  forUsers = lib.filterAttrs (_: secret: secret.neededForUsers) cfg.secrets;
  regular = lib.filterAttrs (_: secret: !secret.neededForUsers) cfg.secrets;

  hostKeys = import ./host-keys.nix config.services.openssh;

  withTools = script: ''
    (
      # An activation script runs without errexit, so without this a failed mount goes on to write plaintext onto /run.
      set -e
      PATH=${
        lib.makeBinPath [
          pkgs.util-linux
          config.systemd.package
        ]
      }:$PATH
      ${script}
    )
  '';

  install =
    link: secrets: templates:
    let
      deliveryOf = name: own: {
        inherit name;
        inherit (own)
          owner
          group
          mode
          restartUnits
          reloadUnits
          ;
      };
      storeFile =
        name: secret:
        let
          file = sauceFile name secret;
        in
        # A missing path becomes null, so that the evaluation reaches the assertion of the missing file, and not a Nix error about the path.
        # A file given as a string, such as a store path, is not checked here, and sauce-install stops on it at activation.
        if file == null || (lib.isPath file && !builtins.pathExists file) then null else "${file}";
      json = pkgs.writeText "sauce-install.json" (
        builtins.toJSON {
          inherit (cfg) identityFile;
          inherit (cfg.age) sshKeyPaths;
          inherit link;
          mountPoint = "${link}.d";
          secrets = lib.mapAttrsToList (
            name: secret:
            deliveryOf name secret
            // {
              file = storeFile name secret;
              placeholder = cfg.placeholder.${name};
            }
          ) secrets;
          templates = lib.mapAttrsToList (
            name: template: deliveryOf name template // { inherit (template) content; }
          ) templates;
        }
      );
    in
    withTools ''
      mkdir -p ${link}.d
      fstype=$(findmnt -n -o FSTYPE --mountpoint ${link}.d || true)
      case "$fstype" in
        "") mount -t tmpfs -o size=16m,noswap,nodev,nosuid,noexec,mode=0751 none ${link}.d ;;
        tmpfs) ;;
        ramfs) echo "reboot to move ${link}.d to a tmpfs" >&2; exit 1 ;;
        *) echo "${link}.d is a mount of $fstype, and sauce-install needs a tmpfs there" >&2; exit 1 ;;
      esac
      # A core dump of sauce-install would hold the values it decrypted; systemd-coredump also stores none at a limit of zero.
      ulimit -c 0
      ${pkgs.callPackage ./sauce-install.nix { }}/bin/sauce-install ${json}
    '';

  # A service can still hold an old file open, so a plain umount can fail, and --lazy takes away every path to the old files at once.
  remove =
    link:
    withTools ''
      if mountpoint -q ${link}.d; then
        case "$(readlink ${link})" in
          ${link}.d/*)
            umount --lazy ${link}.d
            rm ${link}
            rmdir ${link}.d
            ;;
        esac
      fi
    '';
in
{
  options.sauce = {
    secrets = mkOption {
      type = types.attrsOf secret;
      default = { };
      description = "The secrets of this machine, by name.";
    };

    read = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Names of secrets that a module on another machine defines and this machine reads.";
    };

    templates = mkOption {
      type = types.attrsOf template;
      default = { };
      description = "Files made from secrets and plain text, by name.";
    };

    placeholder = mkOption {
      type = types.attrsOf types.str;
      readOnly = true;
      description = "The text that stands for a secret in `content` of a template, by name.";
    };

    defaultDir = optional types.path "The directory of the `.sauce.yaml` file of each secret that has no `file`.";

    recipient = mkOption {
      type = types.str;
      description = "The public key of this machine, as an `age1...` recipient or as the `ssh-ed25519 AAAA...` line of its ssh public key, which `sauce` converts to the `age1...` recipient that `ssh-to-age` prints for it.";
    };

    adminRecipients = {
      age = mkOption {
        type = types.listOf (types.strMatching "age1[a-z0-9]+");
        default = [ ];
        description = "Your own age recipients, which read every secret of this machine. Every kind of age recipient starts with `age1` and goes here.";
      };
      pgp = mkOption {
        type = types.listOf (types.strMatching "[0-9A-F]{40}");
        default = [ ];
        description = "The fingerprints of your own GPG keys, as 40 upper case hex characters, which read every secret of this machine. A fingerprint is the one of a primary key or of a subkey, as in `.sops.yaml`.";
      };
    };

    identityFile = optional types.str "The path of the age identity of this machine, on the machine, as `age-keygen` writes it. `sauce-install` opens a file with this key or with a key of `age.sshKeyPaths`.";

    age.sshKeyPaths = mkOption {
      type = types.listOf keyPath;
      default = hostKeys.paths;
      defaultText = lib.literalMD "The ed25519 keys of {option}`services.openssh.hostKeys`, when openssh is enabled";
      description = "The paths of ssh keys of this machine, on the machine, as in `sops.age.sshKeyPaths` of sops-nix. `sauce-install` converts each ed25519 key to an age identity in memory, so a file for the `age1...` recipient that `ssh-to-age` prints from its public key opens. It skips a key that it cannot read or that is not an ed25519 key, with a warning that names the path. A path is a string outside the Nix store with no store context, as for `identityFile`.";
    };

    manifest = mkOption {
      type = types.raw;
      readOnly = true;
      description = "The JSON value that `sauce generate` reads for this machine.";
    };
  };

  config = {
    sauce = {
      secrets = lib.genAttrs cfg.read (_: { });

      placeholder = lib.mapAttrs (
        name: _: "<SAUCE:${builtins.hashString "sha256" name}:PLACEHOLDER>"
      ) cfg.secrets;

      manifest = {
        inherit (cfg) recipient;
        adminRecipients =
          if cfg.adminRecipients.age == [ ] && cfg.adminRecipients.pgp == [ ] then
            throw "sauce.adminRecipients.age and sauce.adminRecipients.pgp are both empty, and every secret needs the key of an admin."
          else
            cfg.adminRecipients;
        secrets = lib.mapAttrs manifestOf (lib.filterAttrs defines cfg.secrets);
        read = lib.attrNames (lib.filterAttrs (name: secret: !defines name secret) cfg.secrets);
      };
    };

    inherit (hostKeys) warnings;

    assertions =
      lib.mapAttrsToList (name: secret: {
        assertion = secret.owner == "root" && secret.group == "root";
        message = "sauce.secrets.\"${name}\" sets neededForUsers, so its owner and group must be root, because no other user exists yet.";
      }) forUsers
      ++ lib.mapAttrsToList (
        name: secret:
        let
          file = sauceFile name secret;
          relative = builtins.match inSource (toString file);
        in
        if file == null then
          {
            assertion = false;
            message =
              "sauce.secrets.\"${name}\" has no file, because it sets no `file` and sauce.defaultDir is not set. "
              + (
                if defines name secret then
                  "Set sauce.defaultDir, or `file` of the secret."
                else
                  "Set sauce.defaultDir to the folder of the .sauce.yaml files, because this machine only reads the secret."
              );
          }
        else
          {
            assertion = !(lib.isPath file && !builtins.pathExists file);
            message = "sauce.secrets.\"${name}\" has no file at ${
              if relative == null then toString file else lib.head relative
            }. Run `sauce generate`, or `sauce set ${name}` for a secret that you bring yourself, and then `git add` the file, because a flake in git does not see a file that git does not track.";
          }
      ) cfg.secrets
      ++ lib.mapAttrsToList (name: _: {
        assertion = builtins.match "[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*" name != null;
        message = "sauce.templates.\"${name}\" has a name that sauce-install refuses. A name is segments of `a-z`, `0-9`, `.`, `_` and `-` that start with `a-z` or `0-9` and that a `/` separates.";
      }) cfg.templates
      ++ [
        {
          assertion =
            cfg.secrets == { } && cfg.templates == { }
            || lib.versionAtLeast config.boot.kernelPackages.kernel.version "6.4";
          message = "sauce keeps secrets on a tmpfs with noswap, which needs Linux 6.4 or later, and this machine boots Linux ${config.boot.kernelPackages.kernel.version}. Set boot.kernelPackages to a newer kernel.";
        }
        {
          assertion =
            cfg.secrets == { } && cfg.templates == { } || cfg.identityFile != null || cfg.age.sshKeyPaths != [ ];
          message = "This machine has no key for sauce-install, because sauce.identityFile is not set and sauce.age.sshKeyPaths is empty. Set one of them, or enable services.openssh, which puts its ed25519 host key in sauce.age.sshKeyPaths.";
        }
      ];

    systemd.services.sauce-install = lib.mkIf (regular != { } || cfg.templates != { }) {
      description = "Install the secrets of sauce";
      wantedBy = [ "sysinit.target" ];
      requiredBy = [ "sysinit-reactivation.target" ];
      after = [ "local-fs.target" ];
      before = [
        "sysinit.target"
        "sysinit-reactivation.target"
        "shutdown.target"
      ];
      conflicts = [ "shutdown.target" ];
      unitConfig = {
        DefaultDependencies = false;
        RequiresMountsFor = lib.optional (cfg.identityFile != null) cfg.identityFile;
        # A key of sshKeyPaths that cannot be read is skipped, so its mount must not stop the run.
        WantsMountsFor = cfg.age.sshKeyPaths;
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = install "/run/sauce" regular cfg.templates;
    };

    system.activationScripts = lib.mkMerge [
      {
        sauceForUsers = lib.stringAfter [ "specialfs" ] (
          if forUsers == { } then
            remove "/run/sauce-for-users"
          else
            install "/run/sauce-for-users" forUsers { }
        );
      }
      (lib.mkIf (forUsers != { }) { users.deps = [ "sauceForUsers" ]; })
      (lib.mkIf (regular == { } && cfg.templates == { }) {
        sauce = lib.stringAfter [ "specialfs" ] (remove "/run/sauce");
      })
    ];
  };
}
