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
        maxLength = optional (types.ints.between 1 65532) "The maximum length in bytes of a value you bring yourself.";
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
    if secret.generator != null && secret.once != null then
      throw "sauce.secrets.\"${name}\" sets both generator and once, and a secret can have one of them or neither."
    else if secret.maxLength != null && (secret.generator != null || secret.once != null) then
      throw "sauce.secrets.\"${name}\" sets maxLength with generator or once, and maxLength is for a value you bring yourself."
    else
      present {
        file = fileOf name secret;
        generator = if secret.generator == null then null else present secret.generator;
        once = if secret.once == null then null else present secret.once;
        inherit (secret) maxLength note;
      };

  forUsers = lib.filterAttrs (_: secret: secret.neededForUsers) cfg.secrets;
  regular = lib.filterAttrs (_: secret: !secret.neededForUsers) cfg.secrets;

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
      description = "The public key of this machine.";
    };

    adminRecipients = mkOption {
      type = types.nonEmptyListOf types.str;
      description = "Your own public keys: age recipients, and the fingerprints of GPG keys as 40 upper case hex characters.";
    };

    identityFile = mkOption {
      type = types.str;
      description = "The path of the private key of this machine, on the machine.";
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
        inherit (cfg) recipient adminRecipients;
        secrets = lib.mapAttrs manifestOf (lib.filterAttrs defines cfg.secrets);
        read = lib.attrNames (lib.filterAttrs (name: secret: !defines name secret) cfg.secrets);
      };
    };

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
        RequiresMountsFor = [ cfg.identityFile ];
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
