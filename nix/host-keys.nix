# The default of `sauce.age.sshKeyPaths` for the `services.openssh` config of a machine, with the sops-nix rule: its ed25519 host keys when openssh is enabled.
# `warnings` names each ed25519 key that it leaves out, because its path is not one that `sauce.age.sshKeyPaths` takes: an absolute string outside the Nix store with no store context.
openssh:
let
  startsWith = prefix: path: builtins.substring 0 (builtins.stringLength prefix) path == prefix;
  # A Nix path, or a string with store context, copies the key into the store as soon as anything reads it as a string, so those are tested before any string operation.
  usable =
    key:
    builtins.isString key.path
    && !builtins.hasContext key.path
    && startsWith "/" key.path
    && !startsWith "${builtins.storeDir}/" key.path;
  # A key that sauce delivers cannot open the files that deliver it, as sops-nix leaves out /run/secrets.
  inSauce =
    path:
    builtins.any (dir: startsWith dir path) [
      "/run/sauce/"
      "/run/sauce.d/"
      "/run/sauce-for-users/"
      "/run/sauce-for-users.d/"
    ];
  keys = if openssh.enable || openssh.generateHostKeys then openssh.hostKeys else [ ];
  ed25519 = builtins.filter (entry: (entry.key.type or null) == "ed25519") (
    builtins.genList (index: {
      position = index + 1;
      key = builtins.elemAt keys index;
    }) (builtins.length keys)
  );
in
{
  paths = map (entry: entry.key.path) (
    builtins.filter (entry: usable entry.key && !inSauce entry.key.path) ed25519
  );
  # A refused path is named by its position and never printed, because a key pasted where its path belongs would then show in the output of every build.
  warnings = map (
    entry:
    "services.openssh.hostKeys entry ${toString entry.position} is an ed25519 key whose path is not an absolute path outside the Nix store given as a plain string, so sauce.age.sshKeyPaths leaves it out. Give its path on the machine as a plain string."
  ) (builtins.filter (entry: !usable entry.key) ed25519);
}
