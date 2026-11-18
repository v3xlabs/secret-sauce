{
  lib,
  runCommand,
  writeText,
  sauce,
}:
# A directory with one `<name>.sauce.yaml` file for each name in `values`, that only `machine` and the admins open.
machine: values:
let
  host = machine.networking.hostName;
  manifests = writeText "manifests.json" (
    builtins.toJSON {
      ${host} = {
        inherit (machine.sauce) recipient adminRecipients;
        read = [ ];
        secrets = lib.mapAttrs (name: _: { file = "${name}.sauce.yaml"; }) values;
      };
    }
  );
in
runCommand "sauce-files-${host}" { nativeBuildInputs = [ sauce ]; } (
  ''
    mkdir $out
    cd $out
  ''
  + lib.concatMapAttrsStringSep "\n" (name: value: ''
    printf %s ${lib.escapeShellArg value} | sauce set ${name} --manifest ${manifests}
  '') values
)
