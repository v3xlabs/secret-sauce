{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    sauce.url = "github:v3xlabs/secret-sauce";
    sauce.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      sauce,
    }:
    let
      machine =
        name:
        nixpkgs.lib.nixosSystem {
          specialArgs = { inherit self; };
          modules = [
            sauce.nixosModules.default
            ./machines/${name}.nix
            {
              networking.hostName = name;
              nixpkgs.hostPlatform = "x86_64-linux";
              system.stateVersion = "26.05";

              sauce = {
                adminRecipients = [ "age19g68xd9k8k9xfgl9e0sklxy3h5wm9l8yzj4jyd6t726u46yztcfqsv8fxg" ];
                identityFile = "/var/lib/sauce/host.key";
                defaultDir = ./secrets;
              };
            }
          ];
        };
    in
    {
      nixosModules = import ./services;

      nixosConfigurations = nixpkgs.lib.genAttrs [
        "notes"
        "backup"
        "offsite"
      ] machine;
    };
}
