{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Your own flake has github:v3xlabs/secret-sauce here.
    # This example takes the checkout around it, so that it runs the sauce of the same commit.
    sauce.url = "path:..";
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
                adminRecipients.age = [ "age1kv6aj53yzlf5wyu32qnv39wh68apzgkqpv49c0g0zvh5fzpjqcyscym83z" ];
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
