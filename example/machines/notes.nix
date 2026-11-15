{ self, ... }:
{
  imports = [
    self.nixosModules.hedgedoc
    self.nixosModules.postgresql
    self.nixosModules.kanidm
    self.nixosModules.miniflux
    self.nixosModules.restic
    self.nixosModules.ddclient
    self.nixosModules.openssh
  ];

  sauce.recipient = "age1k3jp7hs9alfvd6v4dw5tnyvc62ww9dlehjfa7eukxwgatx9t042swx2d2f";
}
