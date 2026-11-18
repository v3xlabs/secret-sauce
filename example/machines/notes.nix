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

  sauce.recipient = "age1jlamuy0qf6z0mgnw0epd8j9p678gdr8ca45nnsmvrslffujcwg9s05xze5";
}
