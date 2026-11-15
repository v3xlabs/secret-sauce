{ self, ... }:
{
  imports = [
    self.nixosModules.rsync
    self.nixosModules.restic-check
  ];

  sauce.recipient = "age1yz00um34yzkharmcm53s33c59x2tkjqw22wdkw36xkevh70l8ytsfp6un8";
}
