{ self, ... }:
{
  imports = [
    self.nixosModules.rsync
    self.nixosModules.restic-check
  ];

  sauce.recipient = "age1gxja8jf28w6scdug3ncevhr929uht3qggyhuptedv7sghn52ug4sqzqgt8";
}
