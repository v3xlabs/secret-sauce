{ self, ... }:
{
  imports = [ self.nixosModules.rsync ];

  sauce.recipient = "age1dkp38aa5nu2ngfsyfwsut5lza4msl0wgutsumrmcc5zglcf4s5aqeqrgzj";
}
