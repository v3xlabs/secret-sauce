{ self, ... }:
{
  imports = [ self.nixosModules.rsync ];

  sauce.recipient = "age1994ulldhymntg08vsp0ugv3m96mf4jxlc2sldhnkdm0uw5awfaesdjesqc";
}
