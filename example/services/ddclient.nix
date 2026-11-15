{ config, ... }:
{
  sauce.secrets."ddclient/api-token".note =
    "API token for the DNS zone example.com, made in the dashboard of the DNS provider.";

  services.ddclient = {
    enable = true;
    protocol = "cloudflare";
    zone = "example.com";
    domains = [ "notes.example.com" ];
    passwordFile = config.sauce.secrets."ddclient/api-token".path;
  };
}
