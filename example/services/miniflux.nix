{ config, ... }:
let
  inherit (config.sauce) placeholder;
in
{
  sso.clients.miniflux = {
    displayName = "Miniflux";
    originUrl = "https://rss.example.com/oauth2/oidc/callback";
    originLanding = "https://rss.example.com";
  };

  sauce.templates.miniflux-env = {
    restartUnits = [ "miniflux.service" ];
    content = ''
      OAUTH2_CLIENT_SECRET=${placeholder."sso/miniflux"}
    '';
  };

  services.miniflux = {
    enable = true;
    config = {
      CREATE_ADMIN = false;
      OAUTH2_PROVIDER = "oidc";
      OAUTH2_CLIENT_ID = "miniflux";
      OAUTH2_REDIRECT_URL = "https://rss.example.com/oauth2/oidc/callback";
      OAUTH2_OIDC_DISCOVERY_ENDPOINT = "https://auth.example.com/oauth2/openid/miniflux";
      OAUTH2_USER_CREATION = 1;
    };
  };

  systemd.services.miniflux.serviceConfig.EnvironmentFile = config.sauce.templates.miniflux-env.path;
}
