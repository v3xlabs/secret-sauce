{ config, ... }:
let
  inherit (config.sauce) placeholder;
in
{
  sauce.secrets."hedgedoc/db-password" = {
    generator = {
      encoding = "alphanum";
      min = 40;
      max = 48;
    };
    # PostgreSQL reads the file, and HedgeDoc gets the value through the template below.
    owner = "postgres";
    mode = "0400";
    restartUnits = [ "postgresql-setup.service" ];
  };

  sauce.secrets."hedgedoc/session-secret".generator = {
    encoding = "base64url";
    bytes = 32;
  };

  sso.clients.hedgedoc = {
    displayName = "HedgeDoc";
    originUrl = "https://notes.example.com/auth/oauth2/callback";
    originLanding = "https://notes.example.com";
  };

  sauce.templates.hedgedoc-env = {
    restartUnits = [ "hedgedoc.service" ];
    content = ''
      CMD_DB_URL=postgres://hedgedoc:${placeholder."hedgedoc/db-password"}@localhost/hedgedoc
      CMD_OAUTH2_CLIENT_SECRET=${placeholder."sso/hedgedoc"}
      CMD_SESSION_SECRET=${placeholder."hedgedoc/session-secret"}
    '';
  };

  services.hedgedoc = {
    enable = true;
    settings = {
      domain = "notes.example.com";
      protocolUseSSL = true;
      oauth2 = {
        providerName = "Kanidm";
        clientID = "hedgedoc";
        authorizationURL = "https://auth.example.com/ui/oauth2";
        tokenURL = "https://auth.example.com/oauth2/token";
        userProfileURL = "https://auth.example.com/oauth2/openid/hedgedoc/userinfo";
        userProfileUsernameAttr = "preferred_username";
        userProfileDisplayNameAttr = "name";
        userProfileEmailAttr = "email";
        scope = "openid email profile";
        pkce = true;
      };
    };
    environmentFile = config.sauce.templates.hedgedoc-env.path;
  };
}
