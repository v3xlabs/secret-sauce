{
  config,
  lib,
  pkgs,
  ...
}:
let
  cert = config.security.acme.certs."auth.example.com".directory;
in
{
  options.sso.clients = lib.mkOption {
    type = lib.types.attrsOf (lib.types.attrsOf lib.types.str);
    default = { };
  };

  config = {
    sauce.secrets = {
      "kanidm/idm-admin-password" = {
        generator = {
          encoding = "alphanum";
          min = 40;
          max = 48;
        };
        owner = "kanidm";
      };
    }
    // lib.mapAttrs' (
      name: _:
      lib.nameValuePair "sso/${name}" {
        generator = {
          encoding = "alphanum";
          min = 40;
          max = 48;
        };
        owner = "kanidm";
        restartUnits = [ "kanidm.service" ];
      }
    ) config.sso.clients;

    services.kanidm = {
      package = pkgs.kanidmWithSecretProvisioning_1_12;
      server.enable = true;
      server.settings = {
        domain = "auth.example.com";
        origin = "https://auth.example.com";
        bindaddress = "[::]:443";
        tls_chain = "${cert}/fullchain.pem";
        tls_key = "${cert}/key.pem";
      };
      provision = {
        enable = true;
        idmAdminPasswordFile = config.sauce.secrets."kanidm/idm-admin-password".path;
        systems.oauth2 = lib.mapAttrs (
          name: client:
          client
          // {
            basicSecretFile = config.sauce.secrets."sso/${name}".path;
            scopeMaps.idm_all_persons = [
              "openid"
              "email"
              "profile"
            ];
          }
        ) config.sso.clients;
      };
    };

    security.acme = {
      acceptTerms = true;
      defaults.email = "admin@example.com";
      certs."auth.example.com" = {
        listenHTTP = ":80";
        group = "kanidm";
        reloadServices = [ "kanidm.service" ];
      };
    };
  };
}
