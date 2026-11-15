{ config, ... }:
{
  services.postgresql = {
    enable = true;
    ensureDatabases = [ "hedgedoc" ];
    ensureUsers = [
      {
        name = "hedgedoc";
        ensureDBOwnership = true;
      }
    ];
  };

  # psql reads the file itself, so the password stays out of the process list.
  systemd.services.postgresql-setup.postStart = ''
    psql <<'EOF'
    \set password `cat ${config.sauce.secrets."hedgedoc/db-password".path}`
    ALTER ROLE hedgedoc PASSWORD :'password';
    EOF
  '';
}
