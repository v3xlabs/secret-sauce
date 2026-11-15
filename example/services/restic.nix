{ config, ... }:
{
  sauce.secrets."restic/password".once = {
    encoding = "hex";
    bytes = 32;
  };

  services.postgresqlBackup.enable = true;

  services.restic.backups.db = {
    repository = "/var/backup/restic";
    passwordFile = config.sauce.secrets."restic/password".path;
    paths = [ "/var/backup/postgresql" ];
    initialize = true;
  };
}
