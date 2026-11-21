{ config, ... }:
{
  sauce.secrets."restic/password".once = {
    encoding = "alphanum";
    min = 40;
    max = 48;
  };

  services.postgresqlBackup.enable = true;

  services.restic.backups.db = {
    repository = "/var/backup/restic";
    passwordFile = config.sauce.secrets."restic/password".path;
    paths = [ "/var/backup/postgresql" ];
    initialize = true;
  };
}
