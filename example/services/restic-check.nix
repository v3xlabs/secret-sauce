{ config, pkgs, ... }:
{
  sauce.read = [ "restic/password" ];

  systemd.services.restic-check = {
    startAt = "weekly";
    path = [ pkgs.restic ];
    script = ''
      restic check --repo /srv/backup/notes --password-file ${config.sauce.secrets."restic/password".path}
    '';
  };
}
