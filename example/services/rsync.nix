{ config, pkgs, ... }:
{
  sauce.secrets."backup/ssh-key".generator.keypair = "ssh-ed25519";

  systemd.services.pull-notes-backup = {
    startAt = "daily";
    path = [
      pkgs.rsync
      pkgs.openssh
    ];
    script = ''
      rsync -a -e "ssh -i ${config.sauce.secrets."backup/ssh-key".path}" \
        root@notes.example.com:/var/backup/restic/ /srv/backup/notes/
    '';
  };
}
