{
  services.openssh.enable = true;

  users.users.root.openssh.authorizedKeys.keyFiles = [ ../secrets/backup/ssh-key.pub ];
}
