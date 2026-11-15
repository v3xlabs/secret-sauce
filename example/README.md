# Example

This is a small NixOS flake with three machines that keep their secrets with secret-sauce.
It shows what your repository looks like when you are done.
`sauce` and the `sauce` option cannot run it yet, so nothing evaluates it.

## The machines

- `notes` runs HedgeDoc at `notes.example.com` and Miniflux at `rss.example.com`, with one PostgreSQL for both.
  Kanidm at `auth.example.com` gives both services their logins.
  `notes` backs the database up with restic to a local folder, and ddclient keeps its DNS record up to date.
- `backup` copies that restic folder from `notes` every day, over SSH.
- `offsite` does the same from another building, and checks its copy with `restic check` every week.

| Secret | Defined in | Read by |
|---|---|---|
| `hedgedoc/db-password` | `services/hedgedoc.nix` | `notes`, in `services/hedgedoc.nix` and `services/postgresql.nix` |
| `kanidm/idm-admin-password` | `services/kanidm.nix` | `notes` |
| `sso/<client>`, one for each SSO client | the loop in `services/kanidm.nix` | `notes`, in `services/kanidm.nix` and in the file of the client |
| `ddclient/api-token` | `services/ddclient.nix` | `notes` |
| `restic/password` | `services/restic.nix` | `notes`, and `offsite` in `services/restic-check.nix` |
| `backup/ssh-key` | `services/rsync.nix` | `backup` and `offsite`, and `notes` has the public half in `services/openssh.nix` |

Each file in `services/` is a NixOS module, and `services/default.nix` names them all.
`flake.nix` exposes that set as `nixosModules`.
Each file in `machines/` imports the modules of a machine, such as `self.nixosModules.hedgedoc`, and gives the public key of the machine.
`flake.nix` sets what all machines share: your own public keys, and `secrets/` as the folder of the secrets.
The machines leave out their disks and boot loader, which you already have.

## Two services on one machine

HedgeDoc and PostgreSQL both need `hedgedoc/db-password`.
`services/hedgedoc.nix` defines it, with its `generator`.
`services/postgresql.nix` reads `config.sauce.secrets."hedgedoc/db-password".path`, as it reads any other option of the machine.
The file belongs to `postgres`, because PostgreSQL reads it, and HedgeDoc gets the value through a template.

## One secret, two machines

`backup` and `offsite` both import `self.nixosModules.rsync`, so both get `backup/ssh-key`.
Two machines that import the same module share its secret, and `sauce generate` stops when two machines give a different `generator` or `once` for one name.
`services/restic-check.nix` on `offsite` needs `restic/password`, which `services/restic.nix` defines on `notes`.
A module that only reads a secret says so with `sauce.read = [ "restic/password" ];`, and `sauce generate` finds the one definition over all machines.

## SSO for every service

A service says in its own file that it logs in through kanidm.
This is the block in `services/miniflux.nix`.

```nix
sso.clients.miniflux = {
  displayName = "Miniflux";
  originUrl = "https://rss.example.com/oauth2/oidc/callback";
  originLanding = "https://rss.example.com";
};
```

`services/kanidm.nix` has one loop over `config.sso.clients`.
For each client it defines the secret `sso/<client>` with a `generator`, and the kanidm OAuth2 client with that secret as `basicSecretFile`.
This is the part that defines the secrets.

```nix
sauce.secrets = lib.mapAttrs' (
  name: _:
  lib.nameValuePair "sso/${name}" {
    generator = { encoding = "alphanum"; min = 40; max = 48; };
    owner = "kanidm";
    restartUnits = [ "kanidm.service" ];
  }
) config.sso.clients;
```

The service reads its client secret through a template, such as `${config.sauce.placeholder."sso/miniflux"}`.
The file belongs to `kanidm`, because kanidm reads it, and systemd reads the template of the service as root when the service starts.

A new SSO client is one block in the file of its service, and no edit in `services/kanidm.nix`.
`sso.clients` is an option of this example and not of `sauce`.
`sauce` gives the generator, the one definition and the placeholder, and plain Nix gives the loop.
`sauce rotate 'sso/*'` makes new client secrets for all clients, and one deploy of `notes` restarts kanidm and both services.
To add people to kanidm, log in as `idm_admin` with the password from `sauce get kanidm/idm-admin-password --copy`.

## From an empty checkout to three machines

Get `sauce` with `nix shell github:v3xlabs/secret-sauce`.

Make an age key for yourself with `age-keygen`, and put its public key in `sauce.adminRecipients` in `flake.nix`.
A hardware key through an age plugin works too.

On each machine, make the key of the machine.

```sh
age-keygen -o /var/lib/sauce/host.key
```

Put the public key it prints in `sauce.recipient` in `machines/<name>.nix`.

Make the secrets.

```sh
sauce generate
```

This creates `hedgedoc/db-password`, `kanidm/idm-admin-password`, `sso/hedgedoc`, `sso/miniflux`, `restic/password` and `backup/ssh-key`, with `secrets/backup/ssh-key.pub` next to it.
It cannot make `ddclient/api-token`, because that token comes from your DNS provider.
Make the token in the dashboard of the provider, and paste it in.

```sh
sauce set ddclient/api-token --expires 2027-05-15
```

Commit the secrets and deploy.

```sh
git add secrets
git commit -m "Add secrets"
nixos-rebuild switch --flake .#notes --target-host root@notes.example.com
nixos-rebuild switch --flake .#backup --target-host root@backup.example.com
nixos-rebuild switch --flake .#offsite --target-host root@offsite.example.com
```

`notes` reads `secrets/backup/ssh-key.pub` when Nix evaluates it, so it fails to evaluate until `sauce generate` has run.

## Later

Make a new database password.

```sh
sauce rotate 'hedgedoc/*'
git commit -am "Rotate hedgedoc secrets"
```

Then deploy `notes`.
PostgreSQL takes the new password and HedgeDoc restarts with it, in the same activation.

`sauce rotate 'restic/*'` skips `restic/password`, because it is `once`.
A new restic password would lock you out of the old backups.

`sauce status` warns before `ddclient/api-token` expires.
Make a new token at the provider and run `sauce set ddclient/api-token --expires <date>` again.

## What git holds

```
.
├── README.md
├── flake.lock
├── flake.nix
├── machines
│   ├── backup.nix
│   ├── notes.nix
│   └── offsite.nix
├── services
│   ├── ddclient.nix
│   ├── default.nix
│   ├── hedgedoc.nix
│   ├── kanidm.nix
│   ├── miniflux.nix
│   ├── openssh.nix
│   ├── postgresql.nix
│   ├── restic-check.nix
│   ├── restic.nix
│   └── rsync.nix
└── secrets
    ├── backup
    │   ├── ssh-key.pub
    │   └── ssh-key.sauce
    ├── ddclient
    │   └── api-token.sauce
    ├── hedgedoc
    │   └── db-password.sauce
    ├── kanidm
    │   └── idm-admin-password.sauce
    ├── restic
    │   └── password.sauce
    └── sso
        ├── hedgedoc.sauce
        └── miniflux.sauce
```

This folder has no `flake.lock` and no `secrets` yet, because `sauce` cannot make a `.sauce` file yet.

The age keys in this example are throwaway keys.
Their private halves were deleted right after they were made, so nobody can open a secret encrypted for them.
