# Example

This is a small NixOS flake with three machines that keep their secrets with secret-sauce.
`flake.nix` takes `sauce` from the checkout around this folder, so every command here runs the `sauce` of the same commit.

The age keys of this example are throwaway keys, and their private halves are in `snakeoil/`.
Everybody can read them, so that you can try every command, and so that the checks of this repository can start a machine.
Never keep a private key in your own repository.

## The machines

- `notes` runs HedgeDoc and Miniflux with one PostgreSQL, Kanidm for their logins, a restic backup of the database, and ddclient.
- `backup` copies the restic folder of `notes` every day over SSH.
- `offsite` does the same from another building, and runs `restic check` every week.

| Secret | Defined in | Read by |
|---|---|---|
| `hedgedoc/db-password` | `services/hedgedoc.nix` | `notes`, in `services/hedgedoc.nix` and `services/postgresql.nix` |
| `hedgedoc/session-secret` | `services/hedgedoc.nix` | `notes`, in the template of `services/hedgedoc.nix` |
| `kanidm/idm-admin-password` | `services/kanidm.nix` | `notes` |
| `sso/hedgedoc`, `sso/miniflux` | the loop over `sso.clients` in `services/kanidm.nix` | `notes` |
| `ddclient/api-token` | `services/ddclient.nix` | `notes` |
| `restic/password` | `services/restic.nix` | `notes`, and `offsite` through `sauce.read` in `services/restic-check.nix` |
| `backup/ssh-key` | `services/rsync.nix` | `backup` and `offsite`, and `notes` trusts its public half in `services/openssh.nix` |

Each file in `services/` is a NixOS module, and each file in `machines/` imports the modules of one machine and gives its public key.
Two machines that import one module share its secret.
A module that only reads a secret from another machine says so with `sauce.read = [ "restic/password" ];`.
A new SSO client is one `sso.clients.<name>` block in the file of its service, and the loop in `services/kanidm.nix` gives it a secret with a `generator`.

## Walk through the commands

Open a shell with the `sauce` of this checkout, in this folder.

```sh
nix shell ..#sauce
```

See what the machines declare.

```sh
sauce list
```

```
NAME                       MACHINES        MADE BY               SET  EXPIRES  STATE
backup/ssh-key             backup,offsite  ssh-ed25519                         ✗
ddclient/api-token         notes           set                                 ✗
hedgedoc/db-password       notes           alphanum, 40<48                     ✗
hedgedoc/session-secret    notes           base64url, 32 B                     ✗
kanidm/idm-admin-password  notes           alphanum, 40<48                     ✗
restic/password            notes,offsite   once alphanum, 40<48                ✗
sso/hedgedoc               notes           alphanum, 40<48                     ✗
sso/miniflux               notes           alphanum, 40<48                     ✗
The facts are encrypted, so expiry, changed generators and revoke are not checked, because no private key of an admin is set, in --identity, SAUCE_IDENTITY, SOPS_AGE_KEY_FILE or ~/.config/sops/age/keys.txt.
```

`✓` marks a secret whose file exists, and `✗` a secret whose file is missing.
The last line is on stderr, and it says that `sauce list` has no key to open the facts.
Without a key that can read the facts, `SET` and `EXPIRES` stay empty.

If the key file is found but none of its keys can read the secrets, `sauce list` and `sauce status` report the file once.
Use `--identity <key-file>` to pick another key.
Set `NO_COLOR` to turn off terminal colors.
On a terminal, `sauce list` colors the folder of each name, such as `backup/`, in blue, magenta or cyan.
The color comes from the folder text, so a folder has the same color on every run.

A command that takes longer than a moment shows its current step on one line of stderr, such as `⠋ Evaluating machines…`.
The line shows only when stdout and stderr are terminals and `TERM` is not `dumb`, and sauce erases it before it prints a result, an error or a prompt.

Make every secret that `sauce` can make.

```sh
sauce generate
```

```
created backup/ssh-key & backup/ssh-key.pub
created hedgedoc/db-password
created hedgedoc/session-secret
created kanidm/idm-admin-password
created restic/password
created sso/hedgedoc
created sso/miniflux
Set these secrets manually:
  sauce set ddclient/api-token
Generated: 7 created, 0 re-encrypted, 1 needs a value.
```

Each secret is encrypted for the admin keys and for the machines that read it, so this needs no private key.
A second run reports that no files changed.
When a machine starts or stops reading a secret, `sauce generate` shows the exact keys that change and asks before it writes any file.
Re-encrypting existing files needs the private key of an admin.

`sauce generate --dry-run` prints the same action lines without writing any files or asking for a key.
It lists files to create, files to re-encrypt, and secrets whose value you must supply.

`ddclient/api-token` comes from your DNS provider, so you paste it in at a hidden prompt.

```sh
sauce set ddclient/api-token --expires 2027-05-15
```

```
Value of ddclient/api-token:
set ddclient/api-token, version 1
```

`sauce set` also reads the value from a pipe, as it is, with no newline removed.

Look at the secret.

```sh
sauce get ddclient/api-token
```

```
name: ddclient/api-token
file: example/secrets/ddclient/api-token.sauce.yaml
note: API token for the DNS zone example.com, made in the dashboard of the DNS provider.
machines: notes
readers: admin, notes

Facts are locked. Run `sauce get ddclient/api-token --identity <admin-key-file>`.
```

Give it the throwaway admin key of this example.

```sh
export SAUCE_IDENTITY=snakeoil/admin.key
sauce get ddclient/api-token
```

```
name: ddclient/api-token
file: example/secrets/ddclient/api-token.sauce.yaml
note: API token for the DNS zone example.com, made in the dashboard of the DNS provider.
machines: notes
readers: admin, notes
version: 1
set: 2026-11-18
expires: 2027-05-15
made by: sauce set

To use the value: sauce get ddclient/api-token --copy
To edit it: sauce edit ddclient/api-token
```

`sauce get ddclient/api-token --print` writes the value to stdout and nothing else, so it works in a pipe.

With the key of an admin, `sauce list` opens the facts and shows how long ago each value was set and how long until it expires.
If the recorded set date is ahead of today's UTC date, `SET` shows that date instead of an age.
It marks `⚠` for a secret that needs attention in `sauce status`.

```sh
sauce list
```

```
NAME                       MACHINES        MADE BY               SET    EXPIRES  STATE
backup/ssh-key             backup,offsite  ssh-ed25519           today           ✓
ddclient/api-token         notes           set                   today  in 178d  ✓
hedgedoc/db-password       notes           alphanum, 40<48       today           ✓
hedgedoc/session-secret    notes           base64url, 32 B       today           ✓
kanidm/idm-admin-password  notes           alphanum, 40<48       today           ✓
restic/password            notes,offsite   once alphanum, 40<48  today           ✓
sso/hedgedoc               notes           alphanum, 40<48       today           ✓
sso/miniflux               notes           alphanum, 40<48       today           ✓
```

See what needs attention.

```sh
sauce status
```

```
Nothing needs attention.
```

It lists a secret with no file, a file that no machine declares, and a file whose readers differ from the declaration.
If you supply the value for a secret and it has no file, `sauce status` shows `unset`.
With the key of an admin it also lists a secret that expires in the next 30 days, a secret marked `revoke`, and a secret whose generator changed.

Find a secret by a part of its name.

```sh
sauce search
```

The list draws on the terminal, with no value, and narrows as you type.

```
? Secret › sso
❯ sso/hedgedoc               notes           generator encoding=alphanum min=40 max=48
  sso/miniflux               notes           generator encoding=alphanum min=40 max=48
  hedgedoc/db-password       notes           generator encoding=alphanum min=40 max=48
  hedgedoc/session-secret    notes           generator encoding=base64url bytes=32
  kanidm/idm-admin-password  notes           generator encoding=alphanum min=40 max=48
  restic/password            notes,offsite   once encoding=alphanum min=40 max=48
  backup/ssh-key             backup,offsite  generator keypair=ssh-ed25519
```

Enter prints the name, so `sauce get "$(sauce search)" --print` works.
With no terminal, `sauce search sso` prints the names that hold `sso`, one on each line.

Make new values for the SSO client secrets.

```sh
sauce rotate 'sso/*'
```

```
These secrets get a new value:
  sso/hedgedoc
  sso/miniflux
Rotate them? [y/N] y
rotated sso/hedgedoc, version 2
rotated sso/miniflux, version 2
```

In a pattern, `*` stands for any text, `/` included, and an exact name rotates with no question.
`sauce rotate` needs the key of an admin, because it keeps the encrypted facts and counts the version on.
It refuses a `once` secret, because a new restic password would lock you out of the old backups.

```sh
sauce rotate restic/password
```

```
error: restic/password is `once`, and a new value would lose what the old one protects
```

Change one value in your editor.

```sh
sauce edit ddclient/api-token
```

```
edited ddclient/api-token, version 2
```

To edit secrets matching a pattern, quote it so the shell does not expand `*`.

```sh
sauce edit 'sso/*'
```

`sauce edit` lists the names and asks before opening each value.
Answer `y` to open one, press Enter to skip it, or enter `q` to stop without opening any more values.
Edits you already saved still apply.

`sauce edit` writes the value to a file with mode 0600, in a folder of its own in `$XDG_RUNTIME_DIR`, and removes the folder when the editor closes.
It refuses to start when that folder is not in memory.
Use an editor that does not persist value contents or print them outside its editor view.
Turn off swap, backup, and undo files that the editor may keep outside the runtime folder.

Copy a value to paste it somewhere.

```sh
sauce get ddclient/api-token --copy
```

```
Copied ddclient/api-token to the clipboard for 30 seconds. A clipboard history of the desktop keeps a copy of its own.
```

It needs `wl-copy` or `xclip`.
Over SSH with no display it stops with an error and puts the value nowhere.

## Deploy

A flake sees only the files that git tracks, so add the secrets before you build a machine.

```sh
git add secrets
```

Without that step, `nix build .#nixosConfigurations.backup.config.system.build.toplevel` stops at evaluation and names the secret.

```
       Failed assertions:
       - sauce.secrets."backup/ssh-key" has no file at example/secrets/backup/ssh-key.sauce.yaml. Run `sauce generate`, or `sauce set backup/ssh-key` for a secret that you bring yourself, and then `git add` the file, because a flake in git does not see a file that git does not track.
       - The ‘fileSystems’ option does not specify your root file system.
       - You must set the option ‘boot.loader.grub.devices’ or 'boot.loader.grub.mirroredBoots' to make the system bootable.
```

The last two lines are there because the machines of this example leave out their disks and boot loader.

On the machine, at every activation, `sauce-install` opens each `.sauce.yaml` file of the machine with the key in `sauce.identityFile`.
It writes each secret to `/run/sauce/<name>`, and each template to `/run/sauce/rendered/<name>`, on a ramfs, with the owner and mode of the declaration.
It restarts the units in `restartUnits` of a secret or template whose value changed.
When one file does not open, the activation fails and the secrets of the last activation stay in place.
The Nix store of the machine holds only the encrypted files.

## Your own repository

Add this repository as the flake input `secret-sauce`, and import `secret-sauce.nixosModules.default` in each machine, as `flake.nix` here does.
Then this shell gives the `sauce` of your lock file.

```sh
nix shell --inputs-from . secret-sauce#sauce
```

Make an age key for yourself with `age-keygen`, and put its public key in `sauce.adminRecipients.age`.
`sauce` also finds the age key that you use with sops, in `SOPS_AGE_KEY_FILE` or `~/.config/sops/age/keys.txt`.
On each machine, make its key with `age-keygen -o /var/lib/sauce/host.key`, and put the public key that it prints in `sauce.recipient` of that machine.
Then run `sauce generate`, `git add` the secrets, and deploy.
