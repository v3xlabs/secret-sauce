# Design

secret-sauce is a secret manager for NixOS, heavily inspired by sops and sops-nix.

It keeps what they get right.
Secrets sit encrypted in git next to the config that uses them, each host decrypts its own at activation, and nothing readable lands in the Nix store.

What it adds is everything around that.
Making a secret, rotating it, finding it again, and reading one without opening all the others should each take one command.

## Two pieces

secret-sauce ships as a `sauce` command and a `sauce` NixOS option.

You run the command on your workstation, inside your flake.
It creates, encrypts, lists and rotates secrets.

The option goes in your NixOS config.
It says which secrets a host needs and where they appear, and it brings a small program that decrypts them when the host activates.

## Defining a secret

If you know sops-nix, this looks familiar.
An entry in `sauce.secrets` names a secret and says who may read it on the host.
What is new is that the entry also says how the secret is made.

```nix
sauce.secrets."kanidm/oauth2/freshrss" = {
  generator = { encoding = "alphanum"; min = 40; max = 48; };
  owner = "kanidm";
};
```

There are three kinds of secret.

A secret with a `generator` is one that `sauce` can make, and make again later.
Passwords between your own services, session keys and OAuth client secrets are this kind.

A secret with `once` is made a single time and then left alone.
Use it for a key that encrypts stored data, where a new value means the old data is gone.

```nix
sauce.secrets."litellm/salt-key".once = { encoding = "alphanum"; min = 40; max = 48; };
```

[LiteLLM derives its encryption key from the salt](https://docs.litellm.ai/docs/proxy/security_encryption_faq#how-is-it-encrypted), so the salt itself does not need a fixed length.
Use a fixed length only when the software requires one, as `bytes` below does.
Keep the recipe of an existing `once` secret.
A shorter bound can prevent re-encryption of its existing value.

`generator` and `once` take the same two shapes, with any of these encodings.

- `min` and `max` give random characters of the alphabet, with a random length between them.
- `bytes = N` gives N random bytes, encoded.
  The length is then fixed, for software that decodes the value and needs an exact byte count.

| Encoding | Alphabet | `bytes` output |
|---|---|---|
| `alphanum` | `A-Z a-z 0-9` | not offered, because it is not a decoding |
| `hex` | `0-9 a-f` | lower case hex |
| `base64` | `A-Z a-z 0-9 + /` | standard base64 with `=` padding, as `openssl rand -base64` |
| `base64url` | `A-Z a-z 0-9 - _` | URL-safe base64 without padding, as RFC 4648 section 5 |
| `digits` | `0-9` | not offered |

The bound of `bytes` is the encoded length, so the padding step of the file follows it.
`sauce` refuses a declaration that mixes the two shapes, and `bytes` with an encoding that has no output for it.

```nix
sauce.secrets."app/signing-key".generator = { encoding = "base64"; bytes = 32; };
sauce.secrets."app/cookie-key".generator = { encoding = "base64url"; bytes = 32; };
```

The first value is 44 characters, the second 43.

A secret with neither is one you bring yourself, such as an API token from a provider.
You paste it in with `sauce set`.

```nix
sauce.secrets."github/pat" = { };
```

For a larger value, declare its maximum length in bytes.
The bound selects the padding step, and `sauce` refuses a longer value.

```nix
sauce.secrets."tls/private-key".maxLength = 4096;
```

`maxLength` can also sit next to `generator` or `once`, for a secret whose value you sometimes bring yourself, for example with `sauce import`.
`sauce generate` and `sauce rotate` still make values of the recipe, and the file takes the padding step of `maxLength`.
The evaluation refuses a `maxLength` shorter than the longest value of the recipe, and the error names both numbers.
Adding `maxLength` does not change the `generator` fact, so `sauce status` does not ask for a rotate.
When a changed bound takes another padding step, `sauce generate` encrypts the same value again in the new step, with the key of an admin, and it refuses a value that is longer than the new bound.
A lower bound in the same step changes no file, so `sauce generate` does not open the value to compare it, and only the next write of the value meets the new bound.

On the host, a secret is a file at `/run/sauce/<name>` with the owner and mode you gave it.
Templates work as they do in sops-nix, for the env file that needs two secrets and some plain settings.

```nix
sauce.templates.freshrss-env = {
  owner = "freshrss";
  restartUnits = [ "freshrss.service" ];
  content = ''
    OIDC_CLIENT_SECRET=${config.sauce.placeholder."kanidm/oauth2/freshrss"}
  '';
};
```

Two hosts share a secret by declaring the same name.
Put the declaration in a module that both import and they cannot drift apart.

## Making and changing secrets

`sauce generate` looks at what your hosts declare and creates every secret that does not exist yet.
It evaluates your config and never builds it.

This makes work with a coding agent simple.
The agent adds the declaration on a branch.
You check the branch out and run `sauce generate`.
The agent never sees a secret and never runs `sauce`.

`sauce rotate 'kanidm/*'` makes new values for every matching secret that has a `generator`.
It skips secrets with `once` and secrets you brought yourself.
It shows what it is about to do and asks first.

`sauce set <name>` takes a value from a hidden prompt.
`sauce edit 'asterisk/*'` opens only the matching secrets in `$EDITOR`, not the whole lot.
`sauce rename` moves a secret and tells you which lines of Nix still use the old name.

`sauce import config/voice.sops.yaml config/voice.import.json` moves values out of a sops file.
The mapping file is a JSON object from each top-level key of the sops file to the name of a secret, such as `{ "voice_turn": "voice/turn" }`, so the mapping is readable in the PR that adds it.
`sauce` runs `sops decrypt` from your PATH, so sops opens the file with your sops key, age or GPG, and the value reaches `sauce` through a pipe.
`sauce` hides the messages of sops, because they can quote a value, so a failure shows only the exit status of sops.
Both the output and the messages of `sops decrypt` can hold the values of the file, so do not run it on a terminal that others see or that keeps a log.
Each value is a top-level string, and `sauce` keeps its bytes exactly, with no trim.
It writes each mapped secret for the readers of its declaration, and it checks every mapped key before it writes any file.
It never overwrites a `.sauce.yaml` file, and it says that it did not compare the value of a secret that it skips.
It writes every new file next to its place before it puts the first one in place, so a failed write puts no secret in place.
Then it puts the files in place one at a time, and that is not a transaction.
When one fails, the secrets that `sauce` listed as imported keep their file, and a second import skips them and does not compare their values.
`--dry-run` runs the same checks, lists what `sauce` would write, and writes nothing.

`sauce generate`, `rotate`, `set`, `edit` and `import` refuse a secret when a folder between the root of the flake and its `.sauce.yaml` file is a symbolic link, because the write would land where the link points.

## Looking without leaking

`sauce search` is a fuzzy picker over the names of your secrets.
Next to each name it shows which hosts use it, how it is made, when it last changed and when it expires.
It never shows a value, so it is safe on a shared screen.
The names and the hosts are plain text in each file, so `sauce search` lists them with no key.
The other facts are encrypted, so `sauce search`, `sauce get`, `sauce status` and `sauce list` need your private key to show them.

`sauce get <name>` prints the same facts for one secret.
You get the value only when you ask for it, with `--copy`, `--print` or `--exec`.

`sauce status` lists what needs attention.
That is tokens that have expired or are about to, secrets that are declared but not created, and secrets that no host uses any more.

`sauce list`, `sauce get`, `sauce status` and `sauce search` can reuse a private cache of declarations, and check the flake fingerprint, Nix version and settings at the same time.
A changed declaration triggers a new evaluation, and commands that write secrets always evaluate live unless given `--manifest`.

If the bulk evaluation fails, `sauce` evaluates the machines separately and names the ones that failed.
If it cannot list the machines, all commands stop.
`sauce list` and `sauce status` show what they can and exit nonzero.
`sauce status` does not check for unused files or changes to readers until all machines evaluate.
`sauce search` can find known secrets, and `sauce get` can show a known secret.
A secret with no visible definition may be on a failed machine.
`sauce` never saves a partial manifest, so each read repeats the evaluations while a machine is broken.
On a flake with nine machines and one failure, this took about 3.6 seconds per read.
Commands that write stop before changing any files, because a failed machine could be a reader of any secret.

## What ends up in git

Each secret is one small text file, and it can live anywhere in your flake.
As with `sopsFile` in sops-nix, you point the secret at its file.

```nix
sauce.secrets."kanidm/oauth2/freshrss".file = ./kanidm/freshrss-oauth.sauce.yaml;
```

If you would rather not write that line for every secret, set a default directory one time.
A secret with no `file` then gets `<name>.sauce.yaml` in that directory.

```nix
sauce.defaultDir = ./secrets;
```

This is what a file looks like.

```yaml
# kanidm/freshrss-oauth.sauce.yaml
sauce: 1
name: kanidm/oauth2/freshrss
commitment: Rz8x1KcQ...
facts: Kq1vT0bW...
value: 3nXw8Jq0...
keys:
  - for: admin
    age: age1...
    wrap:
      - X25519 q7JdK2... 0aVxR9...
  - for: admin
    pgp: 9F2C41D0...
    wrap: wcBMA5x2...
  - for: web
    age: age1...
    wrap:
      - X25519 Lm4tYc... h2PzE1...
```

The layout is borrowed from sops.
`value` is the secret, encrypted one time.
`facts` holds the version, the dates and the other facts of the secret, encrypted with it.
`keys` holds, for each reader, the piece they need to open it, and `for` says whether that reader is you or one of your hosts.
`commitment` makes sure that every reader who opens the file gets the same secret.
Because the name and the readers are in the file itself, `sauce search` finds every `.sauce.yaml` file in your flake without evaluating any Nix.

Three things are different from sops.

The value is padded before it is encrypted.
Sizes come in steps of 256 bytes, 1 KiB, 4 KiB and up, and the step follows what you declared, not what the value turned out to be.
From the outside, an empty value, a short password and a long URL look the same.

Each secret has its own readers.
A secret is encrypted for you and for the hosts that declare it, and for nobody else.
When a host starts or stops using a secret, `sauce generate` adjusts the readers.

The facts of a secret, such as its version and its expiry date, are encrypted too.

A `.sauce.yaml` file is not a sops file, and sops and age cannot open one.
To make up for that, `spec/format.md` describes the format and what it hides, and the repository will carry a second small decrypt tool that shares no code with `sauce`.
You should never depend on `sauce` alone to get your secrets back.

## Keys

`sauce` encrypts to age keys, to GPG keys, or to a mix of both.
Each host has a key of its own, and you have one or more for yourself.
Hardware keys work through age plugins.

You list your own keys by type: age recipients in `sauce.adminRecipients.age`, and the fingerprints of GPG keys in `sauce.adminRecipients.pgp`.
A GPG fingerprint is the one of a primary key or of a subkey, so a bare fingerprint from your `.sops.yaml` works as it is.
A primary fingerprint names its certificate, and gpg chooses an encryption key of it.
A subkey fingerprint names that one key, so gpg encrypts to it alone and only that subkey opens the file.
`sauce` takes no `!` suffix, because a subkey fingerprint is already exact.
A fingerprint that is not in the keyring of gpg stops every write with an error that asks you to run `gpg --import`.
A subkey that gpg cannot encrypt to, such as an expired one, stops it with an error that gives the reason of gpg, and says to replace the subkey or, if its whole certificate may read, to check its primary fingerprint and use that.
A certificate with an additional decryption subkey makes gpg write for a second key, and `sauce` refuses that wrap, so a write for it stops with an error.
Post-quantum and plugin keys go in `.age` too, because age tells the kinds apart by their prefix.
A key in the wrong list fails the evaluation, and so does a machine with both lists empty.
A GPG key reads as an admin, never as a host.
`sauce` runs the `gpg` program on your PATH for it, so a key on a smartcard or a YubiKey works through gpg-agent and its pinentry.
`sauce` gives gpg the wrap on a pipe, so a pinentry on the terminal needs `GPG_TTY`, as it does for sops, and a graphical pinentry needs nothing.
Every write wraps a new file key for each reader, so each `sauce generate`, `sauce set`, `sauce edit` and `sauce rotate` needs `gpg` and the public key of each GPG reader in the keyring of whoever writes.
To open a file, `sauce` tries your age keys first, and runs gpg only when none of them is a reader and the command needs the file key.
`sauce list` and `sauce status` never run gpg.
A card costs one operation for each file that `sauce` opens with it, so with a touch policy it asks for one touch per file.
When you list both the primary and a subkey fingerprint of one key, the second entry can start another try if the first does not open the file.
Hosts never need gpg, because they read with their age keys.

Post-quantum age keys work the same way.
Moving to them later is a re-encrypt, not a new file format.
One rule applies: the age readers of a single secret move together, because age does not allow post-quantum and classical keys on the same file.

## On the host

This part runs like sops-nix.
At activation, a program called `sauce-install` decrypts the host's secrets with the host's key and writes them to `/run/sauce`, which lives in memory.
That memory is a tmpfs of 16 MiB that never goes to swap, which needs Linux 6.4 or later.
The Nix store holds only the encrypted files.
When a host has no secret left, the next activation removes `/run/sauce` and the files in it.

If a secret cannot be decrypted, the activation fails.
A deploy tool that rolls back on failure then rolls back.

secret-sauce happily runs alongside sops-nix.
They use separate directories and know nothing of each other, so you can migrate one secret at a time or keep both for good.

## Knowing what a key has seen

Git keeps every old version of every secret.
When a host is compromised or retired, the useful question is what its key could ever read.

`sauce exposure <key>` answers that from the git history.
It lists every secret that was ever encrypted for the key, and splits the list into those `sauce` can rotate for you and those you must replace by hand.

`sauce` also keeps an expiry date where there is one.
You give it with `sauce set --expires`, and for a certificate `sauce` reads it from the certificate.
`sauce status` warns before the date.

## What it is not

- Not a home-manager module.
- Not interactive service API calling.
- Not nix-darwin ready at first, maybe later.
- Not a forced naming structure or ruleset.
- Not a runner of generator scripts at first, the built-in generators replace the `openssl rand` pipe.

On the second point, `sauce` does not ask GitHub or kanidm for a token.
A secret that two of your services share is generated one time and both read it.

## Limits worth knowing

Padding hides a value only inside what you declared.
`length = 29` in a public config tells everybody the length.
Use `min` and `max` when the length should stay private.

Anybody who can push to your repository can swap a secret for one they know, or change the key of a host.
`sauce generate` and `sauce set` show every key that is about to gain access to an existing secret and ask before they write.
Read that prompt.

Rotating a secret does not take back what an old key could read.
The old version is still in git, which is why `sauce exposure` exists.

A secret shared by two hosts changes on each host when that host is deployed.
Between the two deploys they disagree.

A post-quantum secret with a GPG reader is only as strong as the GPG key.
`sauce status` points those out.

gpg refuses to encrypt to an expired key, so every write of a secret with that GPG reader stops when the key expires, until you extend the key or remove its fingerprint.

A service that owns a secret can make its file larger until the 16 MiB are full, and then the next activation fails and the current secrets stay.

Linux refuses a tmpfs that never goes to swap in an unprivileged user namespace, so secret-sauce does not support containers.

`sauce import` moves each mapped value into memory that it wipes, but the buffers that `serde_json` fills while it parses the output of sops, and the values of the keys that the mapping does not name, are not wiped.

`sauce` checks the folders of a secret for a symbolic link before it writes, so a folder that becomes a link after that check still takes the write where the link points.

## How it is built

`sauce-install` handles templates, unit restarts and `neededForUsers` the way sops-nix does, so they behave the way people already know.

`spec/format.md` comes first, before any code, and gets a security review of its own.
