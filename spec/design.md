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
sauce.secrets."litellm/salt-key".once = { encoding = "hex"; bytes = 32; };
```

A secret with neither is one you bring yourself, such as an API token from a provider.
You paste it in with `sauce set`.

```nix
sauce.secrets."github/pat" = { };
```

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
sauce.secrets."kanidm/oauth2/freshrss".file = ./kanidm/freshrss-oauth.sauce;
```

If you would rather not write that line for every secret, set a default directory one time.
A secret with no `file` then gets `<name>.sauce` in that directory.

```nix
sauce.defaultDir = ./secrets;
```

This is what a file looks like.

```yaml
# kanidm/freshrss-oauth.sauce
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
Because the name and the readers are in the file itself, `sauce search` finds every `.sauce` file in your flake without evaluating any Nix.

Three things are different from sops.

The value is padded before it is encrypted.
Sizes come in steps of 256 bytes, 1 KiB, 4 KiB and up, and the step follows what you declared, not what the value turned out to be.
From the outside, an empty value, a short password and a long URL look the same.

Each secret has its own readers.
A secret is encrypted for you and for the hosts that declare it, and for nobody else.
When a host starts or stops using a secret, `sauce generate` adjusts the readers.

The facts of a secret, such as its version and its expiry date, are encrypted too.

A `.sauce` file is not a sops file, and sops and age cannot open one.
To make up for that, `spec/format.md` describes the format and what it hides, and the repository will carry a second small decrypt tool that shares no code with `sauce`.
You should never depend on `sauce` alone to get your secrets back.

## Keys

`sauce` encrypts to age keys, to GPG keys, or to a mix of both.
Each host has a key of its own, and you have one or more for yourself.
Hardware keys work through age plugins.

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
`sauce generate` shows every key that is about to gain access to an existing secret and asks before it re-encrypts.
Read that prompt.

Rotating a secret does not take back what an old key could read.
The old version is still in git, which is why `sauce exposure` exists.

A secret shared by two hosts changes on each host when that host is deployed.
Between the two deploys they disagree.

A post-quantum secret with a GPG reader is only as strong as the GPG key.
`sauce status` points those out.

A service that owns a secret can make its file larger until the 16 MiB are full, and then the next activation fails and the current secrets stay.

Linux refuses a tmpfs that never goes to swap in an unprivileged user namespace, so secret-sauce does not support containers.

## How it is built

`sauce-install` handles templates, unit restarts and `neededForUsers` the way sops-nix does, so they behave the way people already know.

`spec/format.md` comes first, before any code, and gets a security review of its own.
