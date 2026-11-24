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

## Typed values

Not built yet.
`sauce` stores and edits `string` values only, and the rest of this part is a plan.
The edit buffer below is built for strings first, so a list or a map later comes in the same buffer with no migration.

A secret holds a string, a list or a map.
`type` in the declaration says which, and `string` is the default.

One secret has one set of readers and one set of facts.
So a list or a map is for values that share readers, an expiry date and an origin.

An item of a list or a map is a string, a whole number, `true`, `false`, a list or a map.
A whole number is from -9223372036854775808 to 9223372036854775807, which is 64 bits with a sign.
A number outside that range is an error that says to write it as a string.
There is no null and no decimal number.
`sauce` must tell if a value changed, and `1.0` and `1.00` are one number with two spellings.
Write a decimal as a string.
`type` says `list` or `map`, and it says nothing about the items.
An item is a string or a number by how you write it, as in a sops file.

The type is in the declaration only.
The manifest carries it, as it carries `maxLength`, and a `.sauce.yaml` file does not store it.
A machine does not need the type, and one place for it cannot disagree with a second place.
So the file format stays at version 1, and an older `sauce-install` writes the same file from the same bytes.
`sauce` uses the type in two places.
It refuses a value of another shape at a write, and it picks the form of the value in the edit buffer.
`sauce` stops when two machines give one name two types, as it does for two generators.

`generator` and `once` make strings only.
A `list` or a `map` with a `generator` or a `once` fails at evaluation.
The facts belong to the whole secret, so one generated item would need a `version`, a `generator` digest and a `revoke` of its own.
A value that `sauce` makes stays a secret of its own.

`value` holds a string as its bytes, and a list or a map as JSON text.
That JSON has one spelling, with no spaces and with the keys of a map in sorted order.
A key of a map is a string.
A key that comes two times in one map is an error, in the edit buffer and in the JSON of `sauce set`, as it is in a `.sauce.yaml` file.
The padding rule does not change.
The bound is `maxLength`, in bytes of the stored value, or 252 bytes without it.
The step follows the bound and never the size of the value.
So a reader of the repository sees the type and the bound, and not the number of items or their lengths.

On the host, the file at `/run/sauce/<name>` holds the stored bytes, a string as it is and a list or a map as JSON.
There is no YAML form, no form with one item on each line, no env form and no choice for each secret.
`sauce-install` already reads JSON, and YAML needs a new crate in the program that runs as root.
One item on each line breaks on an item that holds a newline.
systemd, Docker and dotenv read the quotes of an env file in three different ways.
A service that needs another form gets it from a template.

In a template, `config.sauce.placeholder."<name>"` stands for the whole stored value, for every type.
`config.sauce.item` stands for one item of a list or a map.
It takes the name of the secret and a path.
In the path, a key of a map is a string, and an index of a list is a number that starts at 0.
`config.sauce.item` fails at evaluation for a name that the machine does not have, for a secret that the machine defines as a `string`, and for an empty path.
A machine that only reads the name with `sauce.read` cannot check the type.

```nix
sauce.templates.asterisk-trunk = {
  owner = "asterisk";
  content = ''
    host=${config.sauce.item "asterisk/trunk" [ "host" ]}
    port=${config.sauce.item "asterisk/trunk" [ "port" ]}
    secret=${config.sauce.item "asterisk/trunk" [ "pin" ]}
    allow=${config.sauce.item "asterisk/trunk" [ "codecs" 0 ]}
  '';
};
```

A string item goes in as its bytes, a number and a boolean in their JSON spelling, and a list or a map as JSON.
`sauce-install` reads the path from the template text, and it parses the JSON of a secret only when a template reads an item of it.
It still makes one pass over the template, so a value that holds a placeholder pulls in nothing.
Only the item placeholder needs a new `sauce-install`, and a machine gets that from the same `flake.lock` as the template that uses it.

`sauce set` of a list or a map reads JSON from stdin, and `sauce` stores it in the one spelling.
On a terminal it stops and names `sauce edit`, because a hidden prompt takes one line.
`sauce get` shows the type, and `--print` and `--copy` give the stored bytes.

### A string

A secret with no `type` is a `string`, and every secret of today is one.

```nix
sauce.secrets."asterisk/ari-password" = { };
sauce.secrets."asterisk/env".maxLength = 1020;
```

`value` holds the bytes of the string.
The bound is `maxLength` when the declaration has one, else the longest value that the generator or `once` can make, else 252 bytes.
The file on the host holds the same bytes.
A string has no items, so a template takes it whole, with `config.sauce.placeholder`.
`sauce set` takes it from a hidden prompt, or from stdin.
In the edit buffer it is one line, or a block when it has newlines.
It is in double quotes when neither form gives back the same string.

```yaml
asterisk/ari-password: example-password

asterisk/env: |
  SIP_USER=1001
  SIP_REALM=sip.example.com
```

### A list

```nix
sauce.secrets."asterisk/allowed".type = "list";
```

`value` holds `[1001,1002]`, which is 11 bytes of JSON.
It has no `maxLength`, so the bound is 252 bytes of that JSON, and the secret takes the 256-byte step.
The file on the host holds `[1001,1002]`.
`config.sauce.item "asterisk/allowed" [ 0 ]` puts `1001` in a template.
`sauce set asterisk/allowed` reads JSON from stdin, such as `[1001, 1002]`.
In the edit buffer each item comes after `- `, and an empty list is `[]`.

```yaml
asterisk/allowed:
  - 1001
  - 1002
```

### A map

```nix
sauce.secrets."asterisk/trunk" = {
  type = "map";
  maxLength = 1020;
};
```

`value` holds this JSON, which is 76 bytes.

```json
{"codecs":["opus","g722"],"host":"sip.example.com","pin":"0042","port":5060}
```

The bound is 1020 bytes of that JSON, so the secret takes the 1 KiB step.
The file on the host holds the same JSON.
`config.sauce.item "asterisk/trunk" [ "pin" ]` puts `0042` in a template, `[ "port" ]` puts `5060`, and `[ "codecs" ]` puts `["opus","g722"]`.
`sauce set asterisk/trunk` reads JSON from stdin.
In the edit buffer each item comes after its key and a `:`, and an empty map is `{}`.
An item that is a list or a map takes the lines below its key, as `codecs` does.

```yaml
asterisk/trunk:
  codecs:
    - opus
    - g722
  host: sip.example.com
  pin: "0042"
  port: 5060
```

### A schema for each secret

Not built yet, and this part only keeps the place for it.
A list or a map can be a whole document, such as a JSON list of people for kanidm.
A secret may later declare `schema`, a JSON Schema for its value, in the declaration and the manifest, as it declares `type`, and never in a `.sauce.yaml` file.
`sauce` would then check a value against it before a write, as it checks the type.
How the edit buffer hands a schema to an editor is left open.
A YAML language server reads `pw: 8080` as a number and an empty entry as null, where the buffer reads a string and no value, so that comes with the schema work and its own rules.

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
`sauce edit 'asterisk/*'` opens the matching secrets in one `$EDITOR` buffer, as "Editing in one buffer" says.
`sauce rename` moves a secret and tells you which lines of Nix still use the old name.
`sauce remove <name>` deletes the file of a secret that no machine declares anymore, so the declaration goes first.

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

## Editing in one buffer

`sauce edit` with a pattern opens every matching secret in one buffer, in one run of `$EDITOR`.

The first build of this buffer holds `string` secrets only.
The list and map forms, the rules for items and the type errors below come with typed values, in the same buffer.

```yaml
# sauce edit 'asterisk/*'
# Change values only. sauce does not read a line that starts with #.

# readers: admin, voice. no file yet. list, at most 252 bytes of JSON.
asterisk/allowed:

# readers: admin, voice. made by: set. expires: 2027-02-10. string, at most 252 bytes.
asterisk/ari-password: example-password

# readers: admin, voice. made by: set. string, at most 1020 bytes.
asterisk/env: |
  SIP_USER=1001
  SIP_REALM=sip.example.com

# readers: admin, voice. made by: set. map, at most 1020 bytes of JSON.
asterisk/trunk:
  codecs:
    - opus
    - g722
  host: sip.example.com
  pin: "0042"
  port: 5060

# asterisk/session-key is made by a generator, and `sauce rotate asterisk/session-key` makes a new value.
```

Each matched secret is one top-level entry, with its name as the key, in the order of the names.
`sauce edit` with an exact name opens the same buffer with one entry, so there is one format for both.
The comment above an entry gives the readers, how the secret is made, the expiry date, the type and the bound.
`sauce` reads no comment, so a changed comment changes nothing.

The buffer is a file of mode 0600, in a folder of mode 0700 in `$XDG_RUNTIME_DIR`, which must be a ramfs or a tmpfs mounted with `noswap`.
When the first word of `$EDITOR`, in quotes or not, is `vim` or `nvim`, `sauce` puts `-n -i NONE -c 'set nobackup nowritebackup noundofile'` right after it at every run of the editor, so vim keeps no swap, backup, undo, viminfo or ShaDa file.
A wrapper script and any other editor get no options, so set them up to keep none of these files.
`sauce` removes the folder when the edit ends.
The name of the file ends in `.yaml`, so the editor colours it.

Before the buffer opens, each secret that has a file must have the readers that the machines declare, as for one value today.
Else `sauce edit` stops and names `sauce generate`, so an edit never changes who can read a value.
A new file gets the declared readers.

`sauce edit '*'` is refused, and any other pattern opens the buffer with no question.
A pattern that matches no declared secret stops with an error, and no editor opens.

The declared type decides how `sauce` reads an entry.
Under a `string`, the texts `8080`, `no` and `0042` are strings.

`sauce` writes the buffer itself, in these forms.

- A string is one line.
- A string with newlines is a block with `|`, `|-` or `|+`, so the newline at the end is exact.
  `sauce` writes the block form only for a `string` secret.
- A list has `- ` before each item, and an empty list is `[]`.
- A map has `key: value` for each item, and an empty map is `{}`.
- A string that the forms above cannot hold is in double quotes, with the escapes of JSON.

`sauce` writes a string plain, or as a block, only when the reader gives back the same string.
In every other case it writes the string in double quotes, such as `"a: b"`, `"#x"`, `" x"` and `"\"x\""`.
The rule is the same for a `string` secret, for a string item and for a key of a map.
A string item with a newline is in double quotes with `\n`.

The YAML crate gives `sauce` each scalar with its style, and `sauce` gives a plain item of a list or a map its type by these rules.

- A whole number in the spelling of JSON, such as `5060` or `-7`, is a whole number.
- A number with a leading zero or a `+`, such as `0042` or `+5`, is an error that says to write it in double quotes, so `pin: 0042` never becomes the number 42.
- `true` and `false` are booleans, and no other text is a boolean.
- A decimal number, `null`, `~` and no text are errors.
- All other text is a string.
- A scalar in quotes or in a block is a string, in every place.
- A key of a map is a string in every style, so the key `5060` is the string `5060`.

So `sauce` writes the string items `0042`, `+5`, `1.5` and the empty string as `"0042"`, `"+5"`, `"1.5"` and `""`, and it writes the string item `no` plain.

`sauce` reads the buffer with the YAML crate `saphyr-parser`, and a `.sauce.yaml` file keeps its own reader.
So the buffer accepts YAML that `sauce` does not write.

- A list as `[a, b]` and a map as `{a: b}`, and the items inside follow the rules above.
- Single quotes.
- A `>` block, and a block as an item.
- A plain string on more than one line.
- A comment at the end of a line.

These are errors.

- An anchor and an alias.
- A tag such as `!!str`, because a tag is a second way to give a type, and the declared type decides.
- A second document.
- A key that is a list or a map.

`<<` is a key like any other, with no merge.
`sauce` gives the line number of each error, and you correct the line in the same buffer.

Before the editor opens, `sauce` reads the buffer that it wrote and compares each value with the original.
A value that does not come back byte for byte is left out, with a comment that names `sauce set`.
With the double quotes, only a value that is not UTF-8 text is such a value.

With a pattern, the buffer leaves out a secret with a `generator` or a `once`.
A comment names `sauce rotate` for a `generator`, and `sauce edit` with the exact name for a `once`, because `sauce rotate` refuses a `once`.
A generated secret with no file yet is left out with a comment that names `sauce generate`.
An edit by accident in a long buffer clears the `generator` fact.
Then `sauce get` says that `sauce set` made the secret, and `sauce status` no longer warns when the declaration changes.
`sauce rotate` still makes a new value for a secret with a `generator`, because it works from the declaration.
An exact name still opens such a secret when it has a file, and with no file it stops and names `sauce generate`.
A key pair never opens, and `sauce rotate` makes a new one.
The comment for each secret that the buffer leaves out comes after the last entry.
When the buffer leaves out every match, no editor opens, and `sauce edit` prints the comments.

A secret that you bring yourself and that has no file yet is an empty entry, and its comment says `no file yet`.
A value there makes the file, with `version` 1 and the `set` date of today.
A list or a map needs a way in that is not argv, shell history or a plain file on disk, and the buffer is that way.

`sauce` accepts each name that it put in the buffer one time, and any other name is an error.
An entry that you remove does not change its secret, and `sauce edit` never deletes a secret.
An empty entry, `name:` or `name: ""`, is no value.
It leaves a secret with no file as it is, and it is an error for a secret that has a value, as an empty value is for `sauce set`.
Under a `string`, any other text is the value as it is written, `null` and `~` included.

`sauce` writes only the secrets that changed.
It compares what it read with the old value, a string by its bytes and a list or a map by its stored JSON.
So another order of keys or another indentation is no change.
A secret that did not change keeps its file byte for byte, and its bound is not checked, so a value that a lowered bound left in place does not stop an edit of another secret.
A changed secret gets `version` plus 1 and the `set` date of today.

`sauce` finds every error before the first write.
An error is text that does not parse, a value of the wrong type, a changed value over its bound or a bad name.
`sauce` then opens the same text again, with the errors as comment lines at the top.
It replaces the error lines of the round before, so the line numbers stay correct in each round.
Each error gives a fixed reason and its line in the buffer that opens, and the name of the secret when the line belongs to an entry of the buffer.
It never quotes the text of the buffer, so a value that you typed in the wrong place does not reach the error lines.

```yaml
# asterisk/allowed, line 7: the type is list, and this entry is not a list.
# asterisk/trunk, line 24: port is a decimal number. Write it as a string.
# line 30: this key is not the name of a secret in this buffer.
```

No message on the terminal quotes a value.
You leave with no write when the editor exits with an error, or when you save a buffer with errors and change nothing below its error lines since the round before.

`sauce` writes the changed secrets one at a time, each with the lock and the check of "Making and changing secrets".
When a secret changed on disk while the editor was open, `sauce` refuses that secret only, writes the others, names it and exits nonzero.
Each secret is one file with a `version` of its own, and a write of several files is not one transaction.
The edit of that one secret is lost.

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
A host key is an age key, or the ed25519 ssh host key of the machine, as in sops-nix.
`sauce` turns an `ssh-ed25519` public key into the `age1...` recipient that `ssh-to-age` prints for it, so the `age1...` keys of sops-nix users keep working.

You list your own keys by type: age recipients in `sauce.adminRecipients.age`, and the fingerprints of GPG keys in `sauce.adminRecipients.pgp`.
A GPG fingerprint is the one of a primary key or of a subkey, so a bare fingerprint from your `.sops.yaml` works as it is.
A primary fingerprint names its certificate, and gpg chooses an encryption key of it.
A subkey fingerprint names that one key, so gpg encrypts to it alone and only that subkey opens the file.
`sauce` takes no `!` suffix, because a subkey fingerprint is already exact.
A fingerprint that is not in the keyring of gpg stops every write with an error that asks you to run `gpg --import`.
A subkey that gpg cannot encrypt to, such as an expired one, stops it with an error that gives the reason of gpg, and says to replace the subkey or, if its whole certificate may read, to check its primary fingerprint and use that.
A certificate with an additional decryption subkey makes gpg write for a second key, and `sauce` refuses that wrap, so a write for it stops with an error.
Post-quantum and plugin keys go in `.age` too, because age tells the kinds apart by their prefix.
Only X25519 age recipients work, and a write refuses a post-quantum or plugin age key, while GPG keys work as below.
A key in the wrong list fails the evaluation, and so does a machine with both lists empty.
`sauce` finds your own age key from the sources that sops reads, and unlike sops, which collects the keys of all its sources, it uses the first source that is set: `--identity` or `SAUCE_IDENTITY`, then `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, the output of the command in `SOPS_AGE_KEY_CMD`, and the sops key file in `XDG_CONFIG_HOME` or `~/.config`.
An empty `SOPS_AGE_KEY` or `SOPS_AGE_KEY_CMD` counts as not set.
The key stays in memory, and an error names the source and never the key.
A GPG key reads as an admin, never as a host.
`sauce` runs the `gpg` program on your PATH for it, so a key on a smartcard or a YubiKey works through gpg-agent and its pinentry.
`sauce` gives gpg the wrap on a pipe, so a pinentry on the terminal needs `GPG_TTY`, as it does for sops, and a graphical pinentry needs nothing.
Every write wraps a new file key for each reader, so each `sauce generate`, `sauce set`, `sauce edit`, `sauce expire` and `sauce rotate` needs `gpg` and the public key of each GPG reader in the keyring of whoever writes.
To open a file, `sauce` tries your age keys first, and runs gpg only when none of them is a reader and the command needs the file key.
`sauce list` and `sauce status` never run gpg.
A card costs one operation for each file that `sauce` opens with it, so with a touch policy it asks for one touch per file.
When you list both the primary and a subkey fingerprint of one key, the second entry can start another try if the first does not open the file.
Hosts never need gpg, because they read with their age keys.

Post-quantum age keys do not work today.
Moving to them later is a re-encrypt, not a new file format.
One rule applies: the age readers of a single secret move together, because age does not allow post-quantum and classical keys on the same file.

## On the host

This part runs like sops-nix.
At activation, a program called `sauce-install` decrypts the host's secrets with the host's key and writes them to `/run/sauce`, which lives in memory.
That memory is a tmpfs of 16 MiB that never goes to swap, which needs Linux 6.4 or later.
The Nix store holds only the encrypted files.
When a host has no secret left, the next activation removes `/run/sauce` and the files in it.

The host's keys are the age key in `sauce.identityFile` and the ssh keys in `sauce.age.sshKeyPaths`, which holds the ed25519 host keys of openssh by default, and any one of them opens a file.
`sauce-install` turns each ssh key into its age key in memory, as sops-nix does with the code of `ssh-to-age`.
It skips an ssh key that it cannot read or that is not an ed25519 key, with a warning, because sshd makes its keys only after `sauce-install` runs at the first boot.

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
You give it with `sauce set --expires`, you change or clear it with `sauce expire <name> <date>` or `sauce expire <name> --clear`, and for a certificate `sauce set`, `sauce edit` and `sauce import` read it from the certificate: the `notAfter` of a PEM X.509 certificate, or of the first certificate of a bundle, unless you give `--expires`.
`sauce` reads a certificate with the `x509-cert` crate, and a value that it cannot decode gives no date.
A known limit: in `der` 0.7, a length inside a malformed certificate that claims more bytes than there are can make one `sauce` command allocate that much and abort, and nothing leaks.
Only someone who can already write secrets can give such a value, and the value is at most the bound of the secret.
`x509-cert` also refuses a certificate with a `notBefore` or `notAfter` before 1970, so such a certificate gives no date.
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

With typed values, the type of a secret and the item paths in a template are plain text in your config.
So everybody learns that `asterisk/trunk` is a map with a `pin`.
A secret that must hide its shape stays a `string` that holds JSON, and then no template reads one item of it.

Anybody who can push to your repository can swap a secret for one they know, or change the key of a host.
`sauce generate` and `sauce set` show every key that is about to gain access to an existing secret and ask before they write.
Read that prompt.

Rotating a secret does not take back what an old key could read.
The old version is still in git, which is why `sauce exposure` exists.

A secret shared by two hosts changes on each host when that host is deployed.
Between the two deploys they disagree.

With typed values, a template that reads an item that the list or the map does not have fails the switch on the machine, not the build, and the current secrets stay.
The manifest does not know which items a template reads, so `sauce` cannot find this earlier.

With typed values, after you change the `type` of a secret that has a file, the file keeps the old value until the next write.
When the old value does not fit the new type, `sauce edit` shows an empty entry with a comment, and never a guess at the value.

One buffer of `sauce edit` holds many values, so an editor that keeps undo, swap or yank files outside the buffer folder keeps more of them than with one value.

In the buffer, text after ` #` in a plain value is a comment, so `pw: abc #1` is read as `abc`.
`sauce` writes such a string in double quotes, and you type it in quotes.

The YAML parser keeps copies of the values of the buffer in memory, and `sauce` does not wipe them before the process ends.

An admin with only a GPG key gets one card operation for each file that the buffer opens.

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
