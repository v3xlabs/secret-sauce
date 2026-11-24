# The `.sauce.yaml` file format, version 1

Secret files end in `.sauce.yaml`.
This file says what they hold, how they are encrypted, and what they hide.
`spec/design.md` says why.
The code of `sauce` in `crates/sauce` and its tests define the exact bytes, such as the grammar, the limits and the layout of the associated data.
The first line of every file is the format number, so the format can change later under a new number.

## An example

```yaml
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
  - for: web
    age: age1...
    wrap:
      - X25519 Lm4tYc... h2PzE1...
```

Inside `facts`, before it is padded and encrypted, this file holds these lines.

```
version: 4
set: 2026-11-10
expires: 2027-02-10
generator: 5d1c09e7...
```

## The fields

- `sauce` is the format number, and a reader rejects any number other than `1`.
- `name` is the name of the secret, in lower case segments that a `/` separates, so it is always a safe relative path.
  It is not the name of the file on disk, and "Encryption" says how it is bound.
- `commitment` binds the file to one file key, as "Encryption" says.
- `facts` and `value` are the encrypted facts and the encrypted secret.
  The secret is bytes, and a reader of the file gives them back as they are.
  Typed values, not built yet, will store a list or a map as JSON text in one spelling, with no spaces and with the keys of a map in sorted order, and the declaration and never the file will say which type a value has.
- `keys` lists the readers.
  Each entry has `for`, which is `admin` or the name of a host, then the public key in `age` or `pgp`, then `wrap`.
  An age `wrap` is the stanzas that the age library returns for that key, one line each.
  A host whose key is an ed25519 ssh key has in `age` the X25519 recipient that `ssh-to-age` makes from it, so its entry is the same as for an age key.
  `pgp` is the fingerprint of a GPG key, as 40 upper case hex characters, of its primary key or of one of its subkeys, and it is valid only with `for: admin`, because a host reads with its age key.
  A primary fingerprint reads with any encryption key of its certificate, and a subkey fingerprint reads with that subkey alone, so a reader refuses a wrap for another key, and a decryption by another key, before it uses the file key.
  A file has at most one entry for each fingerprint, so gpg gets at most one try for each fingerprint in each file, and a primary fingerprint and a subkey fingerprint of one key are two fingerprints.
  A GPG `wrap` follows `wrap:` on the same line.
  It is the OpenPGP message that gpg wrote for that key, in base64 with no padding, and it is at most 4096 bytes.

A GPG entry looks like this.

```yaml
  - for: admin
    pgp: 9F2C41D0...
    wrap: hF4DI3eq3vlFN38SAQdA...
```

The file is YAML in block style, in a strict subset that has one spelling for each field.
A reader parses that subset itself, never with a YAML library, and rejects anything else.
Do not rewrite the file with a YAML tool.
The tool can emit valid YAML that a `sauce` reader rejects.
A file is at most 1 MiB, so `sauce` refuses to write a file with more readers than that holds, and a reader stops after 1 MiB and refuses the file.
A reader refuses `facts` or `value` when its length is not a step plus the 16-byte tag, before it decodes the field, as "Padding" says.

The facts are ASCII lines of the form `key: value`, in the order of the list below.
A fact that is not set has no line, and `formerly` has one line for each former name.

- `version` counts the writes of a value.
- `set` is the date of the last write of a value.
- `issued` is the date a provider issued the secret, and it is optional.
- `expires` is the date the secret stops working, and it is optional.
- `generator` is the SHA-256 digest of the declared generator, and a secret you bring yourself has none.
- `formerly` is a former name of the secret, after a rename.
- `revoke: true` says that a former reader still knows the value.

## Padding

Before encryption, `value` and `facts` are each padded with zero bytes to one size from this list, the steps.
The steps are 256 bytes, 1 KiB, 4 KiB, 8 KiB, 16 KiB, 32 KiB and 64 KiB.
The padded bytes start with the length of the content, so the largest secret is 4 bytes short of 64 KiB.

The step of `value` follows the bound that you declared, not the secret itself.
The bound is `maxLength` when you declared it, else the longest value that the generator can make, else 252 bytes.
A declared `maxLength` is never shorter than the longest value of its generator.
`sauce` takes the smallest step that holds the bound, and it refuses a secret that is longer than its bound.

The step of `facts` is the smallest step that holds the former names and every other fact at its longest.
So the step stays the same when an optional fact comes or goes, and it is 256 bytes unless the former names are many or long.

From the size of `value`, a reader of the repository learns its step, and so only the range of the bound you declared.
An API key, a password, a phone number, a port and a boolean all take the 256-byte step, and their `value` fields have the same length.
A private key or a certificate takes a larger step, and its size shows that it is large.
The size of `facts` shows nothing, except that a secret has many or long former names, which git history shows anyway.

## Encryption

A `.sauce.yaml` file follows age where it can.

- Each write makes a new 16-byte file key from a cryptographic random number generator, as age does.
- `sauce` wraps the file key for each age reader with the age library, as age does in its header.
  Only age X25519 recipients work, and a write refuses a post-quantum or plugin age key.
  For a GPG key, gpg encrypts the file key, with no compression, to the public key of that fingerprint in the keyring of the writer, and for a subkey to that subkey alone.
  The message is one public-key encrypted session key packet and then one integrity protected encrypted data packet, and a reader refuses any other packets before it runs gpg.
  The encrypted data holds the 16 bytes of the file key with no literal data packet around them, and a reader takes them with `gpg --unwrap` and refuses any other length, so gpg reads no packet inside the message.
- HKDF-SHA-256 derives three separate 32-byte outputs from the file key, the key of `value`, the key of `facts` and `commitment`, with the labels `secret-sauce/1/value`, `secret-sauce/1/facts` and `secret-sauce/1/commitment`.
- `value` and `facts` are each one ChaCha20-Poly1305 message with a nonce of 12 zero bytes.

The zero nonce is safe because a key encrypts one message only.
`value` and `facts` have two different keys, and every write makes a new file key, so no key ever encrypts a second message.
age uses a zero nonce the same way when it encrypts the file key in an X25519 stanza.

The associated data of both messages is the format number, `name`, `commitment`, and the `for` and the public key of each reader.
The public key of a GPG reader is its fingerprint, and no age key has the spelling of a fingerprint, so the associated data needs no mark of the key type.
So a `.sauce.yaml` file opens only under the name of the secret it was written for.
A file that you move to another folder still opens, when its secret has the same name.
A `name` line that is edited by hand, or one more reader, makes the file fail to open.
Writing needs public keys only, so somebody who can push could copy the file of one secret over another secret that the same machine reads, and the machine would put that value where it expects the other one.
The bound name makes the machine refuse that file.
sops binds the path of each value in the same way.
A rename goes through `sauce` and needs the private key of an admin, because `sauce` encrypts the secret again under its new name.
The wraps are not in the associated data, because a damaged wrap only stops its own reader.

ChaCha20-Poly1305 does not commit to its key.
Without `commitment`, a writer could make one file that gives two readers two different secrets.
A reader derives the commitment from the file key it unwrapped and compares it with `commitment` in constant time, before it decrypts anything.
So every reader that opens one file gets the same value and the same facts.
A reader gives you nothing until the message it opens decrypts and its padding is correct.
A read of the value opens both messages, so a damaged `facts` or `value` stops it.
A read of the facts opens `facts` only and never decrypts `value`, so it skips the authentication and the padding check of `value`, and it works on a file whose `value` is damaged but still parses.
It checks the name, the readers, `commitment` and `facts` as a read of the value does.

These parts are different from age.

- An age file is binary, with an HMAC over its whole header, and a `.sauce.yaml` file is text with no header HMAC.
  The associated data covers the name and the readers, and `commitment` binds the file key, but nothing covers the bytes of the wraps.
- An age payload mixes a random 16-byte nonce into its key and is encrypted in chunks of 64 KiB.
  A `.sauce.yaml` file has no payload nonce, because each file key encrypts one file only, and each field is one message of at most 64 KiB.
  Without that nonce, `commitment` depends on the file key alone, so somebody who guesses file keys can test each guess against the commitments of all files at once.
  With N files, a guess is N times as likely to hit one, which is still far out of reach with 128-bit file keys, but it is less margin than age keeps.
- age does not pad, and `sauce` pads both fields.

## What a reader of the repository can see

Anybody with the repository and no key sees these.

- `name`, and so which secrets exist.
- The `for` and the public key of each reader, and so which hosts read which secret.
- The number and the types of the stanzas.
- The fingerprint of each GPG reader, and the key ID of its encryption subkey in the wrap.
- The steps of `value` and of `facts`.
- `commitment`, which changes with each write and shows nothing about the secret.

They do not see the value or any fact.
Every reader of a secret, host or admin, can read all of its facts.

Git keeps every earlier file, with the date of each commit.
So the history shows when a secret was written, when it was renamed and when its readers changed, even though `set`, `version` and `formerly` are encrypted.
An old reader can still open the old files.

The format does not show who wrote a file.
Writing needs public keys only, so anybody who can push to your repository can replace a file, put back an older one, or add a reader.
`sauce generate` and `sauce set` show every key that is about to gain access and ask first.

## What is different from sops

- sops shows the length of each value, and `sauce` pads every value to a step.
- The values of one sops file share one data key, and each `.sauce.yaml` file is one secret with its own readers.
- The facts of a secret, such as its expiry date, are encrypted next to its value.
- sops stores a full age file for each age reader, and a `.sauce.yaml` file stores only the stanzas.
- sops and age cannot open a `.sauce.yaml` file.
