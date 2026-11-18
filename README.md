# secret-sauce

Secrets for NixOS that live in git and do not give away their length.

Declare a secret next to the service that uses it:

```nix
# rotated whenever you ask
sauce.secrets."kanidm/oauth2/freshrss".generator = { encoding = "alphanum"; min = 40; max = 48; };

# made one time and never touched again
sauce.secrets."litellm/salt-key".once = { encoding = "hex"; bytes = 32; };

# a token somebody else issues, you paste it in with `sauce set`
sauce.secrets."github/pat" = { };
```

Then run `sauce generate`.
It makes the values, pads them, and encrypts each one for the hosts that use it and for nobody else.

`sauce search` lists every secret and never prints one.

None of this is built yet.
The design is in [`spec/`](spec/).

## Independent decryption

Run `python tools/sauce-decrypt.py secret.sauce.yaml identity.key --name secret/name` to open a file with an age X25519 identity.
The program prints the facts and the value length.
Add `--print` to print the value instead of its length.
The development shell provides Python and `cryptography`.
