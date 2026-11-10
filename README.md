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
