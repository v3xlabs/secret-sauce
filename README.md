![secret-sauce](docs/lettermark.svg)

Like sops with sops-nix, plus a lifecycle: `sauce` generates and rotates the secrets of your NixOS machines, tracks their expiry dates, keeps them encrypted in your repository, and pads each one so that its length stays hidden.

![A sauce session: a secret declared in Nix, then generate, set with an expiry date, rotate, and the padded files](docs/demo.gif)

Declare a secret next to the service that uses it:

```nix
# rotated whenever you ask
sauce.secrets."kanidm/oauth2/freshrss".generator = { encoding = "alphanum"; min = 40; max = 48; };

# made one time and never touched again
sauce.secrets."litellm/salt-key".once = { encoding = "alphanum"; min = 40; max = 48; };

# a token somebody else issues, you paste it in with `sauce set`
sauce.secrets."github/pat" = { };
```

Then run `sauce generate`.
It makes the values, pads them, and encrypts each one for the hosts that use it and for your admin keys.

## Add to a flake

Add the input and import `nixosModules.default` in each machine.

```nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.sauce.url = "github:v3xlabs/secret-sauce";

  outputs = { nixpkgs, sauce, ... }: {
    nixosConfigurations.notes = nixpkgs.lib.nixosSystem {
      modules = [
        ./configuration.nix
        sauce.nixosModules.default
        {
          sauce = {
            adminRecipients.age = [ "<age public key of an admin>" ];
            # adminRecipients.pgp = [ "<GPG fingerprint of an admin>" ];
            recipient = "<public key of this machine>";
            identityFile = "/var/lib/sauce/host.key";
            defaultDir = ./secrets;
          };
        }
      ];
    };
  };
}
```

## Commands

`list`, `generate`, `set`, `rotate`, `status`, `edit`, `import`, `search`, `get`

## Running sauce

Run the `sauce` of the flake input that your hosts use: `nix run --inputs-from . sauce -- generate`.
A newer `sauce` can write a file that an older `sauce-install` refuses, and then that host fails to activate.

## Independent decryption

Open a file with an age X25519 identity: `python tools/sauce-decrypt.py secret.sauce.yaml identity.key --name secret/name`.
It prints the facts and the value length, or the value with `--print`.
It has no GPG support, so it cannot open the wrap of a GPG reader.
The development shell provides Python and `cryptography`.
