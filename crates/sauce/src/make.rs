use rand::{Rng as _, RngCore as _, rngs::OsRng};
use sauce::format::Value;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use zeroize::Zeroizing;

use crate::manifest::{Definition, Generator, Once};

const ALPHANUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The length of an OpenSSH ed25519 private key with no comment and no passphrase, as `ssh-key` writes it.
/// It is the bound of the key pair `ssh-ed25519`, so a new layout in `ssh-key` makes `format::write` refuse the key.
const ED25519_BYTES: usize = 387;

const HEX: &[u8] = b"0123456789abcdef";

/// The longest value that a `.sauce` file holds, 4 bytes short of the largest step in `spec/format.md`.
const LARGEST: usize = 65_532;

/// The bound of a value that `sauce set` gives, from `spec/format.md`, as long as a declaration has no `maxLength`.
pub const SET_BOUND: usize = 252;

/// How `sauce` makes the value of a secret.
pub enum Recipe {
    /// Random characters of an alphabet, with a length drawn between `min` and `max`.
    Text {
        alphabet: &'static [u8],
        min: usize,
        max: usize,
    },
    /// Random bytes, written as hex.
    HexBytes(usize),
    /// An OpenSSH ed25519 private key, with its public half.
    Ed25519,
}

/// A declaration that `sauce` cannot make a value for.
#[derive(Debug, thiserror::Error)]
pub enum RecipeError {
    #[error(
        "sauce cannot make `{0}`, and makes `encoding` alphanum or hex with `min` and `max`, `once` hex with `bytes`, or `keypair` ssh-ed25519"
    )]
    Unsupported(String),
    #[error("`{0}` makes values longer than the {LARGEST} bytes that a file holds")]
    TooLong(String),
}

/// A value that `sauce` made.
pub struct Made {
    pub value: Value,
    /// The public half of a key pair, as one line of OpenSSH text.
    pub public: Option<String>,
}

impl Recipe {
    /// The recipe of a declaration, or `None` for a value that `sauce set` gives.
    pub fn new(definition: &Definition) -> Result<Option<Self>, RecipeError> {
        let recipe = match (&definition.generator, &definition.once) {
            (None, None) => return Ok(None),
            (Some(generator), _) => Self::generator(generator),
            (None, Some(once)) => Self::once(once),
        };
        let declaration = || definition.declaration().unwrap_or_default();
        let recipe = recipe.ok_or_else(|| RecipeError::Unsupported(declaration()))?;
        if recipe.bound() > LARGEST {
            return Err(RecipeError::TooLong(declaration()));
        }
        Ok(Some(recipe))
    }

    /// The longest value that this recipe makes, in bytes.
    pub fn bound(&self) -> usize {
        match self {
            Self::Text { max, .. } => *max,
            Self::HexBytes(count) => count.saturating_mul(2),
            Self::Ed25519 => ED25519_BYTES,
        }
    }

    pub fn make(&self) -> Made {
        match self {
            Self::Text { alphabet, min, max } => {
                let length = OsRng.gen_range(*min..=*max);
                let text: Vec<u8> = (0..length)
                    .map(|_| alphabet[OsRng.gen_range(0..alphabet.len())])
                    .collect();
                Made {
                    value: Value::from(text),
                    public: None,
                }
            }
            Self::HexBytes(count) => {
                let mut bytes = Zeroizing::new(vec![0; *count]);
                OsRng.fill_bytes(&mut bytes);
                let text: Vec<u8> = bytes
                    .iter()
                    .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0xf)]])
                    .collect();
                Made {
                    value: Value::from(text),
                    public: None,
                }
            }
            Self::Ed25519 => {
                let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
                    .expect("ssh-key makes ed25519 keys");
                let private = key
                    .to_openssh(LineEnding::LF)
                    .expect("an ed25519 key encodes as OpenSSH text");
                let public = key
                    .public_key()
                    .to_openssh()
                    .expect("an ed25519 public key encodes as OpenSSH text");
                Made {
                    value: Value::from(private.as_bytes().to_vec()),
                    public: Some(public),
                }
            }
        }
    }

    fn generator(generator: &Generator) -> Option<Self> {
        match generator {
            Generator {
                encoding: None,
                min: None,
                max: None,
                keypair: Some(keypair),
            } if keypair == "ssh-ed25519" => Some(Self::Ed25519),
            Generator {
                encoding: Some(encoding),
                min: Some(min),
                max: Some(max),
                keypair: None,
            } if min <= max => Some(Self::Text {
                alphabet: alphabet(encoding)?,
                min: usize::try_from(*min).ok()?,
                max: usize::try_from(*max).ok()?,
            }),
            _ => None,
        }
    }

    fn once(once: &Once) -> Option<Self> {
        match once {
            Once {
                encoding: Some(encoding),
                bytes: Some(bytes),
            } if encoding == "hex" => Some(Self::HexBytes(usize::try_from(*bytes).ok()?)),
            _ => None,
        }
    }
}

fn alphabet(encoding: &str) -> Option<&'static [u8]> {
    match encoding {
        "alphanum" => Some(ALPHANUM),
        "hex" => Some(HEX),
        _ => None,
    }
}
