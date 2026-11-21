use rand::{Rng as _, RngCore as _, rngs::OsRng};
use sauce::format::Value;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use zeroize::Zeroizing;

use crate::manifest::{Definition, Generator, Once};

/// The length of an OpenSSH ed25519 private key with no comment and no passphrase, as `ssh-key` writes it.
/// It is the bound of the key pair `ssh-ed25519`, so a new layout in `ssh-key` makes `format::write` refuse the key.
const ED25519_BYTES: usize = 387;

/// The longest value that a `.sauce.yaml` file holds, 4 bytes short of the largest step in `spec/format.md`.
const LARGEST: usize = 65_532;

/// The bound of a value that `sauce set` gives, from `spec/format.md`, as long as a declaration has no `maxLength`.
pub const SET_BOUND: usize = 252;

static ENCODINGS: [Encoding; 5] = [
    Encoding {
        name: "alphanum",
        alphabet: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        padded: false,
    },
    Encoding {
        name: "hex",
        alphabet: b"0123456789abcdef",
        padded: false,
    },
    Encoding {
        name: "base64",
        alphabet: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        padded: true,
    },
    Encoding {
        name: "base64url",
        alphabet: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        padded: false,
    },
    Encoding {
        name: "digits",
        alphabet: b"0123456789",
        padded: false,
    },
];

/// An encoding of values, by the name that a declaration gives as `encoding`.
pub struct Encoding {
    name: &'static str,
    alphabet: &'static [u8],
    /// Whether `bytes` ends the value with `=` up to a multiple of 4 characters.
    padded: bool,
}

/// How `sauce` makes the value of a secret.
pub enum Recipe {
    /// Random characters of an encoding, with a length drawn between `min` and `max`.
    Text {
        encoding: &'static Encoding,
        min: usize,
        max: usize,
    },
    /// Random bytes, written in an encoding.
    Bytes {
        encoding: &'static Encoding,
        count: usize,
    },
    /// An OpenSSH ed25519 private key, with its public half.
    Ed25519,
}

/// A declaration that `sauce` cannot make a value for.
#[derive(Debug, thiserror::Error)]
pub enum RecipeError {
    #[error(
        "sauce cannot make `{0}`; use `min` and `max` with alphanum, hex, base64, base64url or digits, `bytes` with hex, base64 or base64url, or an ssh-ed25519 `generator` key pair"
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
            Self::Bytes { encoding, count } => encoding.length(*count),
            Self::Ed25519 => ED25519_BYTES,
        }
    }

    pub fn make(&self) -> Made {
        match self {
            Self::Text { encoding, min, max } => {
                let length = OsRng.gen_range(*min..=*max);
                let text: Vec<u8> = (0..length)
                    .map(|_| encoding.alphabet[OsRng.gen_range(0..encoding.alphabet.len())])
                    .collect();
                Made {
                    value: Value::from(text),
                    public: None,
                }
            }
            Self::Bytes { encoding, count } => {
                let mut bytes = Zeroizing::new(vec![0; *count]);
                OsRng.fill_bytes(&mut bytes);
                Made {
                    value: Value::from(encoding.encode(&bytes)),
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
                bytes: None,
                keypair: Some(keypair),
            } if keypair == "ssh-ed25519" => Some(Self::Ed25519),
            Generator {
                encoding: Some(encoding),
                min,
                max,
                bytes,
                keypair: None,
            } => Self::encoded(encoding, *min, *max, *bytes),
            _ => None,
        }
    }

    fn once(once: &Once) -> Option<Self> {
        let Once {
            encoding: Some(encoding),
            min,
            max,
            bytes,
        } = once
        else {
            return None;
        };
        Self::encoded(encoding, *min, *max, *bytes)
    }

    /// `min` and `max` together make `Text`, and `bytes` alone makes `Bytes`.
    fn encoded(
        encoding: &str,
        min: Option<u32>,
        max: Option<u32>,
        bytes: Option<u32>,
    ) -> Option<Self> {
        let encoding = Encoding::find(encoding)?;
        match (min, max, bytes) {
            (Some(min), Some(max), None) if min <= max => Some(Self::Text {
                encoding,
                min: usize::try_from(min).ok()?,
                max: usize::try_from(max).ok()?,
            }),
            (None, None, Some(bytes)) if encoding.decodes() => Some(Self::Bytes {
                encoding,
                count: usize::try_from(bytes).ok()?,
            }),
            _ => None,
        }
    }
}

impl Encoding {
    fn find(name: &str) -> Option<&'static Self> {
        ENCODINGS.iter().find(|encoding| encoding.name == name)
    }

    /// `bytes` needs a power of two of characters, so `alphanum` and `digits` have none.
    fn decodes(&self) -> bool {
        self.alphabet.len().is_power_of_two()
    }

    fn bits(&self) -> usize {
        usize::try_from(self.alphabet.len().ilog2()).expect("a bit count fits in usize")
    }

    /// The length of `count` bytes in this encoding.
    fn length(&self, count: usize) -> usize {
        let length = count.saturating_mul(8).div_ceil(self.bits());
        if self.padded {
            length.next_multiple_of(4)
        } else {
            length
        }
    }

    fn encode(&self, bytes: &[u8]) -> Vec<u8> {
        let bits = self.bits();
        let mask = self.alphabet.len() - 1;
        let mut text = Vec::with_capacity(self.length(bytes.len()));
        let mut buffer = 0_usize;
        let mut held = 0;
        for byte in bytes {
            buffer = (buffer << 8) | usize::from(*byte);
            held += 8;
            while held >= bits {
                held -= bits;
                text.push(self.alphabet[(buffer >> held) & mask]);
            }
        }
        if held > 0 {
            text.push(self.alphabet[(buffer << (bits - held)) & mask]);
        }
        text.resize(self.length(bytes.len()), b'=');
        text
    }
}

#[cfg(test)]
mod tests {
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };

    use super::{ENCODINGS, Encoding, Recipe};
    use crate::manifest::Definition;

    fn recipe(declaration: &str) -> Option<Recipe> {
        let definition: Definition = serde_json::from_str(&format!(
            r#"{{ "file": "a.sauce.yaml", "generator": {declaration} }}"#
        ))
        .unwrap();
        Recipe::new(&definition).ok().flatten()
    }

    fn member(name: &str, byte: u8) -> bool {
        match name {
            "alphanum" => byte.is_ascii_alphanumeric(),
            "hex" => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
            "base64" => byte.is_ascii_alphanumeric() || b"+/".contains(&byte),
            "base64url" => byte.is_ascii_alphanumeric() || b"-_".contains(&byte),
            "digits" => byte.is_ascii_digit(),
            _ => panic!("the test does not know the encoding {name}"),
        }
    }

    fn decode(name: &str, text: &[u8]) -> Vec<u8> {
        match name {
            "hex" => text
                .chunks(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect(),
            "base64" => STANDARD.decode(text).unwrap(),
            "base64url" => URL_SAFE_NO_PAD.decode(text).unwrap(),
            _ => panic!("the test cannot decode {name}"),
        }
    }

    #[test]
    fn each_encoding_makes_its_own_characters_in_range() {
        for Encoding { name, alphabet, .. } in &ENCODINGS {
            let mut alphabet = alphabet.to_vec();
            alphabet.sort_unstable();
            let expected: Vec<u8> = (0..=u8::MAX).filter(|byte| member(name, *byte)).collect();
            assert_eq!(alphabet, expected, "the alphabet of {name}");

            let recipe = recipe(&format!(
                r#"{{ "encoding": "{name}", "min": 5, "max": 9 }}"#
            ))
            .unwrap();
            for _ in 0..200 {
                let made = recipe.make();
                let value = made.value.expose();
                assert!(
                    (5..=9).contains(&value.len()),
                    "{name} made {} characters",
                    value.len()
                );
                assert!(
                    value.iter().all(|byte| member(name, *byte)),
                    "{name} made a character outside its alphabet"
                );
            }
        }
    }

    #[test]
    fn bytes_decode_to_exactly_that_many_bytes() {
        for encoding in ENCODINGS.iter().filter(|encoding| encoding.decodes()) {
            let name = encoding.name;
            for count in 1..=10_u8 {
                let recipe =
                    recipe(&format!(r#"{{ "encoding": "{name}", "bytes": {count} }}"#)).unwrap();
                let made = recipe.make();
                let value = made.value.expose();
                assert_eq!(
                    decode(name, value).len(),
                    usize::from(count),
                    "{name} with {count} bytes"
                );
                assert_eq!(value.len(), recipe.bound(), "{name} with {count} bytes");

                let input: Vec<u8> = (0..count)
                    .map(|byte| byte.wrapping_mul(37).wrapping_add(200))
                    .collect();
                assert_eq!(
                    decode(name, &encoding.encode(&input)),
                    input,
                    "{name} with {count} bytes"
                );
            }
        }
    }

    #[test]
    fn bytes_need_an_encoding_that_decodes_and_exclude_min_and_max() {
        assert!(recipe(r#"{ "encoding": "alphanum", "bytes": 8 }"#).is_none());
        assert!(recipe(r#"{ "encoding": "digits", "bytes": 8 }"#).is_none());
        assert!(recipe(r#"{ "encoding": "base64url", "min": 8, "max": 8, "bytes": 8 }"#).is_none());
        assert!(recipe(r#"{ "encoding": "base64url", "min": 9, "max": 8 }"#).is_none());
    }
}
