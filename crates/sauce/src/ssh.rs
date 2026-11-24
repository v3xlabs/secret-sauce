//! The age X25519 keys of an ed25519 ssh key, the same keys that `ssh-to-age` makes.
//!
//! The X25519 private key is the scalar of the ed25519 key, from `SigningKey::to_scalar_bytes` of `ed25519-dalek`.
//! The X25519 public key is the Montgomery form of the ed25519 point, from `VerifyingKey::to_montgomery`, so it belongs to that scalar.

use age::x25519;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bech32::{
    Bech32, Hrp,
    primitives::iter::{ByteIterExt as _, Fe32IterExt as _},
};
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use zeroize::Zeroizing;

/// The prefix of an age X25519 identity, as `age-keygen` writes it.
const IDENTITY_PREFIX: Hrp = Hrp::parse_unchecked("AGE-SECRET-KEY-");
/// The prefix of an age X25519 recipient.
const RECIPIENT_PREFIX: Hrp = Hrp::parse_unchecked("age");
/// The label of the PEM text of an OpenSSH private key, between `-----BEGIN ` and `-----`, from `PROTOCOL.key` of OpenSSH.
const PEM_LABEL: &[u8] = b"OPENSSH PRIVATE KEY";
/// The magic bytes of the binary private key format, from `PROTOCOL.key` of OpenSSH.
const MAGIC: &[u8] = b"openssh-key-v1\0";

/// The parts of a binary OpenSSH private key with one key that come before its private bytes.
struct Header<'a> {
    cipher: &'a [u8],
    public: &'a [u8],
    private: &'a [u8],
}

/// Bytes of the SSH wire format, read from the front.
struct Wire<'a>(&'a [u8]);

/// Why an ssh key has no age key.
/// No variant holds bytes of a private key, because the errors of the parsers can hold the bytes that they refused.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("it is a key of type {0}, and sauce reads only ssh-ed25519 keys")]
    Algorithm(String),
    #[error("it is encrypted, and sauce reads only a key without a passphrase")]
    Encrypted,
    #[error("it is not an OpenSSH private key")]
    NotPrivateKey,
    #[error("it is not an OpenSSH public key: {0}")]
    Parse(ssh_key::Error),
    #[error("its ed25519 public key is not a point of the curve")]
    Point(ed25519_dalek::SignatureError),
    #[error("its ed25519 public key is a point of small order, which no real key has")]
    Weak,
}

impl KeyError {
    /// The name of an unknown algorithm stays out of the text, because it comes from the bytes of the key file.
    fn algorithm(algorithm: &Algorithm) -> Self {
        Self::Algorithm(match algorithm {
            Algorithm::Other(_) => "unknown".to_owned(),
            known => known.as_str().to_owned(),
        })
    }
}

impl<'a> Header<'a> {
    fn parse(binary: &'a [u8]) -> Option<Self> {
        let mut wire = Wire(binary.strip_prefix(MAGIC)?);
        let cipher = wire.string()?;
        let _kdf = wire.string()?;
        let _kdf_options = wire.string()?;
        if wire.number()? != 1 {
            return None;
        }
        let public = wire.string()?;
        let private = wire.string()?;
        Some(Self {
            cipher,
            public,
            private,
        })
    }

    /// The algorithm at the head of the private part, after its two check numbers and before any private byte, or none when the private part is encrypted.
    fn private_algorithm(&self) -> Option<&'a [u8]> {
        let mut wire = Wire(self.private);
        wire.number()?;
        wire.number()?;
        wire.string()
    }
}

impl<'a> Wire<'a> {
    /// A number of 4 bytes, most significant first.
    fn number(&mut self) -> Option<u32> {
        let (number, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_be_bytes(*number))
    }

    /// A field: its length as a number, then that many bytes.
    fn string(&mut self) -> Option<&'a [u8]> {
        let length = usize::try_from(self.number()?).ok()?;
        let (field, rest) = self.0.split_at_checked(length)?;
        self.0 = rest;
        Some(field)
    }
}

/// The age identity of an OpenSSH ed25519 private key, such as the content of `/etc/ssh/ssh_host_ed25519_key`.
///
/// It reads the cipher and the algorithms of the public part and of the private part first, so no decoder of `ssh-key` but the ed25519 one ever sees the private bytes.
///
/// # Panics
///
/// Never, because the bech32 of 32 bytes always fits and always parses as an identity.
pub fn identity(openssh: &[u8]) -> Result<x25519::Identity, KeyError> {
    let binary = pem_body(openssh).ok_or(KeyError::NotPrivateKey)?;
    let header = Header::parse(&binary).ok_or(KeyError::NotPrivateKey)?;
    let Ok(public) = PublicKey::from_bytes(header.public) else {
        return Err(KeyError::NotPrivateKey);
    };
    if public.algorithm() != Algorithm::Ed25519 {
        return Err(KeyError::algorithm(&public.algorithm()));
    }
    if header.cipher != b"none" {
        return Err(KeyError::Encrypted);
    }
    // ssh-key picks the decoder of the private part by the algorithm in that part, before it compares it with the public part.
    if header.private_algorithm() != Some(Algorithm::Ed25519.as_str().as_bytes()) {
        return Err(KeyError::NotPrivateKey);
    }
    let Ok(key) = PrivateKey::from_bytes(&binary) else {
        return Err(KeyError::NotPrivateKey);
    };
    let keypair = key.key_data().ed25519().ok_or(KeyError::NotPrivateKey)?;

    let scalar =
        Zeroizing::new(ed25519_dalek::SigningKey::from(&keypair.private).to_scalar_bytes());
    let scalar = scalar.as_slice();
    let length = bech32::encoded_length::<Bech32>(IDENTITY_PREFIX, scalar)
        .expect("32 bytes fit in one bech32 string");
    // Each character goes straight into memory of the final size, so no copy of the text is left behind.
    let mut text = Zeroizing::new(String::with_capacity(length));
    text.extend(
        scalar
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32>(&IDENTITY_PREFIX)
            .chars()
            .map(|character| character.to_ascii_uppercase()),
    );
    Ok(text
        .parse()
        .expect("age parses the bech32 of 32 bytes as an X25519 identity"))
}

/// The age recipient of an OpenSSH ed25519 public key, such as the line of `/etc/ssh/ssh_host_ed25519_key.pub`.
///
/// # Panics
///
/// Never, because the bech32 of 32 bytes always fits and always parses as a recipient.
pub fn recipient(openssh: &str) -> Result<x25519::Recipient, KeyError> {
    let key = PublicKey::from_openssh(openssh.trim()).map_err(KeyError::Parse)?;
    let public = key
        .key_data()
        .ed25519()
        .ok_or_else(|| KeyError::algorithm(&key.algorithm()))?;
    let point = ed25519_dalek::VerifyingKey::from_bytes(&public.0).map_err(KeyError::Point)?;
    // age refuses to wrap for a point of small order, because its shared secret is zero.
    if point.is_weak() {
        return Err(KeyError::Weak);
    }
    let text = bech32::encode_lower::<Bech32>(RECIPIENT_PREFIX, point.to_montgomery().as_bytes())
        .expect("32 bytes fit in one bech32 string");
    Ok(text
        .parse()
        .expect("age parses the bech32 of 32 bytes as an X25519 recipient"))
}

/// The binary key inside the PEM text of an OpenSSH private key, in memory that is wiped on drop.
fn pem_body(text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let inner = text
        .trim_ascii()
        .strip_prefix(b"-----BEGIN ")?
        .strip_prefix(PEM_LABEL)?
        .strip_prefix(b"-----")?
        .strip_suffix(b"-----")?
        .strip_suffix(PEM_LABEL)?
        .strip_suffix(b"-----END ")?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(inner.len()));
    encoded.extend(
        inner
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace()),
    );
    let mut binary = Zeroizing::new(Vec::with_capacity(base64::decoded_len_estimate(
        encoded.len(),
    )));
    // The error of base64 names the byte that it refused, so only its absence is used.
    STANDARD
        .decode_vec(encoded.as_slice(), &mut binary)
        .is_ok()
        .then_some(binary)
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey, public::Ed25519PublicKey};

    use super::{KeyError, identity, recipient};

    #[test]
    fn recipient_is_the_one_of_ssh_to_age() {
        // `ssh-to-age -i` printed this recipient for this public key.
        let public = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICTXzxJ50h6ryTt3OJCdNFH02sI6SG73QRmRPQeFsLy9 root@host\n";
        assert_eq!(
            recipient(public).unwrap().to_string(),
            "age16dcrs85pzhktupqpfq0az6d58yxm54ceu9l47cqtehwzg6fjde8s8nm2dw"
        );

        let rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCnhLAbFOBlfx0r5qsCtKtkF6ZwkxLaCmuEwL9HR38I/1iOcrvc1u2nC9kM1S31YHFDIchM3MbIRyu8A8L0E8C15OMFoGP4FBTtf7QutyR52WZdzAfSkJjUYVqbjrGXXTcrhBsgS5DDM2XGWaL/PcdFAqFumDfaZeGPFlzcjiAOaQ==";
        let error = recipient(rsa).unwrap_err();
        assert!(
            matches!(&error, KeyError::Algorithm(name) if name == "ssh-rsa"),
            "{error:?}"
        );

        // The encoding of the neutral point, which has order 1.
        let mut neutral = [0; 32];
        neutral[0] = 1;
        let weak = PublicKey::from(Ed25519PublicKey(neutral))
            .to_openssh()
            .unwrap();
        assert!(matches!(recipient(&weak), Err(KeyError::Weak)));
    }

    #[test]
    fn identity_opens_for_the_recipient_of_its_public_key() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let private = key.to_openssh(LineEnding::LF).unwrap();
        let public = key.public_key().to_openssh().unwrap();
        assert_eq!(
            identity(private.as_bytes())
                .unwrap()
                .to_public()
                .to_string(),
            recipient(&public).unwrap().to_string()
        );
    }
}
