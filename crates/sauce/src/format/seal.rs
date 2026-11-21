use age::secrecy::ExposeSecret;
use age_core::format::FileKey;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{Name, Reader};

/// The sizes of padded `value` and `facts` that `spec/format.md` lists.
const STEPS: [usize; 7] = [256, 1024, 4096, 8192, 16384, 32768, 65536];

/// The bytes of the length that starts the padded bytes.
const LENGTH_BYTES: usize = 4;

/// The bytes of the ChaCha20-Poly1305 tag at the end of each sealed field.
const TAG_BYTES: usize = 16;

/// The three outputs of HKDF-SHA-256 over one file key.
pub struct Keys {
    pub value: Zeroizing<[u8; 32]>,
    pub facts: Zeroizing<[u8; 32]>,
    pub commitment: [u8; 32],
}

impl Keys {
    pub fn new(file_key: &FileKey) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, file_key.expose_secret());
        let derive = |label: &str| {
            let mut key = Zeroizing::new([0; 32]);
            hkdf.expand(label.as_bytes(), key.as_mut())
                .expect("32 bytes is a valid output length of HKDF-SHA-256");
            key
        };
        Self {
            value: derive("secret-sauce/1/value"),
            facts: derive("secret-sauce/1/facts"),
            commitment: *derive("secret-sauce/1/commitment"),
        }
    }

    /// Compares `commitment` in a time that does not depend on where the first different byte is.
    pub fn matches(&self, commitment: &[u8; 32]) -> bool {
        let difference = self
            .commitment
            .iter()
            .zip(commitment)
            .fold(0, |difference, (a, b)| difference | (a ^ b));
        std::hint::black_box(difference) == 0
    }
}

/// The smallest step that holds content of `length` bytes and its length.
pub fn step(length: usize) -> Option<usize> {
    STEPS
        .into_iter()
        .find(|step| length.saturating_add(LENGTH_BYTES) <= *step)
}

/// The content of `step` bytes: its length, most significant byte first, then the content, then zero bytes.
pub fn pad(content: &[u8], step: usize) -> Zeroizing<Vec<u8>> {
    let length = u32::try_from(content.len()).expect("content fits a step of at most 64 KiB");
    let mut padded = Zeroizing::new(Vec::with_capacity(step));
    padded.extend_from_slice(&length.to_be_bytes());
    padded.extend_from_slice(content);
    padded.resize(step, 0);
    padded
}

pub fn unpad(padded: &[u8]) -> Option<&[u8]> {
    if !STEPS.contains(&padded.len()) {
        return None;
    }
    let (length, rest) = padded.split_first_chunk::<LENGTH_BYTES>()?;
    let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
    let (content, zeros) = rest.split_at_checked(length)?;
    zeros.iter().all(|byte| *byte == 0).then_some(content)
}

/// Whether a sealed field of `length` bytes is a step plus the tag.
pub fn is_sealed_length(length: usize) -> bool {
    STEPS.iter().any(|step| step + TAG_BYTES == length)
}

/// The associated data of `facts` and `value`.
///
/// It is the format number, `name`, `commitment`, then `for` and the `age` or `pgp` key of each reader, in file order.
/// An age recipient never has the spelling of a GPG fingerprint, so the field needs no mark of its type.
/// Each field has its length before it, as 8 bytes, most significant byte first.
pub fn associated_data<'a>(
    name: &Name,
    commitment: &[u8; 32],
    readers: impl IntoIterator<Item = &'a Reader>,
) -> Vec<u8> {
    let mut data = Vec::new();
    let mut field = |bytes: &[u8]| {
        let length = u64::try_from(bytes.len()).expect("a length fits in 64 bits");
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(bytes);
    };
    field(b"1");
    field(name.as_str().as_bytes());
    field(commitment);
    for reader in readers {
        field(reader.r#for.as_bytes());
        field(reader.key.as_str().as_bytes());
    }
    data
}

// Each key encrypts one message only, so the nonce is zero, as in an age X25519 stanza.
pub fn seal(key: &[u8; 32], associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };
    ChaCha20Poly1305::new(key.into())
        .encrypt(&Nonce::default(), payload)
        .expect("ChaCha20-Poly1305 encrypts a message of at most 64 KiB")
}

pub fn open(
    key: &[u8; 32],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };
    ChaCha20Poly1305::new(key.into())
        .decrypt(&Nonce::default(), payload)
        .ok()
        .map(Zeroizing::new)
}
