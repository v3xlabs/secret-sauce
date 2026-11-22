//! One `.sauce.yaml` file, as `spec/format.md` describes it.

mod facts;
mod file;
mod name;
mod seal;
mod value;

pub use facts::{Date, DateError, Facts};
pub use file::{Key, ParseError, Reader};
pub use name::{Name, NameError};
pub use value::Value;

use std::fs;
use std::io::{self, Read as _};
use std::path::Path;

use age::Recipient as _;
use age_core::format::FileKey;
use file::{Entry, File, Wrap};
use rand::{RngCore, rngs::OsRng};
use seal::Keys;

/// The largest `.sauce.yaml` file, in bytes, as `spec/format.md` says.
const LARGEST_FILE: usize = 1024 * 1024;

/// The largest wrap of a GPG reader, in bytes.
///
/// A wrap for an RSA key of 4096 bits is 601 bytes, and one for 8192 bits, the largest RSA key that gpg makes, is about 1100.
/// A larger wrap is refused before gpg reads it.
pub const LARGEST_PGP_WRAP: usize = 4096;

/// Unwraps the file key from the wrap of a GPG reader, given its fingerprint, and gives `None` for a key it does not hold.
pub type PgpUnwrap<'a> = dyn Fn(&str, &[u8]) -> Option<io::Result<FileKey>> + 'a;

/// The private key that opens a file.
#[derive(Clone, Copy)]
pub enum Opener<'a> {
    /// An age identity, which skips the entries of GPG keys.
    Age(&'a dyn age::Identity),
    /// The secret keys of gpg, which skip the entries of age keys.
    Pgp(&'a PgpUnwrap<'a>),
}

#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("the bound of {0} bytes is larger than the largest step holds")]
    Bound(usize),
    #[error("the value is longer than its bound of {0} bytes")]
    TooLong(usize),
    #[error("the facts do not fit in the largest step")]
    Facts,
    #[error("a file needs at least one reader")]
    NoReaders,
    #[error(
        "reader {0} does not have `admin` or a host name in `for` and an age X25519 recipient in `age`, or `admin` in `for` and a GPG fingerprint of 40 upper case hex characters in `pgp` that no earlier reader has"
    )]
    Reader(usize),
    #[error(
        "the file is larger than 1 MiB, the largest .sauce.yaml file, because it has too many readers"
    )]
    TooLarge,
    #[error("age cannot wrap the file key")]
    Wrap(#[from] age::EncryptError),
    #[error("gpg cannot wrap the file key for {fingerprint}: {source}")]
    Pgp {
        fingerprint: String,
        #[source]
        source: io::Error,
    },
    #[error("the wrap for {0} is empty or larger than {LARGEST_PGP_WRAP} bytes")]
    PgpWrap(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("the file holds another secret than the expected name")]
    Name,
    #[error("no entry in `keys` is for this identity")]
    NotAReader,
    #[error("age cannot unwrap the file key")]
    Unwrap(#[source] age::DecryptError),
    #[error("gpg cannot unwrap the file key: {0}")]
    Pgp(#[source] io::Error),
    #[error("the file key does not match `commitment`")]
    Commitment,
    #[error("`facts` or `value` does not decrypt, so the file changed after it was written")]
    Decrypt,
    #[error("`facts` or `value` has padding that is not valid")]
    Padding,
    #[error("the decrypted facts are not in the format")]
    Facts,
}

/// Writes the text of a file for these readers, with public keys only.
///
/// `bound` is the longest value in bytes that the declaration of the secret allows, and it chooses the step of `value`.
/// `pgp` wraps the file key for the fingerprint of each GPG reader, and only for those.
pub fn write(
    name: &Name,
    value: &Value,
    facts: &Facts,
    bound: usize,
    readers: &[Reader],
    mut pgp: impl FnMut(&str, &FileKey) -> io::Result<Vec<u8>>,
) -> Result<String, WriteError> {
    let value_step = seal::step(bound).ok_or(WriteError::Bound(bound))?;
    if value.expose().len() > bound {
        return Err(WriteError::TooLong(bound));
    }
    let facts_step = seal::step(facts::longest(facts)).ok_or(WriteError::Facts)?;
    let recipients = checked_recipients(readers)?.collect::<Result<Vec<_>, _>>()?;

    let file_key = FileKey::init_with_mut(|key| OsRng.fill_bytes(key));
    let keys = Keys::new(&file_key);
    let associated_data = seal::associated_data(name, &keys.commitment, readers);
    let mut entries = Vec::with_capacity(readers.len());
    for (reader, recipient) in readers.iter().zip(&recipients) {
        let wrap = if let Some(recipient) = recipient {
            Wrap::Age(recipient.wrap_file_key(&file_key)?.0)
        } else {
            let fingerprint = reader.key.as_str();
            let wrap = pgp(fingerprint, &file_key).map_err(|source| WriteError::Pgp {
                fingerprint: fingerprint.to_owned(),
                source,
            })?;
            if !(1..=LARGEST_PGP_WRAP).contains(&wrap.len()) {
                return Err(WriteError::PgpWrap(fingerprint.to_owned()));
            }
            Wrap::Pgp(wrap)
        };
        entries.push(Entry {
            reader: reader.clone(),
            wrap,
        });
    }
    let facts = seal::pad(facts::print(facts).as_bytes(), facts_step);
    let value = seal::pad(value.expose(), value_step);
    let file = File {
        name: name.clone(),
        commitment: keys.commitment,
        facts: seal::seal(&keys.facts, &associated_data, &facts),
        value: seal::seal(&keys.value, &associated_data, &value),
        entries,
    };
    let text = file.to_string();
    if text.len() > LARGEST_FILE {
        return Err(WriteError::TooLarge);
    }
    Ok(text)
}

pub fn validate_readers(readers: &[Reader]) -> Result<(), WriteError> {
    checked_recipients(readers)?.try_for_each(|recipient| recipient.map(drop))
}

/// Gives the age recipient of each reader, and `None` for a GPG reader, which `pgp` of [`write`] wraps for.
fn checked_recipients(
    readers: &[Reader],
) -> Result<impl Iterator<Item = Result<Option<age::x25519::Recipient>, WriteError>>, WriteError> {
    if readers.is_empty() {
        return Err(WriteError::NoReaders);
    }
    Ok(readers.iter().enumerate().map(|(index, reader)| {
        let recipient = match &reader.key {
            Key::Age(age) => age.parse::<age::x25519::Recipient>().ok().map(Some),
            Key::Pgp(_) => (!readers[..index].contains(reader)).then_some(None),
        };
        recipient
            .filter(|_| file::is_valid(reader))
            .ok_or(WriteError::Reader(index))
    }))
}

#[must_use]
pub fn has_suffix(path: &Path) -> bool {
    let suffix = b".sauce.yaml";
    path.file_name().is_some_and(|name| {
        let name = name.as_encoded_bytes();
        name.len() > suffix.len() && name.ends_with(suffix)
    })
}

/// Reads the text of a `.sauce.yaml` file, and refuses a file larger than the largest before it reads more than that.
pub fn load(path: &Path) -> io::Result<String> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(LARGEST_FILE as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > LARGEST_FILE {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "the file is larger than 1 MiB, the largest .sauce.yaml file",
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Opens a file with one private key and gives its value and its facts.
///
/// `name` is the name of the secret that the caller expects in this file.
pub fn read(text: &str, name: &Name, opener: Opener<'_>) -> Result<(Value, Facts), ReadError> {
    let (file, keys) = unlock(text, name, opener)?;
    let associated_data = associated_data(&file);
    let facts = seal::open(&keys.facts, &associated_data, &file.facts).ok_or(ReadError::Decrypt)?;
    let value = seal::open(&keys.value, &associated_data, &file.value).ok_or(ReadError::Decrypt)?;
    let facts = seal::unpad(&facts).ok_or(ReadError::Padding)?;
    let value = seal::unpad(&value).ok_or(ReadError::Padding)?;
    let facts = parse_facts(facts)?;
    Ok((Value::from(value.to_vec()), facts))
}

/// Opens a file with one private key and gives its facts only.
///
/// The value is never decrypted, so a file whose `value` does not open still gives its facts.
/// `name` is the name of the secret that the caller expects in this file.
pub fn read_facts(text: &str, name: &Name, opener: Opener<'_>) -> Result<Facts, ReadError> {
    let (file, keys) = unlock(text, name, opener)?;
    let facts =
        seal::open(&keys.facts, &associated_data(&file), &file.facts).ok_or(ReadError::Decrypt)?;
    parse_facts(seal::unpad(&facts).ok_or(ReadError::Padding)?)
}

/// Parses a file, checks its name, and finds the keys that the private key unwraps.
fn unlock(text: &str, name: &Name, opener: Opener<'_>) -> Result<(File, Keys), ReadError> {
    let file = File::parse(text)?;
    if file.name != *name {
        return Err(ReadError::Name);
    }
    // A damaged wrap must stop only its own reader, so the search goes on after a failure.
    let mut keys = Err(ReadError::NotAReader);
    for entry in &file.entries {
        let unwrapped = match (opener, &entry.wrap) {
            (Opener::Age(identity), Wrap::Age(stanzas)) => identity
                .unwrap_stanzas(stanzas)
                .map(|unwrapped| unwrapped.map_err(ReadError::Unwrap)),
            (Opener::Pgp(unwrap), Wrap::Pgp(wrap)) => unwrap(entry.reader.key.as_str(), wrap)
                .map(|unwrapped| unwrapped.map_err(ReadError::Pgp)),
            (Opener::Age(_), Wrap::Pgp(_)) | (Opener::Pgp(_), Wrap::Age(_)) => None,
        };
        match unwrapped {
            None => {}
            Some(Err(error)) => {
                if matches!(keys, Err(ReadError::NotAReader)) {
                    keys = Err(error);
                }
            }
            Some(Ok(file_key)) => {
                let found = Keys::new(&file_key);
                if found.matches(&file.commitment) {
                    keys = Ok(found);
                    break;
                }
                keys = Err(ReadError::Commitment);
            }
        }
    }
    Ok((file, keys?))
}

fn associated_data(file: &File) -> Vec<u8> {
    let readers = file.entries.iter().map(|entry| &entry.reader);
    seal::associated_data(&file.name, &file.commitment, readers)
}

fn parse_facts(unpadded: &[u8]) -> Result<Facts, ReadError> {
    std::str::from_utf8(unpadded)
        .ok()
        .and_then(facts::parse)
        .ok_or(ReadError::Facts)
}

/// Reads the name and the readers of a file, with no key.
///
/// Nothing checks them, because anybody who can push can change the text.
pub fn look(text: &str) -> Result<(Name, Vec<Reader>), ParseError> {
    let file = File::parse(text)?;
    Ok((
        file.name,
        file.entries.into_iter().map(|entry| entry.reader).collect(),
    ))
}

/// Whether the `value` of a file has the step that `bound` chooses, read with no key.
pub fn has_step(text: &str, bound: usize) -> Result<bool, ParseError> {
    let file = File::parse(text)?;
    Ok(seal::step(bound).is_some_and(|step| file.value.len() == step + seal::TAG_BYTES))
}
