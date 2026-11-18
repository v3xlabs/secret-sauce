//! One `.sauce.yaml` file, as `spec/format.md` describes it.

mod facts;
mod file;
mod name;
mod seal;
mod value;

pub use facts::{Date, DateError, Facts};
pub use file::{ParseError, Reader};
pub use name::{Name, NameError};
pub use value::Value;

use std::fs;
use std::io::{self, Read as _};
use std::path::Path;

use age::Recipient as _;
use age_core::format::FileKey;
use file::{Entry, File};
use rand::{RngCore, rngs::OsRng};
use seal::Keys;

/// The largest `.sauce.yaml` file, in bytes, as `spec/format.md` says.
const LARGEST_FILE: usize = 1024 * 1024;

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
        "reader {0} does not have `admin` or a host name in `for` and an age X25519 recipient in `age`"
    )]
    Reader(usize),
    #[error(
        "the file is larger than 1 MiB, the largest .sauce.yaml file, because it has too many readers"
    )]
    TooLarge,
    #[error("age cannot wrap the file key")]
    Wrap(#[from] age::EncryptError),
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
pub fn write(
    name: &Name,
    value: &Value,
    facts: &Facts,
    bound: usize,
    readers: &[Reader],
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
    let entries = readers
        .iter()
        .zip(&recipients)
        .map(|(reader, recipient)| {
            let (wrap, _labels) = recipient.wrap_file_key(&file_key)?;
            Ok(Entry {
                reader: reader.clone(),
                wrap,
            })
        })
        .collect::<Result<_, WriteError>>()?;
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

fn checked_recipients(
    readers: &[Reader],
) -> Result<impl Iterator<Item = Result<age::x25519::Recipient, WriteError>>, WriteError> {
    if readers.is_empty() {
        return Err(WriteError::NoReaders);
    }
    Ok(readers.iter().enumerate().map(|(index, reader)| {
        let recipient = reader.age.parse::<age::x25519::Recipient>().ok();
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

/// Opens a file with one age identity and gives its value and its facts.
///
/// `name` is the name of the secret that the caller expects in this file.
pub fn read<I: age::Identity + ?Sized>(
    text: &str,
    name: &Name,
    identity: &I,
) -> Result<(Value, Facts), ReadError> {
    let (file, keys) = unlock(text, name, identity)?;
    let associated_data = associated_data(&file);
    let facts = seal::open(&keys.facts, &associated_data, &file.facts).ok_or(ReadError::Decrypt)?;
    let value = seal::open(&keys.value, &associated_data, &file.value).ok_or(ReadError::Decrypt)?;
    let facts = seal::unpad(&facts).ok_or(ReadError::Padding)?;
    let value = seal::unpad(&value).ok_or(ReadError::Padding)?;
    let facts = parse_facts(facts)?;
    Ok((Value::from(value.to_vec()), facts))
}

/// Opens a file with one age identity and gives its facts only.
///
/// The value is never decrypted, so a file whose `value` does not open still gives its facts.
/// `name` is the name of the secret that the caller expects in this file.
pub fn read_facts<I: age::Identity + ?Sized>(
    text: &str,
    name: &Name,
    identity: &I,
) -> Result<Facts, ReadError> {
    let (file, keys) = unlock(text, name, identity)?;
    let facts =
        seal::open(&keys.facts, &associated_data(&file), &file.facts).ok_or(ReadError::Decrypt)?;
    parse_facts(seal::unpad(&facts).ok_or(ReadError::Padding)?)
}

/// Parses a file, checks its name, and finds the keys that the identity unwraps.
fn unlock<I: age::Identity + ?Sized>(
    text: &str,
    name: &Name,
    identity: &I,
) -> Result<(File, Keys), ReadError> {
    let file = File::parse(text)?;
    if file.name != *name {
        return Err(ReadError::Name);
    }
    // A damaged wrap must stop only its own reader, so the search goes on after a failure.
    let mut keys = Err(ReadError::NotAReader);
    for entry in &file.entries {
        match identity.unwrap_stanzas(&entry.wrap) {
            None => {}
            Some(Err(error)) => {
                if matches!(keys, Err(ReadError::NotAReader)) {
                    keys = Err(ReadError::Unwrap(error));
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
