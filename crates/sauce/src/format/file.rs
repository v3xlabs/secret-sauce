use std::{collections::HashSet, fmt, iter::Peekable, str::Lines};

use age_core::format::Stanza;
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD as BASE64};

use super::{LARGEST_PGP_WRAP, Name, seal};

/// The longest host name, the length of one DNS label, as `networking.hostName` of NixOS allows.
const HOST_NAME_BYTES: usize = 63;

/// The characters of a GPG fingerprint in `pgp`: the 20 bytes of a version 4 key in hex, which is the version that gpg 2.4 makes.
const FINGERPRINT_CHARS: usize = 40;

/// The public key of a reader, from the line `age` or `pgp` of its entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// An age recipient, such as `age1...`.
    Age(String),
    /// The fingerprint of a GPG key, in upper case hex.
    Pgp(String),
}

/// One reader of a secret, as an entry in `keys` names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reader {
    /// `admin`, or the name of a host.
    pub r#for: String,
    pub key: Key,
}

/// A text that is not a `.sauce.yaml` file.
#[derive(Debug, thiserror::Error)]
#[error("line {line} of the file is not in the `.sauce.yaml` format")]
pub struct ParseError {
    pub line: usize,
}

/// The fields of a `.sauce.yaml` file, decoded and not checked by any key.
pub struct File {
    pub name: Name,
    pub commitment: [u8; 32],
    pub facts: Vec<u8>,
    pub value: Vec<u8>,
    pub entries: Vec<Entry>,
}

pub struct Entry {
    pub reader: Reader,
    pub wrap: Wrap,
}

/// The file key, wrapped for one reader.
pub enum Wrap {
    /// The stanzas that the age library gives for the recipient.
    Age(Vec<Stanza>),
    /// The message that gpg wrote for the fingerprint.
    Pgp(Vec<u8>),
}

struct Cursor<'a> {
    lines: Peekable<Lines<'a>>,
    number: usize,
}

impl File {
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut lines = Cursor {
            lines: text.lines().peekable(),
            number: 0,
        };
        lines.line("sauce: 1")?;
        let name = lines.next("name: ")?.parse().ok();
        let name = lines.check(name)?;
        let commitment = base64(lines.next("commitment: ")?).and_then(|key| key.try_into().ok());
        let commitment = lines.check(commitment)?;
        let facts = sealed(lines.next("facts: ")?);
        let facts = lines.check(facts)?;
        let value = sealed(lines.next("value: ")?);
        let value = lines.check(value)?;
        lines.line("keys:")?;
        let mut entries = Vec::new();
        let mut fingerprints = HashSet::new();
        while let Some(host) = lines.next_if("  - for: ") {
            let entry = if let Some(age) = lines.next_if("    age: ") {
                let reader = Reader {
                    r#for: host.to_owned(),
                    key: Key::Age(age.to_owned()),
                };
                lines.check(is_valid(&reader).then_some(()))?;
                lines.line("    wrap:")?;
                let mut wrap = Vec::new();
                while let Some(stanza) = lines.next_if("      - ") {
                    wrap.push(lines.check(parse_stanza(stanza))?);
                }
                lines.check((!wrap.is_empty()).then_some(()))?;
                Entry {
                    reader,
                    wrap: Wrap::Age(wrap),
                }
            } else {
                let fingerprint = lines.next("    pgp: ")?;
                let reader = Reader {
                    r#for: host.to_owned(),
                    key: Key::Pgp(fingerprint.to_owned()),
                };
                // One entry for each fingerprint, so that gpg gets at most one try for a key in each file.
                let unique = fingerprints.insert(fingerprint);
                lines.check((is_valid(&reader) && unique).then_some(()))?;
                let wrap = pgp_wrap(lines.next("    wrap: ")?);
                Entry {
                    reader,
                    wrap: Wrap::Pgp(lines.check(wrap)?),
                }
            };
            entries.push(entry);
        }
        lines.check((!entries.is_empty()).then_some(()))?;
        let file = Self {
            name,
            commitment,
            facts,
            value,
            entries,
        };
        // Comparing the input with the printed file leaves one spelling for each field.
        let printed = file.to_string();
        if printed != text {
            let same = printed
                .split_inclusive('\n')
                .zip(text.split_inclusive('\n'))
                .take_while(|(printed, text)| printed == text)
                .count();
            return Err(ParseError { line: same + 1 });
        }
        Ok(file)
    }
}

impl fmt::Display for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "sauce: 1")?;
        writeln!(f, "name: {}", self.name)?;
        writeln!(f, "commitment: {}", BASE64.encode(self.commitment))?;
        writeln!(f, "facts: {}", BASE64.encode(&self.facts))?;
        writeln!(f, "value: {}", BASE64.encode(&self.value))?;
        writeln!(f, "keys:")?;
        for entry in &self.entries {
            writeln!(f, "  - for: {}", entry.reader.r#for)?;
            match &entry.reader.key {
                Key::Age(age) => writeln!(f, "    age: {age}")?,
                Key::Pgp(fingerprint) => writeln!(f, "    pgp: {fingerprint}")?,
            }
            match &entry.wrap {
                Wrap::Age(stanzas) => {
                    writeln!(f, "    wrap:")?;
                    for stanza in stanzas {
                        write!(f, "      - {}", stanza.tag)?;
                        for arg in &stanza.args {
                            write!(f, " {arg}")?;
                        }
                        writeln!(f, " {}", BASE64.encode(&stanza.body))?;
                    }
                }
                Wrap::Pgp(message) => writeln!(f, "    wrap: {}", BASE64.encode(message))?,
            }
        }
        Ok(())
    }
}

impl<'a> Cursor<'a> {
    fn check<T>(&self, value: Option<T>) -> Result<T, ParseError> {
        value.ok_or(ParseError { line: self.number })
    }

    fn line(&mut self, line: &str) -> Result<(), ParseError> {
        let rest = self.next(line)?;
        self.check(rest.is_empty().then_some(()))
    }

    fn next(&mut self, prefix: &str) -> Result<&'a str, ParseError> {
        self.number += 1;
        let rest = self.lines.next().and_then(|line| line.strip_prefix(prefix));
        self.check(rest)
    }

    fn next_if(&mut self, prefix: &str) -> Option<&'a str> {
        let line = self.lines.next_if(|line| line.starts_with(prefix))?;
        self.number += 1;
        Some(&line[prefix.len()..])
    }
}

impl Key {
    /// The age recipient or the fingerprint, as the line of the entry spells it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Age(key) | Self::Pgp(key) => key,
        }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn base64(text: &str) -> Option<Vec<u8>> {
    BASE64.decode(text).ok()
}

/// The bytes that a text in base64 with no padding decodes to.
fn decoded_length(text: &str) -> usize {
    // 4 characters per 3 bytes, and a last group of 2 or 3 characters for 1 or 2 bytes.
    text.len() / 4 * 3 + (text.len() % 4).saturating_sub(1)
}

/// Decodes `facts` or `value`, and refuses a length that no step gives before it decodes anything.
fn sealed(text: &str) -> Option<Vec<u8>> {
    seal::is_sealed_length(decoded_length(text)).then(|| base64(text))?
}

/// Decodes the wrap of a GPG reader, and refuses an empty one or one larger than the largest before it decodes anything.
fn pgp_wrap(text: &str) -> Option<Vec<u8>> {
    (1..=LARGEST_PGP_WRAP)
        .contains(&decoded_length(text))
        .then(|| base64(text))?
}

/// Parses an age stanza as one line: the type, each argument and the body in base64, with single spaces.
///
/// The type and the arguments use only `A-Z`, `a-z`, `0-9`, `+`, `/`, `.`, `_` and `-`, and the type starts with a letter or a digit.
/// So the line stays one plain YAML scalar.
fn parse_stanza(line: &str) -> Option<Stanza> {
    let mut words: Vec<&str> = line.split(' ').collect();
    let body = base64(words.pop()?)?;
    let (tag, args) = words.split_first()?;
    let word = |word: &&str| {
        !word.is_empty()
            && word
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+/._-".contains(&byte))
    };
    let valid = words.iter().all(word) && tag.as_bytes()[0].is_ascii_alphanumeric();
    (valid && !body.is_empty()).then(|| Stanza {
        tag: (*tag).to_owned(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        body,
    })
}

/// Whether `for` and the key of a reader can stand in a file.
///
/// A GPG key reads only for `admin`, because a machine reads with its age key.
#[must_use]
pub fn is_valid(reader: &Reader) -> bool {
    let alnum = u8::is_ascii_alphanumeric;
    let host = reader.r#for.as_bytes();
    let key = match &reader.key {
        Key::Age(age) => {
            let age = age.strip_prefix("age1").unwrap_or_default();
            !age.is_empty()
                && age
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        }
        Key::Pgp(fingerprint) => reader.r#for == "admin" && is_fingerprint(fingerprint),
    };
    (1..=HOST_NAME_BYTES).contains(&host.len())
        && host.first().is_some_and(alnum)
        && host.last().is_some_and(alnum)
        && host.iter().all(|byte| alnum(byte) || b"_-".contains(byte))
        && key
}

fn is_fingerprint(key: &str) -> bool {
    key.len() == FINGERPRINT_CHARS
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}
