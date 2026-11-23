use std::{
    cell::OnceCell,
    env,
    ffi::OsString,
    fmt, fs,
    io::{self, BufRead, BufReader, Read as _},
    os::unix::ffi::OsStringExt as _,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

use age::IdentityFile;
use sauce::format::{self, Facts, Key, Name, Opener, ReadError, Value};
use zeroize::Zeroizing;

use crate::gpg::{GpgError, SecretKeys};

const KEY_VARIABLE: &str = "SOPS_AGE_KEY";
const KEY_COMMAND: &str = "SOPS_AGE_KEY_CMD";

/// The most bytes that sauce reads from the key command, so that a command cannot fill the memory.
const COMMAND_OUTPUT_LIMIT: usize = 1 << 16;

/// The key file of sops, relative to a config folder.
const SOPS_KEYS: &str = "sops/age/keys.txt";

/// The private keys of an admin: the age keys of one identity file, and the secret keys of gpg for a command that needs the file key.
pub struct Admin {
    age: Option<AgeKeys>,
    /// Listed at the first file that no age key opens, and `None` for a command that never starts gpg.
    gpg: Option<OnceCell<SecretKeys>>,
}

/// The age keys of one source.
struct AgeKeys {
    from: KeySource,
    identities: Vec<Box<dyn age::Identity + Send + Sync>>,
}

/// Where the age keys of an admin are, named in an error and never with their text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySource {
    File(PathBuf),
    Variable,
    Command,
}

impl fmt::Display for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(path) => write!(f, "the age identity file {}", path.display()),
            Self::Variable => f.write_str(KEY_VARIABLE),
            Self::Command => f.write_str(KEY_COMMAND),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error(
        "no private key of an admin is set, in --identity, SAUCE_IDENTITY, SOPS_AGE_KEY, SOPS_AGE_KEY_FILE, SOPS_AGE_KEY_CMD or the sops key file in XDG_CONFIG_HOME or ~/.config"
    )]
    Missing,
    #[error("{from} holds no key")]
    NoKeys { from: KeySource },
    #[error("cannot read {from}: {source}")]
    Read {
        from: KeySource,
        #[source]
        source: io::Error,
    },
    #[error("{from} is not valid: {source}")]
    Invalid {
        from: KeySource,
        #[source]
        source: age::DecryptError,
    },
    #[error("{KEY_COMMAND} exited with {0}")]
    CommandExit(ExitStatus),
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("no key in {from}{} is a reader of {name}", if *gpg { " and no secret key of gpg" } else { "" })]
    NotAReader {
        from: KeySource,
        name: Name,
        gpg: bool,
    },
    #[error(
        "{}, and no secret key of gpg is a reader of {name}",
        IdentityError::Missing
    )]
    NoKey { name: Name },
    #[error("cannot list the secret keys of gpg: {0}")]
    Gpg(#[from] GpgError),
    #[error("cannot open {name}: {source}")]
    Read {
        name: Name,
        #[source]
        source: format::ReadError,
    },
}

impl Admin {
    /// Loads the age keys, as [`Admin::find_age`] does, and opens with gpg a file that no age key opens.
    pub fn find(identity: Option<&Path>) -> Result<Self, IdentityError> {
        Ok(Self {
            age: AgeKeys::find(identity)?,
            gpg: Some(OnceCell::new()),
        })
    }

    /// Loads the age keys, and gives `None` when no age identity file is set. A key that cannot be read stays an error.
    ///
    /// It never starts gpg, so it suits a command that opens many files, where a card would ask once for each.
    pub fn find_age(identity: Option<&Path>) -> Result<Option<Self>, IdentityError> {
        Ok(AgeKeys::find(identity)?.map(|age| Self {
            age: Some(age),
            gpg: None,
        }))
    }

    /// Opens a file with the first key of the admin that is one of its readers.
    pub fn open(&self, text: &str, name: &Name) -> Result<(Value, Facts), OpenError> {
        self.first_reader(text, name, |opener| format::read(text, name, opener))
    }

    /// Like [`Admin::open`], and gives the facts only, so the value is never decrypted.
    pub fn open_facts(&self, text: &str, name: &Name) -> Result<Facts, OpenError> {
        self.first_reader(text, name, |opener| format::read_facts(text, name, opener))
    }

    fn first_reader<T>(
        &self,
        text: &str,
        name: &Name,
        read: impl Fn(Opener<'_>) -> Result<T, ReadError>,
    ) -> Result<T, OpenError> {
        let opened = |result: Result<T, ReadError>| {
            result.map_err(|source| OpenError::Read {
                name: name.clone(),
                source,
            })
        };
        // A wrap that fails stops only its own reader, so the search goes on and keeps the first failure.
        let mut failed = None;
        for identity in self.age.iter().flat_map(|age| &age.identities) {
            match read(Opener::Age(identity.as_ref())) {
                Err(ReadError::NotAReader) => {}
                Err(error) if is_wrap_failure(&error) => {
                    failed.get_or_insert(error);
                }
                result => return opened(result),
            }
        }
        if let Some(gpg) = self.gpg.as_ref().filter(|_| has_pgp_reader(text)) {
            let keys = if let Some(keys) = gpg.get() {
                keys
            } else {
                let found = SecretKeys::find()?;
                gpg.get_or_init(|| found)
            };
            let unwrap = |fingerprint: &str, wrap: &[u8]| {
                keys.unwrap(fingerprint, wrap)
                    .map(|unwrapped| unwrapped.map_err(io::Error::other))
            };
            match read(Opener::Pgp(&unwrap)) {
                Err(ReadError::NotAReader) => {}
                Err(error) if is_wrap_failure(&error) => {
                    failed.get_or_insert(error);
                }
                result => return opened(result),
            }
        }
        if let Some(error) = failed {
            return opened(Err(error));
        }
        Err(match &self.age {
            Some(age) => OpenError::NotAReader {
                from: age.from.clone(),
                name: name.clone(),
                gpg: self.gpg.is_some(),
            },
            None => OpenError::NoKey { name: name.clone() },
        })
    }
}

impl AgeKeys {
    /// Loads the first source that is set, in the order that sops reads them, after `--identity` and `SAUCE_IDENTITY`.
    fn find(identity: Option<&Path>) -> Result<Option<Self>, IdentityError> {
        if let Some(file) = identity {
            return Self::from_file(file.to_owned()).map(Some);
        }
        if let Some(keys) = env::var_os(KEY_VARIABLE).filter(|keys| !keys.is_empty()) {
            return with_text(keys, KeySource::Variable, Self::from_variable).map(Some);
        }
        if let Some(file) = env::var_os("SOPS_AGE_KEY_FILE") {
            return Self::from_file(file.into()).map(Some);
        }
        if let Some(command) = env::var_os(KEY_COMMAND).filter(|command| !command.is_empty()) {
            return with_text(command, KeySource::Command, Self::from_command).map(Some);
        }
        match default_file(env::var_os("XDG_CONFIG_HOME"), env::var_os("HOME"))? {
            Some(file) => Self::from_file(file).map(Some),
            None => Ok(None),
        }
    }

    fn from_file(file: PathBuf) -> Result<Self, IdentityError> {
        let input = fs::File::open(&file)
            .map(BufReader::new)
            .map_err(|source| IdentityError::Read {
                from: KeySource::File(file.clone()),
                source,
            })?;
        Self::parse(KeySource::File(file), input)
    }

    /// The keys sit in the text as in a file, and a line can hold several keys, as sops allows.
    fn from_variable(keys: &str) -> Result<Self, IdentityError> {
        // The words and their line ends fit in the length of the text and one more, so the buffer never grows and leaves no copy of a key in freed memory.
        let mut lines = Zeroizing::new(String::with_capacity(keys.len() + 1));
        for line in keys.lines().filter(|line| !line.starts_with('#')) {
            for word in line.split_whitespace() {
                // sops reads each word as a key, so a word that starts a comment for age is no key.
                if word.starts_with('#') {
                    return Err(IdentityError::Read {
                        from: KeySource::Variable,
                        source: io::Error::new(io::ErrorKind::InvalidData, "a word is not a key"),
                    });
                }
                lines.push_str(word);
                lines.push('\n');
            }
        }
        Self::parse(KeySource::Variable, lines.as_bytes())
    }

    /// The command cannot read stdin, so it takes nothing that is meant for sauce.
    fn from_command(command: &str) -> Result<Self, IdentityError> {
        let read = |source| IdentityError::Read {
            from: KeySource::Command,
            source,
        };
        let words = split_command(command)
            .map_err(|message| read(io::Error::new(io::ErrorKind::InvalidInput, message)))?;
        let Some((program, args)) = words.split_first() else {
            return Err(read(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the command is empty",
            )));
        };
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(read)?;
        let mut stdout = child
            .stdout
            .take()
            .expect("stdout of the key command is piped");
        // One buffer takes the whole output, so that no growth leaves a copy of a key in freed memory.
        let mut keys = Zeroizing::new(vec![0; COMMAND_OUTPUT_LIMIT + 1]);
        let mut filled = 0;
        while filled < keys.len() {
            match stdout.read(&mut keys[filled..]) {
                Ok(0) => break,
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(read(error)),
            }
        }
        if filled > COMMAND_OUTPUT_LIMIT {
            return Err(read(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("its output is longer than {COMMAND_OUTPUT_LIMIT} bytes"),
            )));
        }
        let status = child.wait().map_err(read)?;
        if !status.success() {
            return Err(IdentityError::CommandExit(status));
        }
        let keys = std::str::from_utf8(&keys[..filled]).map_err(|_ignored| {
            read(io::Error::new(
                io::ErrorKind::InvalidData,
                "the output is not UTF-8",
            ))
        })?;
        Self::parse(KeySource::Command, keys.as_bytes())
    }

    fn parse(from: KeySource, input: impl BufRead) -> Result<Self, IdentityError> {
        let identities = IdentityFile::from_buffer(input)
            .map_err(|source| IdentityError::Read {
                from: from.clone(),
                source,
            })?
            .into_identities()
            .map_err(|source| IdentityError::Invalid {
                from: from.clone(),
                source,
            })?;
        if identities.is_empty() {
            return Err(IdentityError::NoKeys { from });
        }
        Ok(Self { from, identities })
    }
}

/// Keeps the inline key of `SOPS_AGE_KEY` out of a program that sauce starts, as it does for gpg.
/// Only `sops` in `sauce import` gets it.
pub fn without_key(command: &mut Command) -> &mut Command {
    command.env_remove(KEY_VARIABLE)
}

/// Gives the text of an environment variable to `read`, or the error that names the variable.
/// The bytes stay in a `Zeroizing` buffer while they are checked, also when they are not UTF-8.
fn with_text<T>(
    value: OsString,
    from: KeySource,
    read: impl FnOnce(&str) -> Result<T, IdentityError>,
) -> Result<T, IdentityError> {
    let bytes = Zeroizing::new(value.into_vec());
    let text = std::str::from_utf8(&bytes).map_err(|_ignored| IdentityError::Read {
        from,
        source: io::Error::new(io::ErrorKind::InvalidData, "the value is not UTF-8"),
    })?;
    read(text)
}

/// Whether the file has a GPG reader, so that a file of age readers only never starts gpg.
fn has_pgp_reader(text: &str) -> bool {
    format::look(text).is_ok_and(|(_, readers)| {
        readers
            .iter()
            .any(|reader| matches!(reader.key, Key::Pgp(_)))
    })
}

/// Whether a read failed at the wrap of one reader, so that another reader can still open the file.
fn is_wrap_failure(error: &ReadError) -> bool {
    matches!(
        error,
        ReadError::Unwrap(_) | ReadError::Pgp(_) | ReadError::Commitment
    )
}

/// The sops key file in the config folder `xdg`, then in `~/.config` of `home`, and `None` when neither exists.
/// A relative `xdg` is ignored, as the XDG specification says.
/// A file that cannot be looked up, such as one behind a folder that cannot be entered, is an error and not an absent key.
fn default_file(
    xdg: Option<OsString>,
    home: Option<OsString>,
) -> Result<Option<PathBuf>, IdentityError> {
    let xdg = xdg.map(PathBuf::from).filter(|folder| folder.is_absolute());
    let home = home.map(|home| PathBuf::from(home).join(".config"));
    for folder in [xdg, home].into_iter().flatten() {
        let file = folder.join(SOPS_KEYS);
        match fs::metadata(&file) {
            Ok(_) => return Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(IdentityError::Read {
                    from: KeySource::File(file),
                    source,
                });
            }
        }
    }
    Ok(None)
}

/// Splits `line` into words as `google/shlex` does for sops, and starts no shell, so `$` and `;` stay text.
fn split_command(line: &str) -> Result<Vec<String>, &'static str> {
    const OPEN_QUOTE: &str = "the command has a quote that never closes";
    const OPEN_ESCAPE: &str = "the command ends in a backslash";
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                started = true;
                loop {
                    match chars.next().ok_or(OPEN_QUOTE)? {
                        '\'' => break,
                        c => word.push(c),
                    }
                }
            }
            '"' => {
                started = true;
                loop {
                    match chars.next().ok_or(OPEN_QUOTE)? {
                        '"' => break,
                        '\\' => word.push(chars.next().ok_or(OPEN_ESCAPE)?),
                        c => word.push(c),
                    }
                }
            }
            '\\' => {
                started = true;
                word.push(chars.next().ok_or(OPEN_ESCAPE)?);
            }
            '#' if !started => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
            }
            ' ' | '\t' | '\r' | '\n' => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            c => {
                started = true;
                word.push(c);
            }
        }
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, io, path::PathBuf};

    use super::{AgeKeys, IdentityError, KeySource, default_file, split_command};

    #[test]
    fn identity_file_with_no_key_is_an_error_that_names_the_file() {
        for text in ["", "# created: 2026-11-18\n\n"] {
            let from = KeySource::File(PathBuf::from("admin.key"));
            let error = AgeKeys::parse(from, text.as_bytes())
                .err()
                .expect("a file with no key is refused");

            assert!(
                matches!(&error, IdentityError::NoKeys { from: KeySource::File(path) } if path.ends_with("admin.key")),
                "{error:?}"
            );
            assert!(error.to_string().contains("admin.key"), "{error}");
        }
    }

    #[test]
    fn default_key_file_that_cannot_be_looked_up_is_an_error() {
        // A regular file in the place of the home folder, so the lookup fails with something other than "not found".
        let home = OsString::from(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));

        let error = default_file(None, Some(home)).expect_err("the lookup fails");

        assert!(
            matches!(
                &error,
                IdentityError::Read { from: KeySource::File(path), source }
                    if path.ends_with("keys.txt") && source.kind() == io::ErrorKind::NotADirectory
            ),
            "{error:?}"
        );
    }

    #[test]
    fn default_key_file_that_does_not_exist_is_no_key() {
        let home = OsString::from(env!("CARGO_MANIFEST_DIR"));

        assert_eq!(default_file(None, Some(home)).unwrap(), None);
    }

    #[test]
    fn command_splits_like_sops_does() {
        assert_eq!(
            split_command(r#"pass show 'my key' "a \"b\" \q" c\ d # a comment"#).unwrap(),
            ["pass", "show", "my key", r#"a "b" q"#, "c d"]
        );
        assert_eq!(
            split_command(r#"cat $HOME; "" x#y"#).unwrap(),
            ["cat", "$HOME;", "", "x#y"]
        );
        assert_eq!(split_command("a\u{a0}b c").unwrap(), ["a\u{a0}b", "c"]);
        assert!(split_command("'unterminated").is_err());
        assert!(split_command("trailing\\").is_err());
        assert_eq!(
            split_command("  # nothing but a comment").unwrap(),
            Vec::<String>::new()
        );
    }
}
