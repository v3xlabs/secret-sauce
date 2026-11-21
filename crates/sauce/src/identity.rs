use std::{
    cell::OnceCell,
    env,
    ffi::OsString,
    fs,
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
};

use age::IdentityFile;
use sauce::format::{self, Facts, Key, Name, Opener, ReadError, Value};

use crate::gpg::{GpgError, SecretKeys};

/// The file that sops reads when `SOPS_AGE_KEY_FILE` is not set, relative to the home folder.
const SOPS_KEYS: &str = ".config/sops/age/keys.txt";

/// The private keys of an admin: the age keys of one identity file, and the secret keys of gpg for a command that needs the file key.
pub struct Admin {
    age: Option<AgeKeys>,
    /// Listed at the first file that no age key opens, and `None` for a command that never starts gpg.
    gpg: Option<OnceCell<SecretKeys>>,
}

/// The age keys of one identity file.
struct AgeKeys {
    file: PathBuf,
    identities: Vec<Box<dyn age::Identity + Send + Sync>>,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error(
        "no private key of an admin is set, in --identity, SAUCE_IDENTITY, SOPS_AGE_KEY_FILE or ~/.config/sops/age/keys.txt"
    )]
    Missing,
    #[error("the age identity file {} holds no key", path.display())]
    NoKeys { path: PathBuf },
    #[error("cannot read the age identity file {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the age identity file {} is not valid: {source}", path.display())]
    Invalid {
        path: PathBuf,
        #[source]
        source: age::DecryptError,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("no key in {}{} is a reader of {name}", file.display(), if *gpg { " and no secret key of gpg" } else { "" })]
    NotAReader {
        file: PathBuf,
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
                file: age.file.clone(),
                name: name.clone(),
                gpg: self.gpg.is_some(),
            },
            None => OpenError::NoKey { name: name.clone() },
        })
    }
}

impl AgeKeys {
    /// Loads the file of `--identity` or `SAUCE_IDENTITY`, then the files that sops reads, `SOPS_AGE_KEY_FILE` and then `~/.config/sops/age/keys.txt`.
    fn find(identity: Option<&Path>) -> Result<Option<Self>, IdentityError> {
        let file = match identity {
            Some(file) => file.to_owned(),
            None => match sops_file(env::var_os("SOPS_AGE_KEY_FILE"), env::var_os("HOME"))? {
                Some(file) => file,
                None => return Ok(None),
            },
        };
        let input = fs::File::open(&file)
            .map(BufReader::new)
            .map_err(|source| IdentityError::Read {
                path: file.clone(),
                source,
            })?;
        Self::parse(file, input).map(Some)
    }

    fn parse(file: PathBuf, input: impl BufRead) -> Result<Self, IdentityError> {
        let identities = IdentityFile::from_buffer(input)
            .map_err(|source| IdentityError::Read {
                path: file.clone(),
                source,
            })?
            .into_identities()
            .map_err(|source| IdentityError::Invalid {
                path: file.clone(),
                source,
            })?;
        if identities.is_empty() {
            return Err(IdentityError::NoKeys { path: file });
        }
        Ok(Self { file, identities })
    }
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

/// `SOPS_AGE_KEY_FILE`, else the default file of sops in `home`, and `None` when that file does not exist.
/// A file that cannot be looked up, such as one behind a folder that cannot be entered, is an error and not an absent key.
fn sops_file(
    key_file: Option<OsString>,
    home: Option<OsString>,
) -> Result<Option<PathBuf>, IdentityError> {
    if let Some(file) = key_file {
        return Ok(Some(file.into()));
    }
    let Some(home) = home else {
        return Ok(None);
    };
    let file = PathBuf::from(home).join(SOPS_KEYS);
    match fs::metadata(&file) {
        Ok(_) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(IdentityError::Read { path: file, source }),
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, io, path::PathBuf};

    use super::{AgeKeys, IdentityError, sops_file};

    #[test]
    fn identity_file_with_no_key_is_an_error_that_names_the_file() {
        for text in ["", "# created: 2026-11-18\n\n"] {
            let error = AgeKeys::parse(PathBuf::from("admin.key"), text.as_bytes())
                .err()
                .expect("a file with no key is refused");

            assert!(
                matches!(&error, IdentityError::NoKeys { path } if path.ends_with("admin.key")),
                "{error:?}"
            );
            assert!(error.to_string().contains("admin.key"), "{error}");
        }
    }

    #[test]
    fn default_key_file_that_cannot_be_looked_up_is_an_error() {
        // A regular file in the place of the home folder, so the lookup fails with something other than "not found".
        let home = OsString::from(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));

        let error = sops_file(None, Some(home)).expect_err("the lookup fails");

        assert!(
            matches!(
                &error,
                IdentityError::Read { path, source }
                    if path.ends_with("keys.txt") && source.kind() == io::ErrorKind::NotADirectory
            ),
            "{error:?}"
        );
    }

    #[test]
    fn default_key_file_that_does_not_exist_is_no_key() {
        let home = OsString::from(env!("CARGO_MANIFEST_DIR"));

        assert_eq!(sops_file(None, Some(home)).unwrap(), None);
    }
}
