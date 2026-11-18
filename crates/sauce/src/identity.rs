use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
};

use age::IdentityFile;
use sauce::format::{self, Facts, Name, Value};

/// The file that sops reads when `SOPS_AGE_KEY_FILE` is not set, relative to the home folder.
const SOPS_KEYS: &str = ".config/sops/age/keys.txt";

/// The private keys of an admin, from one age identity file.
pub struct Admin {
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
    #[error("no key in {} is a reader of {name}", file.display())]
    NotAReader { file: PathBuf, name: Name },
    #[error("cannot open {name}: {source}")]
    Read {
        name: Name,
        #[source]
        source: format::ReadError,
    },
}

impl Admin {
    /// Loads the file of `--identity` or `SAUCE_IDENTITY`, then the files that sops reads, `SOPS_AGE_KEY_FILE` and then `~/.config/sops/age/keys.txt`.
    pub fn find(identity: Option<&Path>) -> Result<Self, IdentityError> {
        let file = match identity {
            Some(file) => file.to_owned(),
            None => sops_file(env::var_os("SOPS_AGE_KEY_FILE"), env::var_os("HOME"))?
                .ok_or(IdentityError::Missing)?,
        };
        let input = fs::File::open(&file)
            .map(BufReader::new)
            .map_err(|source| IdentityError::Read {
                path: file.clone(),
                source,
            })?;
        Self::parse(file, input)
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

    /// Like [`Admin::find`], with `None` when no key is set. A key that cannot be read stays an error.
    pub fn find_if_set(identity: Option<&Path>) -> Result<Option<Self>, IdentityError> {
        match Self::find(identity) {
            Ok(admin) => Ok(Some(admin)),
            Err(IdentityError::Missing) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Opens a file with the first key of the admin that is one of its readers.
    pub fn open(&self, text: &str, name: &Name) -> Result<(Value, Facts), OpenError> {
        self.first_reader(name, |identity| format::read(text, name, identity))
    }

    /// Like [`Admin::open`], and gives the facts only, so the value is never decrypted.
    pub fn open_facts(&self, text: &str, name: &Name) -> Result<Facts, OpenError> {
        self.first_reader(name, |identity| format::read_facts(text, name, identity))
    }

    fn first_reader<T>(
        &self,
        name: &Name,
        read: impl Fn(&(dyn age::Identity + Send + Sync)) -> Result<T, format::ReadError>,
    ) -> Result<T, OpenError> {
        for identity in &self.identities {
            match read(identity.as_ref()) {
                Err(format::ReadError::NotAReader) => {}
                opened => {
                    return opened.map_err(|source| OpenError::Read {
                        name: name.clone(),
                        source,
                    });
                }
            }
        }
        Err(OpenError::NotAReader {
            file: self.file.clone(),
            name: name.clone(),
        })
    }
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

    use super::{Admin, IdentityError, sops_file};

    #[test]
    fn identity_file_with_no_key_is_an_error_that_names_the_file() {
        for text in ["", "# created: 2026-11-18\n\n"] {
            let error = Admin::parse(PathBuf::from("admin.key"), text.as_bytes())
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
