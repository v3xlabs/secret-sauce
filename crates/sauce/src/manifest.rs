use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt, fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

use sauce::format::{Name, Reader};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Applied to `nixosConfigurations`, so that one `nix eval` reads every machine.
/// A machine without the `sauce` option declares no secrets and is left out.
const MANIFESTS: &str = r"machines:
builtins.mapAttrs (_: machine: machine.config.sauce.manifest) (
  builtins.removeAttrs machines (
    builtins.filter (name: !(machines.${name}.options ? sauce)) (builtins.attrNames machines)
  )
)";

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("nix eval failed with {0}")]
    Eval(ExitStatus),
    #[error("cannot read {}: {source}", path.display())]
    File {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the manifest is not valid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cannot run nix: {0}")]
    Nix(#[source] io::Error),
}

/// A rule that needs the manifests of all machines at once.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("{machine} declares secret {name:?}, and {source}")]
    Name {
        name: String,
        machine: String,
        #[source]
        source: sauce::format::NameError,
    },
    /// One name has one definition, so two machines that define it give it the same fields.
    #[error("secret {name} has a different {field} on {} and on {}", machines[0], machines[1])]
    Redefined {
        name: Name,
        machines: [String; 2],
        field: &'static str,
    },
    #[error("secrets {} and {} have the same file {}", names[0], names[1], file.display())]
    SameFile { names: [Name; 2], file: PathBuf },
    #[error("{machine} reads secret {name}, and no machine defines it")]
    Undefined { name: String, machine: String },
}

/// What a machine declares about one secret that it defines.
#[derive(Debug, Deserialize, Serialize)]
pub struct Definition {
    /// The `.sauce` file, relative to [`source_root`].
    pub file: PathBuf,
    pub generator: Option<Generator>,
    pub once: Option<Once>,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Generator {
    pub encoding: Option<String>,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub keypair: Option<String>,
}

/// The manifests of the machines of a flake, by machine name.
#[derive(Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Machines(BTreeMap<String, Manifest>);

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    recipient: String,
    admin_recipients: Vec<String>,
    secrets: BTreeMap<String, Definition>,
    read: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Once {
    pub encoding: Option<String>,
    pub bytes: Option<u32>,
}

/// One secret over all machines.
#[derive(Debug)]
pub struct Secret<'a> {
    pub definition: &'a Definition,
    /// The machines that define or read the secret, sorted by name.
    pub machines: Vec<&'a str>,
    /// The admins of those machines, then the machines.
    pub readers: Vec<Reader>,
}

impl Definition {
    /// How `sauce` makes the value, or `None` for a value that `sauce set` gives.
    pub fn declaration(&self) -> Option<String> {
        match (&self.generator, &self.once) {
            (Some(generator), _) => Some(generator.to_string()),
            (None, Some(once)) => Some(once.to_string()),
            (None, None) => None,
        }
    }

    /// The short form of [`Definition::declaration`] for `sauce list`, or `set` for a value that `sauce set` gives.
    /// A declaration with other fields keeps its long form, so that `sauce list` does not hide it.
    pub fn made_by(&self) -> String {
        match (&self.generator, &self.once) {
            (
                Some(Generator {
                    encoding: None,
                    min: None,
                    max: None,
                    keypair: Some(keypair),
                }),
                None,
            ) => keypair.clone(),
            (
                Some(Generator {
                    encoding: Some(encoding),
                    min: Some(min),
                    max: Some(max),
                    keypair: None,
                }),
                None,
            ) => {
                if min == max {
                    format!("{encoding}, {min}")
                } else {
                    format!("{encoding}, {min}<{max}")
                }
            }
            (
                None,
                Some(Once {
                    encoding: Some(encoding),
                    bytes: Some(bytes),
                }),
            ) => format!("once {encoding}, {bytes} B"),
            _ => self.declaration().unwrap_or_else(|| String::from("set")),
        }
    }

    /// The `generator` fact of a value that `sauce` makes, the SHA-256 digest of [`Definition::declaration`].
    pub fn digest(&self) -> Option<[u8; 32]> {
        self.declaration()
            .map(|declaration| Sha256::digest(declaration).into())
    }

    fn difference(&self, other: &Self) -> Option<&'static str> {
        [
            ("file", self.file != other.file),
            ("generator", self.generator != other.generator),
            ("once", self.once != other.once),
            ("note", self.note != other.note),
        ]
        .into_iter()
        .find_map(|(field, differs)| differs.then_some(field))
    }
}

impl fmt::Display for Generator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("generator")?;
        if let Some(encoding) = &self.encoding {
            write!(f, " encoding={encoding}")?;
        }
        if let Some(min) = self.min {
            write!(f, " min={min}")?;
        }
        if let Some(max) = self.max {
            write!(f, " max={max}")?;
        }
        if let Some(keypair) = &self.keypair {
            write!(f, " keypair={keypair}")?;
        }
        Ok(())
    }
}

impl Machines {
    /// Reads every machine of the flake in the folder `flake` with one `nix eval`, which never builds.
    pub fn eval(flake: &Path) -> Result<Self, ReadError> {
        let output = Command::new("nix")
            .current_dir(flake)
            .args(["eval", "--json"])
            .args(["--option", "allow-import-from-derivation", "false"])
            .arg(".#nixosConfigurations")
            .args(["--apply", MANIFESTS])
            .stderr(Stdio::inherit())
            .output()
            .map_err(ReadError::Nix)?;
        if !output.status.success() {
            return Err(ReadError::Eval(output.status));
        }
        Ok(serde_json::from_slice(&output.stdout)?)
    }

    /// Reads a JSON file with the same content as the output of [`Machines::eval`].
    pub fn read(file: &Path) -> Result<Self, ReadError> {
        let json = fs::read(file).map_err(|source| ReadError::File {
            path: file.to_owned(),
            source,
        })?;
        Ok(serde_json::from_slice(&json)?)
    }

    /// Joins the manifests by secret name, and checks the rules that need all machines at once.
    pub fn secrets(&self) -> Result<BTreeMap<Name, Secret<'_>>, RuleError> {
        let mut secrets = BTreeMap::new();
        for (machine, manifest) in &self.0 {
            for (name, definition) in &manifest.secrets {
                let name = name.parse::<Name>().map_err(|source| RuleError::Name {
                    name: name.clone(),
                    machine: machine.clone(),
                    source,
                })?;
                match secrets.entry(name) {
                    Entry::Vacant(entry) => {
                        entry.insert(Secret {
                            definition,
                            machines: vec![machine.as_str()],
                            readers: Vec::new(),
                        });
                    }
                    Entry::Occupied(mut entry) => {
                        let first = entry.get().machines[0];
                        if let Some(field) = entry.get().definition.difference(definition) {
                            return Err(RuleError::Redefined {
                                name: entry.key().clone(),
                                machines: [first.to_owned(), machine.clone()],
                                field,
                            });
                        }
                        entry.get_mut().machines.push(machine);
                    }
                }
            }
        }
        for (machine, manifest) in &self.0 {
            for name in &manifest.read {
                let secret = name
                    .parse::<Name>()
                    .ok()
                    .and_then(|name| secrets.get_mut(&name))
                    .ok_or_else(|| RuleError::Undefined {
                        name: name.clone(),
                        machine: machine.clone(),
                    })?;
                secret.machines.push(machine);
            }
        }
        for secret in secrets.values_mut() {
            secret.machines.sort_unstable();
            secret.machines.dedup();
            for machine in &secret.machines {
                for age in &self.0[*machine].admin_recipients {
                    let admin = Reader {
                        r#for: String::from("admin"),
                        age: age.clone(),
                    };
                    if !secret.readers.contains(&admin) {
                        secret.readers.push(admin);
                    }
                }
            }
            for machine in &secret.machines {
                secret.readers.push(Reader {
                    r#for: (*machine).to_owned(),
                    age: self.0[*machine].recipient.clone(),
                });
            }
        }
        let mut files = BTreeMap::new();
        for (name, secret) in &secrets {
            if let Some(other) = files.insert(&secret.definition.file, name) {
                return Err(RuleError::SameFile {
                    names: [other.clone(), name.clone()],
                    file: secret.definition.file.clone(),
                });
            }
        }
        Ok(secrets)
    }
}

impl fmt::Display for Once {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("once")?;
        if let Some(encoding) = &self.encoding {
            write!(f, " encoding={encoding}")?;
        }
        if let Some(bytes) = self.bytes {
            write!(f, " bytes={bytes}")?;
        }
        Ok(())
    }
}

/// The folder that the `file` of a [`Definition`] is relative to, for the absolute folder `flake`.
/// Nix copies the git repository that holds the flake, or the flake folder alone outside git.
pub fn source_root(flake: &Path) -> &Path {
    flake
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .unwrap_or(flake)
}

#[cfg(test)]
mod tests {
    use super::{Definition, Machines, RuleError};

    #[test]
    fn declaration_that_sauce_cannot_make_keeps_its_long_form() {
        let definition: Definition = serde_json::from_str(
            r#"{ "file": "secrets/a.sauce", "generator": { "encoding": "alphanum", "min": 40 } }"#,
        )
        .unwrap();

        assert_eq!(definition.made_by(), "generator encoding=alphanum min=40");
    }

    #[test]
    fn equal_bounds_show_one_length() {
        let definition: Definition = serde_json::from_str(
            r#"{ "file": "secrets/a.sauce", "generator": { "encoding": "hex", "min": 32, "max": 32 } }"#,
        )
        .unwrap();

        assert_eq!(definition.made_by(), "hex, 32");
    }

    #[test]
    fn two_generators_for_one_name_stop() {
        let machines: Machines = serde_json::from_str(
            r#"{
                "backup": {
                    "recipient": "age1backup",
                    "adminRecipients": ["age1admin"],
                    "read": [],
                    "secrets": {
                        "backup/ssh-key": {
                            "file": "secrets/backup/ssh-key.sauce",
                            "generator": { "keypair": "ssh-ed25519" }
                        }
                    }
                },
                "offsite": {
                    "recipient": "age1offsite",
                    "adminRecipients": ["age1admin"],
                    "read": [],
                    "secrets": {
                        "backup/ssh-key": {
                            "file": "secrets/backup/ssh-key.sauce",
                            "generator": { "keypair": "ssh-rsa" }
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        let error = machines.secrets().unwrap_err();

        assert!(
            matches!(
                &error,
                RuleError::Redefined { name, field: "generator", .. } if name.as_str() == "backup/ssh-key"
            ),
            "{error:?}"
        );
    }
}
