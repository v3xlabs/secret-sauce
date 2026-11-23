use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt, fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
};

use sauce::format::{self, Key, Name, Reader};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::make::{LARGEST, Recipe};
use crate::spinner::Step;

/// Applied to `nixosConfigurations`, so that one `nix eval` reads every machine.
/// A machine without the `sauce` option declares no secrets and is left out.
const MANIFESTS: &str = r"machines:
builtins.mapAttrs (_: machine: machine.config.sauce.manifest) (
  builtins.removeAttrs machines (
    builtins.filter (name: !(machines.${name}.options ? sauce)) (builtins.attrNames machines)
  )
)";

const MACHINE_MANIFEST: &str =
    "machine: if machine.options ? sauce then machine.config.sauce.manifest else null";

/// Each worker runs its own Nix evaluator, so cap concurrent CPU and memory use.
const RETRY_WORKERS: usize = 4;

/// The bound of a secret with neither `maxLength` nor a recipe, from `spec/format.md`.
const SET_BOUND: usize = 252;

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("nix eval failed with {status}\n{stderr}")]
    Eval { status: ExitStatus, stderr: String },
    #[error("{0}")]
    FailedMachines(MachineFailures),
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
    #[error("secret {name} has the file {}, which must end in .sauce.yaml", file.display())]
    FileSuffix { name: Name, file: PathBuf },
    #[error(
        "secret {name} has maxLength {max_length}, and a file holds a value of 1 to {LARGEST} bytes"
    )]
    MaxLength { name: Name, max_length: usize },
    /// One name has one definition, so two machines that define it give it the same fields.
    #[error("secret {name} has a different {field} on {} and on {}", machines[0], machines[1])]
    Redefined {
        name: Name,
        machines: [String; 2],
        field: &'static str,
    },
    #[error(
        "secret {name} has the file {file:?}, which is not a relative path of plain names, so it can point outside the source root"
    )]
    FileOutside { name: Name, file: PathBuf },
    #[error(
        "the file {} of secret {} is a folder on the way to the file of secret {}",
        file.display(),
        names[0],
        names[1]
    )]
    FileIsFolder { names: [Name; 2], file: PathBuf },
    #[error("secrets {} and {} have the same file {}", names[0], names[1], file.display())]
    SameFile { names: [Name; 2], file: PathBuf },
    #[error("{machine} reads secret {name}, and no machine defines it")]
    Undefined { name: String, machine: String },
    #[error("{machine} has {key:?} in adminRecipients.{list}, and it is not a key of that type")]
    AdminKey {
        machine: String,
        list: &'static str,
        key: String,
    },
    /// The same text as the evaluation error of `nix/module.nix`, for a `--manifest` file that skips it.
    #[error(
        "{0}: sauce.adminRecipients.age and sauce.adminRecipients.pgp are both empty, and every secret needs the key of an admin"
    )]
    NoAdmin(String),
}

/// A folder on the way to the file of a secret, which a write of that file must not go through.
#[derive(Debug, thiserror::Error)]
pub enum FolderError {
    #[error("the folder {} of {name} is a symbolic link", folder.display())]
    Link { name: Name, folder: PathBuf },
    #[error("cannot read {}: {source}", folder.display())]
    Read {
        folder: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// What a machine declares about one secret that it defines.
#[derive(Debug, Deserialize, Serialize)]
pub struct Definition {
    /// The `.sauce.yaml` file, relative to [`source_root`].
    pub file: PathBuf,
    pub generator: Option<Generator>,
    pub once: Option<Once>,
    #[serde(rename = "maxLength")]
    pub max_length: Option<usize>,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Generator {
    pub encoding: Option<String>,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub bytes: Option<u32>,
    pub keypair: Option<String>,
}

/// The manifests of the machines of a flake, by machine name.
#[derive(Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Machines(BTreeMap<String, Manifest>);

pub enum ReadManifests {
    Complete(Machines),
    Partial(PartialManifests),
}

pub struct PartialManifests {
    machines: Machines,
    failures: MachineFailures,
}

#[derive(Debug)]
pub struct MachineFailures(BTreeMap<String, ReadError>);

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    recipient: String,
    admin_recipients: AdminRecipients,
    secrets: BTreeMap<String, Definition>,
    read: Vec<String>,
}

/// The public keys of the admins of a machine, by the program that wraps the file key for them.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdminRecipients {
    age: Vec<String>,
    pgp: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Once {
    pub encoding: Option<String>,
    pub min: Option<u32>,
    pub max: Option<u32>,
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

impl AdminRecipients {
    /// Each key as an admin reader, with the name of its list.
    fn readers(&self) -> impl Iterator<Item = (&'static str, Reader)> {
        let admin = |key| Reader {
            r#for: String::from("admin"),
            key,
        };
        let age = self
            .age
            .iter()
            .map(move |key| ("age", admin(Key::Age(key.clone()))));
        let pgp = self
            .pgp
            .iter()
            .map(move |key| ("pgp", admin(Key::Pgp(key.clone()))));
        age.chain(pgp)
    }
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
        let prefix = if self.once.is_some() { "once " } else { "" };
        match (&self.generator, &self.once) {
            (
                Some(Generator {
                    encoding: None,
                    min: None,
                    max: None,
                    bytes: None,
                    keypair: Some(keypair),
                }),
                None,
            ) => keypair.clone(),
            (
                Some(Generator {
                    encoding: Some(encoding),
                    min: Some(min),
                    max: Some(max),
                    bytes: None,
                    keypair: None,
                }),
                None,
            )
            | (
                None,
                Some(Once {
                    encoding: Some(encoding),
                    min: Some(min),
                    max: Some(max),
                    bytes: None,
                }),
            ) => {
                if min == max {
                    format!("{prefix}{encoding}, {min}")
                } else {
                    format!("{prefix}{encoding}, {min}<{max}")
                }
            }
            (
                Some(Generator {
                    encoding: Some(encoding),
                    min: None,
                    max: None,
                    bytes: Some(bytes),
                    keypair: None,
                }),
                None,
            )
            | (
                None,
                Some(Once {
                    encoding: Some(encoding),
                    min: None,
                    max: None,
                    bytes: Some(bytes),
                }),
            ) => format!("{prefix}{encoding}, {bytes} B"),
            _ => self.declaration().unwrap_or_else(|| String::from("set")),
        }
    }

    /// The `generator` fact of a value that `sauce` makes, the SHA-256 digest of [`Definition::declaration`].
    pub fn digest(&self) -> Option<[u8; 32]> {
        self.declaration()
            .map(|declaration| Sha256::digest(declaration).into())
    }

    /// The longest value of the secret in bytes: `maxLength`, else the longest value of `recipe`, else [`SET_BOUND`].
    pub fn bound(&self, recipe: Option<&Recipe>) -> usize {
        self.max_length
            .unwrap_or_else(|| recipe.map_or(SET_BOUND, Recipe::bound))
    }

    fn difference(&self, other: &Self) -> Option<&'static str> {
        [
            ("file", self.file != other.file),
            ("generator", self.generator != other.generator),
            ("once", self.once != other.once),
            ("maxLength", self.max_length != other.max_length),
            ("note", self.note != other.note),
        ]
        .into_iter()
        .find_map(|(field, differs)| differs.then_some(field))
    }
}

impl Secret<'_> {
    pub fn path(&self, name: &Name, root: &Path) -> Result<PathBuf, FolderError> {
        checked_path(name, &self.definition.file, root)
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
        if let Some(bytes) = self.bytes {
            write!(f, " bytes={bytes}")?;
        }
        if let Some(keypair) = &self.keypair {
            write!(f, " keypair={keypair}")?;
        }
        Ok(())
    }
}

impl fmt::Display for MachineFailures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (name, error)) in self.0.iter().enumerate() {
            if i != 0 {
                writeln!(f)?;
            }
            write!(f, "cannot evaluate machine {name:?}: {error}")?;
        }
        Ok(())
    }
}

impl From<Machines> for ReadManifests {
    fn from(machines: Machines) -> Self {
        Self::Complete(machines)
    }
}

impl ReadManifests {
    pub fn eval(flake: &Path) -> Result<Self, ReadError> {
        match Machines::eval_bulk(flake, true) {
            Ok(machines) => Ok(Self::Complete(machines)),
            Err(error @ ReadError::Eval { .. }) => {
                retry_machines(flake, true).map(Self::Partial).ok_or(error)
            }
            Err(error) => Err(error),
        }
    }

    pub fn failures(&self) -> Option<&MachineFailures> {
        match self {
            Self::Complete(_) => None,
            Self::Partial(partial) => Some(&partial.failures),
        }
    }

    pub fn secrets(&self) -> Result<BTreeMap<Name, Secret<'_>>, RuleError> {
        match self {
            Self::Complete(machines) => machines.secrets(),
            Self::Partial(partial) => partial.machines.join_secrets(true),
        }
    }
}

impl Machines {
    /// Reads every machine of the flake in the folder `flake` with one `nix eval`, which never builds.
    pub fn eval(flake: &Path) -> Result<Self, ReadError> {
        Self::eval_with_lock_write(flake, true)
    }

    pub fn eval_read_only(flake: &Path) -> Result<Self, ReadError> {
        Self::eval_with_lock_write(flake, false)
    }

    fn eval_with_lock_write(flake: &Path, write_lock: bool) -> Result<Self, ReadError> {
        match Self::eval_bulk(flake, write_lock) {
            Ok(machines) => Ok(machines),
            Err(error @ ReadError::Eval { .. }) => Err(retry_machines(flake, write_lock)
                .map_or(error, |partial| ReadError::FailedMachines(partial.failures))),
            Err(error) => Err(error),
        }
    }

    fn eval_bulk(flake: &Path, write_lock: bool) -> Result<Self, ReadError> {
        let output = {
            let _step = Step::show("Evaluating machines…");
            nix_eval(flake, MANIFESTS, write_lock)?
        };
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
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
        self.join_secrets(false)
    }

    fn join_secrets(&self, partial: bool) -> Result<BTreeMap<Name, Secret<'_>>, RuleError> {
        let mut secrets = BTreeMap::new();
        for (machine, manifest) in &self.0 {
            let admins = &manifest.admin_recipients;
            if admins.age.is_empty() && admins.pgp.is_empty() {
                return Err(RuleError::NoAdmin(machine.clone()));
            }
            for (list, admin) in admins.readers() {
                if !format::is_valid(&admin) {
                    return Err(RuleError::AdminKey {
                        machine: machine.clone(),
                        list,
                        key: admin.key.as_str().to_owned(),
                    });
                }
            }
            for (name, definition) in &manifest.secrets {
                let name = name.parse::<Name>().map_err(|source| RuleError::Name {
                    name: name.clone(),
                    machine: machine.clone(),
                    source,
                })?;
                if !format::has_suffix(&definition.file) {
                    return Err(RuleError::FileSuffix {
                        name,
                        file: definition.file.clone(),
                    });
                }
                if let Some(max_length) = definition.max_length
                    && !(1..=LARGEST).contains(&max_length)
                {
                    return Err(RuleError::MaxLength { name, max_length });
                }
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
                let undefined = || RuleError::Undefined {
                    name: name.clone(),
                    machine: machine.clone(),
                };
                let key = name.parse::<Name>().map_err(|source| RuleError::Name {
                    name: name.clone(),
                    machine: machine.clone(),
                    source,
                })?;
                match secrets.get_mut(&key) {
                    Some(secret) => secret.machines.push(machine),
                    None if partial => {}
                    None => return Err(undefined()),
                }
            }
        }
        for secret in secrets.values_mut() {
            secret.machines.sort_unstable();
            secret.machines.dedup();
            for machine in &secret.machines {
                for (_, admin) in self.0[*machine].admin_recipients.readers() {
                    if !secret.readers.contains(&admin) {
                        secret.readers.push(admin);
                    }
                }
            }
            for machine in &secret.machines {
                secret.readers.push(Reader {
                    r#for: (*machine).to_owned(),
                    key: Key::Age(self.0[*machine].recipient.clone()),
                });
            }
        }
        check_files(&secrets)?;
        Ok(secrets)
    }
}

impl fmt::Display for Once {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("once")?;
        if let Some(encoding) = &self.encoding {
            write!(f, " encoding={encoding}")?;
        }
        if let Some(min) = self.min {
            write!(f, " min={min}")?;
        }
        if let Some(max) = self.max {
            write!(f, " max={max}")?;
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

/// `file` in `root`, refused when a folder between `root` and the file is a symbolic link, because a write would land where the link points.
///
/// A folder that becomes a link after this check still takes the write where it points.
pub fn checked_path(name: &Name, file: &Path, root: &Path) -> Result<PathBuf, FolderError> {
    let mut folder = root.to_path_buf();
    for part in file.parent().into_iter().flat_map(Path::components) {
        folder.push(part);
        match fs::symlink_metadata(&folder) {
            Ok(metadata) if metadata.is_symlink() => {
                return Err(FolderError::Link {
                    name: name.clone(),
                    folder,
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(source) => return Err(FolderError::Read { folder, source }),
        }
    }
    Ok(root.join(file))
}

/// Checks that each file of a secret stays in the source root, and that no two files clash.
fn check_files(secrets: &BTreeMap<Name, Secret<'_>>) -> Result<(), RuleError> {
    let mut files = BTreeMap::new();
    for (name, secret) in secrets {
        let file = &secret.definition.file;
        // The Nix module gives a clean relative path, and a `--manifest` file can give any path.
        if file
            .as_os_str()
            .as_encoded_bytes()
            .split(|byte| *byte == b'/')
            .any(|part| matches!(part, b"" | b"." | b".."))
        {
            return Err(RuleError::FileOutside {
                name: name.clone(),
                file: file.clone(),
            });
        }
        if let Some(other) = files.insert(file.as_path(), name) {
            return Err(RuleError::SameFile {
                names: [other.clone(), name.clone()],
                file: file.clone(),
            });
        }
    }
    // A file that is also a folder of another file would make one of the two writes fail, or land in the wrong place.
    for (file, name) in &files {
        if let Some((folder, other)) = file
            .ancestors()
            .skip(1)
            .find_map(|folder| files.get_key_value(folder))
        {
            return Err(RuleError::FileIsFolder {
                names: [(*other).clone(), (*name).clone()],
                file: folder.to_path_buf(),
            });
        }
    }
    Ok(())
}

fn eval_machine(flake: &Path, name: &str, write_lock: bool) -> Result<Option<Manifest>, ReadError> {
    let name = name
        .replace('\\', "\\\\")
        .replace('\r', "\\r")
        .replace('"', "\\\"")
        .replace("${", "\\${");
    let apply = format!("machines: ({MACHINE_MANIFEST}) (builtins.getAttr \"{name}\" machines)");
    let output = nix_eval(flake, &apply, write_lock)?;
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn nix_eval(flake: &Path, apply: &str, write_lock: bool) -> Result<Output, ReadError> {
    let mut command = Command::new("nix");
    crate::identity::without_key(&mut command);
    command.args(["eval", "--json"]);
    if !write_lock {
        command.arg("--no-write-lock-file");
    }
    let output = command
        .current_dir(flake)
        .args(["--option", "allow-import-from-derivation", "false"])
        .args([".#nixosConfigurations", "--apply", apply])
        .output()
        .map_err(ReadError::Nix)?;
    if !output.status.success() {
        return Err(ReadError::Eval {
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr)
                .trim_end()
                .to_owned(),
        });
    }
    Ok(output)
}

fn retry_machines(flake: &Path, write_lock: bool) -> Option<PartialManifests> {
    let _step = Step::show("Evaluating each machine on its own…");
    let output = nix_eval(flake, "builtins.attrNames", write_lock).ok()?;
    let names: Vec<String> = serde_json::from_slice(&output.stdout).ok()?;
    let next = AtomicUsize::new(0);
    let mut machines = BTreeMap::new();
    let mut failures = BTreeMap::new();
    thread::scope(|scope| {
        let workers: Vec<_> = (0..names.len().min(RETRY_WORKERS))
            .map(|_| {
                scope.spawn(|| {
                    std::iter::from_fn(|| names.get(next.fetch_add(1, Ordering::Relaxed)))
                        .map(|name| (name, eval_machine(flake, name, write_lock)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for worker in workers {
            for (name, result) in worker.join().expect("manifest evaluation worker panicked") {
                match result {
                    Ok(Some(manifest)) => {
                        machines.insert(name.clone(), manifest);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        failures.insert(name.clone(), error);
                    }
                }
            }
        }
    });
    (!failures.is_empty()).then_some(PartialManifests {
        machines: Machines(machines),
        failures: MachineFailures(failures),
    })
}

#[cfg(test)]
mod tests {
    use sauce::format::Key;

    use super::{Definition, Machines, RuleError};

    #[test]
    fn declaration_that_sauce_cannot_make_keeps_its_long_form() {
        let definition: Definition = serde_json::from_str(
            r#"{ "file": "secrets/a.sauce.yaml", "generator": { "encoding": "alphanum", "min": 40 } }"#,
        )
        .unwrap();

        assert_eq!(definition.made_by(), "generator encoding=alphanum min=40");
    }

    #[test]
    fn equal_bounds_show_one_length() {
        let definition: Definition = serde_json::from_str(
            r#"{ "file": "secrets/a.sauce.yaml", "generator": { "encoding": "hex", "min": 32, "max": 32 } }"#,
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
                    "adminRecipients": { "age": ["age1admin"], "pgp": [] },
                    "read": [],
                    "secrets": {
                        "backup/ssh-key": {
                            "file": "secrets/backup/ssh-key.sauce.yaml",
                            "generator": { "keypair": "ssh-ed25519" }
                        }
                    }
                },
                "offsite": {
                    "recipient": "age1offsite",
                    "adminRecipients": { "age": ["age1admin"], "pgp": [] },
                    "read": [],
                    "secrets": {
                        "backup/ssh-key": {
                            "file": "secrets/backup/ssh-key.sauce.yaml",
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

    #[test]
    fn file_that_can_leave_the_source_root_stops() {
        for (file, outside) in [
            ("kanidm/freshrss-oauth.sauce.yaml", false),
            ("secrets/..data.sauce.yaml", false),
            ("/etc/a.sauce.yaml", true),
            ("../a.sauce.yaml", true),
            ("secrets/../../a.sauce.yaml", true),
            ("./a.sauce.yaml", true),
            ("secrets//a.sauce.yaml", true),
            ("secrets/a.sauce.yaml/", true),
        ] {
            let machines: Machines = serde_json::from_value(serde_json::json!({
                "notes": {
                    "recipient": "age1notes",
                    "adminRecipients": { "age": ["age1admin"], "pgp": [] },
                    "read": [],
                    "secrets": { "notes/a": { "file": file } }
                }
            }))
            .unwrap();

            let result = machines.secrets();

            assert_eq!(
                matches!(result, Err(RuleError::FileOutside { .. })),
                outside,
                "{file:?}: {:?}",
                result.err()
            );
        }
    }

    #[test]
    fn file_that_is_a_folder_of_another_file_stops() {
        for (other, conflict) in [
            ("secrets/a.sauce.yaml/b.sauce.yaml", true),
            ("secrets/a.sauce.yaml/deeper/b.sauce.yaml", true),
            ("secrets/a.sauce.yamlb/b.sauce.yaml", false),
            ("secrets/a/b.sauce.yaml", false),
        ] {
            let machines: Machines = serde_json::from_value(serde_json::json!({
                "notes": {
                    "recipient": "age1notes",
                    "adminRecipients": { "age": ["age1admin"], "pgp": [] },
                    "read": [],
                    "secrets": {
                        "notes/a": { "file": "secrets/a.sauce.yaml" },
                        "notes/b": { "file": other }
                    }
                }
            }))
            .unwrap();

            let result = machines.secrets();

            assert_eq!(
                matches!(
                    &result,
                    Err(RuleError::FileIsFolder { names, file })
                        if names[0].as_str() == "notes/a" && file.as_os_str() == "secrets/a.sauce.yaml"
                ),
                conflict,
                "{other:?}: {:?}",
                result.err()
            );
        }
    }

    #[test]
    fn max_length_outside_what_a_file_holds_stops() {
        for (max_length, refused) in [(0, true), (1, false), (65_532, false), (65_533, true)] {
            let machines: Machines = serde_json::from_value(serde_json::json!({
                "notes": {
                    "recipient": "age1notes",
                    "adminRecipients": { "age": ["age1admin"], "pgp": [] },
                    "read": [],
                    "secrets": { "notes/a": { "file": "secrets/a.sauce.yaml", "maxLength": max_length } }
                }
            }))
            .unwrap();

            let result = machines.secrets();

            assert_eq!(
                matches!(result, Err(RuleError::MaxLength { .. })),
                refused,
                "{max_length}: {:?}",
                result.err()
            );
        }
    }

    #[test]
    fn admin_key_in_the_wrong_list_stops() {
        let fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567";
        let lower = fingerprint.to_lowercase();
        for (age, pgp, refused) in [
            ("age1admin", fingerprint, None),
            (fingerprint, fingerprint, Some("age")),
            ("age1admin", "age1admin", Some("pgp")),
            ("age1admin", lower.as_str(), Some("pgp")),
        ] {
            let machines: Machines = serde_json::from_value(serde_json::json!({
                "notes": {
                    "recipient": "age1notes",
                    "adminRecipients": { "age": [age], "pgp": [pgp] },
                    "read": [],
                    "secrets": { "notes/a": { "file": "secrets/a.sauce.yaml" } }
                }
            }))
            .unwrap();

            let result = machines.secrets();

            match (&result, refused) {
                (Err(RuleError::AdminKey { list, .. }), Some(expected)) => {
                    assert_eq!(*list, expected);
                }
                (Ok(secrets), None) => {
                    let secret = secrets.values().next().unwrap();
                    let readers: Vec<_> = secret
                        .readers
                        .iter()
                        .map(|reader| (reader.r#for.as_str(), &reader.key))
                        .collect();
                    assert_eq!(
                        readers,
                        [
                            ("admin", &Key::Age(String::from("age1admin"))),
                            ("admin", &Key::Pgp(String::from(fingerprint))),
                            ("notes", &Key::Age(String::from("age1notes"))),
                        ]
                    );
                }
                _ => panic!("{age:?} and {pgp:?}: {:?}", result.err()),
            }
        }
    }

    #[test]
    fn machine_with_no_admin_key_stops() {
        // `backup` has an admin, so the secret that both share would still have one admin reader.
        let machines: Machines = serde_json::from_value(serde_json::json!({
            "backup": {
                "recipient": "age1backup",
                "adminRecipients": { "age": ["age1admin"], "pgp": [] },
                "read": [],
                "secrets": { "backup/a": { "file": "secrets/a.sauce.yaml" } }
            },
            "offsite": {
                "recipient": "age1offsite",
                "adminRecipients": { "age": [], "pgp": [] },
                "read": ["backup/a"],
                "secrets": {}
            }
        }))
        .unwrap();

        let error = machines.secrets().unwrap_err();

        assert_eq!(
            error.to_string(),
            "offsite: sauce.adminRecipients.age and sauce.adminRecipients.pgp are both empty, and every secret needs the key of an admin"
        );
    }

    #[test]
    fn unknown_admin_list_stops() {
        let machines = serde_json::from_value::<Machines>(serde_json::json!({
            "notes": {
                "recipient": "age1notes",
                "adminRecipients": { "age": ["age1admin"], "pgp": [], "gpg": ["0123456789ABCDEF0123456789ABCDEF01234567"] },
                "read": [],
                "secrets": {}
            }
        }));

        let error = machines.unwrap_err().to_string();

        assert!(error.contains("unknown field `gpg`"), "{error}");
    }
}
