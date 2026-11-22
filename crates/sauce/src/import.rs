//! `sauce import`: secrets from a sops file, through the `sops` program on PATH.

use std::{
    collections::HashSet,
    fmt,
    fs::{self, File},
    io::{self, Read as _, Write as _},
    marker::PhantomData,
    mem,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

use sauce::format::{self, Date, Facts, Name, Value};
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use zeroize::Zeroizing;

use crate::{
    generate, gpg,
    make::Recipe,
    manifest::{Machines, RuleError, Secret},
};

/// The most bytes of a mapping file that sauce reads.
/// A mapping of a few hundred keys is far below it, and a larger file stops the import before sops runs.
const LARGEST_MAPPING: usize = 1024 * 1024;

/// The most bytes of the output of `sops decrypt` that sauce reads.
/// A sops file of a few hundred secrets is far below it, and a larger output stops the import before sauce parses it.
/// The buffer takes this capacity before the read, so that it never moves and leaves a copy of a value behind.
const LARGEST_SOPS_OUTPUT: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("cannot read the mapping file {}: {source}", path.display())]
    ReadMapping {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the mapping file {} is larger than {LARGEST_MAPPING} bytes", .0.display())]
    MappingTooLarge(PathBuf),
    // The error of serde_json can quote a value from the file, so only its place is shown.
    #[error(
        "the mapping file {} is not one JSON object from each sops key to the name of a secret, at line {line}, column {column}",
        path.display()
    )]
    Mapping {
        path: PathBuf,
        line: usize,
        column: usize,
    },
    #[error("cannot run sops: {0}")]
    Sops(#[source] io::Error),
    // The stderr of sops can quote a value, so sauce drops it.
    #[error(
        "sops decrypt failed with {0}, and sauce does not show its message, which can quote a value"
    )]
    SopsFailed(ExitStatus),
    #[error("the output of sops decrypt is larger than {LARGEST_SOPS_OUTPUT} bytes")]
    SopsTooLarge,
    #[error("the output of sops decrypt is not a JSON object")]
    SopsFormat,
    #[error("{0} of the mapped keys cannot be imported, so sauce wrote nothing")]
    Refused(usize),
    #[error("cannot write {}: {source}", path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "cannot put {} in place: {source}, and only the secrets that sauce listed as imported got a .sauce.yaml file",
        path.display()
    )]
    Link {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "cannot write to stdout: {0}, and only the secrets that sauce listed as imported on stderr got a .sauce.yaml file"
    )]
    Stdout(#[source] io::Error),
}

/// The members of a JSON object, in file order, with each key as often as the object has it.
struct Pairs<V>(Vec<(String, V)>);

/// What `sauce import` does with one mapped key.
enum Step<'a> {
    Import {
        key: &'a str,
        name: &'a Name,
        path: PathBuf,
        text: String,
    },
    /// In a dry run, a secret that sauce would import, whose readers are checked and not wrapped for.
    Preview { key: &'a str, name: &'a Name },
    /// The secret has a `.sauce.yaml` file, which sauce never overwrites.
    Skip { key: &'a str, name: &'a Name },
    /// Why the key cannot be imported.
    Refuse(String),
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for Pairs<V> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(PairsVisitor(PhantomData))
    }
}

/// Reads an object as [`Pairs`], because a map keeps only the last member of a key that the object has twice.
struct PairsVisitor<V>(PhantomData<V>);

impl<'de, V: Deserialize<'de>> Visitor<'de> for PairsVisitor<V> {
    type Value = Pairs<V>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Pairs<V>, A::Error> {
        let mut pairs = Vec::new();
        while let Some(pair) = map.next_entry()? {
            pairs.push(pair);
        }
        Ok(Pairs(pairs))
    }
}

/// Writes each secret that the mapping names from the top-level string of its sops key, for the readers that the machines declare.
///
/// It checks and encrypts every mapped key before it writes any file, and it never overwrites a `.sauce.yaml` file.
/// With `dry_run` it lists what it would write and writes nothing.
pub fn import(
    machines: &Machines,
    root: &Path,
    sops: &Path,
    mapping: &Path,
    dry_run: bool,
) -> Result<(), ImportError> {
    let mut text = Vec::new();
    File::open(mapping)
        .and_then(|file| {
            file.take(u64::try_from(LARGEST_MAPPING + 1).expect("the limit fits in u64"))
                .read_to_end(&mut text)
        })
        .map_err(|source| ImportError::ReadMapping {
            path: mapping.to_owned(),
            source,
        })?;
    if text.len() > LARGEST_MAPPING {
        return Err(ImportError::MappingTooLarge(mapping.to_owned()));
    }
    let Pairs(pairs) =
        serde_json::from_slice::<Pairs<String>>(&text).map_err(|error| ImportError::Mapping {
            path: mapping.to_owned(),
            line: error.line(),
            column: error.column(),
        })?;
    let secrets = machines.secrets()?;
    let Pairs(mut values) = decrypt(sops)?;

    let mut steps = Vec::with_capacity(pairs.len());
    let mut keys = HashSet::with_capacity(pairs.len());
    let mut names = HashSet::with_capacity(pairs.len());
    for (key, target) in &pairs {
        let step = if keys.insert(key) {
            match target
                .parse::<Name>()
                .ok()
                .and_then(|name| secrets.get_key_value(&name))
            {
                // The target can be a credential pasted into the wrong field, so only a declared name is printed.
                None => Step::Refuse(format!("{key:?}: no machine declares the target")),
                // Each refusal names only its own key, so the refusals together stay as small as the mapping.
                Some((name, _)) if !names.insert(name) => {
                    Step::Refuse(format!("{key:?}: an earlier sops key also maps to {name}"))
                }
                Some((name, secret)) => step(key, name, secret, root, &mut values, dry_run),
            }
        } else {
            Step::Refuse(format!("{key:?}: the mapping names this sops key twice"))
        };
        steps.push(step);
    }
    // The other values leave memory with the pairs, which serde_json filled and nobody wipes.
    drop(values);

    let refused: Vec<_> = steps
        .iter()
        .filter_map(|step| match step {
            Step::Refuse(reason) => Some(reason),
            Step::Import { .. } | Step::Preview { .. } | Step::Skip { .. } => None,
        })
        .collect();
    if !refused.is_empty() {
        for reason in &refused {
            eprintln!("refuse {reason}");
        }
        return Err(ImportError::Refused(refused.len()));
    }
    publish(steps, dry_run)
}

/// Prints a line for each step, and without `dry_run` puts the file of each import in place.
fn publish(steps: Vec<Step<'_>>, dry_run: bool) -> Result<(), ImportError> {
    let mut staged = if dry_run { Vec::new() } else { stage(&steps)? }.into_iter();
    let mut installed = Vec::new();
    let mut stdout = io::stdout().lock();
    for step in steps {
        let line = match step {
            Step::Skip { key, name } => format!(
                "skip {key:?}: {name} has a .sauce.yaml file, which sauce keeps, and sauce did not compare the values"
            ),
            Step::Preview { key, name } => format!("import {key:?} as {name}"),
            Step::Import {
                key, name, path, ..
            } => {
                let temporary = staged.next().expect("every import has a staged file");
                // A hard link never replaces a file, where a rename would.
                let linked = fs::hard_link(&temporary, &path);
                if let Err(error) = fs::remove_file(&temporary) {
                    eprintln!(
                        "warning: cannot remove the staged file {}: {error}",
                        temporary.display()
                    );
                }
                match linked {
                    Ok(()) => {
                        installed.push((key, name));
                        format!("imported {key:?} as {name}")
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::AlreadyExists
                            && fs::symlink_metadata(&path).is_ok_and(|metadata| {
                                metadata.is_file() || metadata.is_symlink()
                            }) =>
                    {
                        format!(
                            "skip {key:?}: {name} got a .sauce.yaml file during the import, which sauce keeps, and sauce did not compare the values"
                        )
                    }
                    Err(source) => {
                        for temporary in staged {
                            let _ = fs::remove_file(temporary);
                        }
                        return Err(ImportError::Link { path, source });
                    }
                }
            }
            Step::Refuse(_) => continue,
        };
        if let Err(source) = writeln!(stdout, "{line}") {
            for temporary in staged {
                let _ = fs::remove_file(temporary);
            }
            // Without stdout, stderr is the only place left to say which secrets are in place.
            for (key, name) in installed {
                eprintln!("imported {key:?} as {name}");
            }
            return Err(ImportError::Stdout(source));
        }
    }
    if dry_run {
        writeln!(stdout, "This was a dry run, and sauce wrote nothing.")
            .map_err(ImportError::Stdout)?;
    }
    Ok(())
}

/// Writes the file of every import next to its place, before the first link, so that a failed write puts no secret in place.
fn stage(steps: &[Step<'_>]) -> Result<Vec<PathBuf>, ImportError> {
    let mut staged = Vec::new();
    for step in steps {
        let Step::Import { path, text, .. } = step else {
            continue;
        };
        match generate::stage(path, text) {
            Ok(temporary) => staged.push(temporary),
            Err(source) => {
                for temporary in &staged {
                    // No secret is in place yet, and a leftover staged file is only clutter.
                    let _ = fs::remove_file(temporary);
                }
                return Err(ImportError::Write {
                    path: path.clone(),
                    source,
                });
            }
        }
    }
    Ok(staged)
}

/// What to do with one mapped key whose secret a machine declares.
///
/// The value moves out of `values`, so its bytes are not copied, and it is encrypted here, so that a key that cannot be written stops the import before any write.
/// A dry run checks the readers and wraps for none of them, so it starts no gpg.
fn step<'a>(
    key: &'a str,
    name: &'a Name,
    secret: &Secret<'_>,
    root: &Path,
    values: &mut [(String, serde_json::Value)],
    dry_run: bool,
) -> Step<'a> {
    let mut found = values.iter_mut().filter(|(other, _)| other == key);
    let value = match (found.next(), found.next()) {
        (None, _) => return Step::Refuse(format!("{key:?}: the sops file has no such key")),
        (Some(_), Some(_)) => {
            return Step::Refuse(format!("{key:?}: the sops file has this key twice"));
        }
        (Some((_, value)), None) => mem::take(value),
    };
    let serde_json::Value::String(value) = value else {
        return Step::Refuse(format!(
            "{key:?}: the value is not a string at the top level of the sops file"
        ));
    };
    let value = Value::from(value.into_bytes());
    if value.expose().is_empty() {
        return Step::Refuse(format!("{key:?}: the value is empty"));
    }
    let bound = match Recipe::new(secret.definition) {
        Ok(Some(Recipe::Ed25519)) => {
            return Step::Refuse(format!(
                "{key:?}: {name} is a key pair, and sauce generate makes it with its public key"
            ));
        }
        Ok(recipe) => secret.definition.bound(recipe.as_ref()),
        Err(error) => return Step::Refuse(format!("{key:?}: secret {name}: {error}")),
    };
    if value.expose().len() > bound {
        return Step::Refuse(format!(
            "{key:?}: the value is longer than the bound of {name}, {bound} bytes"
        ));
    }
    let path = match secret.path(name, root) {
        Ok(path) => path,
        Err(error) => return Step::Refuse(format!("{key:?}: {error}")),
    };
    match fs::symlink_metadata(&path) {
        // A symbolic link counts as a file, even when it points nowhere.
        Ok(metadata) if metadata.is_file() || metadata.is_symlink() => {
            return Step::Skip { key, name };
        }
        Ok(_) => {
            return Step::Refuse(format!("{key:?}: {} is not a file", path.display()));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Step::Refuse(format!("{key:?}: cannot read {}: {error}", path.display()));
        }
    }
    if dry_run {
        return match format::validate_readers(&secret.readers) {
            Ok(()) => Step::Preview { key, name },
            Err(error) => Step::Refuse(format!("{key:?}: cannot encrypt {name}: {error}")),
        };
    }
    let facts = Facts {
        version: 1,
        set: Date::today(),
        issued: None,
        expires: None,
        generator: None,
        formerly: Vec::new(),
        revoke: false,
    };
    match format::write(name, &value, &facts, bound, &secret.readers, gpg::wrap) {
        Ok(text) => Step::Import {
            key,
            name,
            path,
            text,
        },
        Err(error) => Step::Refuse(format!("{key:?}: cannot encrypt {name}: {error}")),
    }
}

/// Runs `sops decrypt` on PATH, which opens the file with the sops key of the admin, and reads its stdout into memory.
fn decrypt(sops: &Path) -> Result<Pairs<serde_json::Value>, ImportError> {
    let mut child = Command::new("sops")
        .args(["decrypt", "--output-type", "json"])
        .arg(sops)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(ImportError::Sops)?;
    let mut output = Zeroizing::new(Vec::with_capacity(LARGEST_SOPS_OUTPUT + 1));
    let read = child
        .stdout
        .take()
        .expect("stdout of sops is piped")
        .take(u64::try_from(LARGEST_SOPS_OUTPUT + 1).expect("the limit fits in u64"))
        .read_to_end(&mut output);
    if output.len() > LARGEST_SOPS_OUTPUT {
        // The error of the kill is moot, because sops is stopped or has ended either way.
        let _ = child.kill();
        let _ = child.wait();
        return Err(ImportError::SopsTooLarge);
    }
    let status = child.wait().map_err(ImportError::Sops)?;
    if !status.success() {
        return Err(ImportError::SopsFailed(status));
    }
    read.map_err(ImportError::Sops)?;
    // The error of serde_json can quote a value from the output, so it is left out.
    serde_json::from_slice(&output)
        .ok()
        .ok_or(ImportError::SopsFormat)
}
