use std::{
    collections::BTreeSet,
    fs,
    io::{self, IsTerminal as _, Write as _},
    path::{Path, PathBuf},
};

use sauce::format::{self, Name, NameError};

use crate::{
    manifest::{FolderError, Machines, RuleError, checked_path},
    rotate::{confirm, matches},
    status::sauce_files,
};

#[derive(Debug, thiserror::Error)]
pub enum RemoveError {
    #[error(transparent)]
    Name(#[from] NameError),
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("{name} is declared by {machines}, and its declaration goes first")]
    Declared { name: Name, machines: String },
    #[error("no .sauce.yaml file of a secret that no machine declares matches {0}")]
    NoMatch(String),
    #[error(transparent)]
    Folder(#[from] FolderError),
    #[error("sauce remove asks on a terminal; use `--yes` to remove with no question")]
    NotInteractive,
    #[error("cannot ask: {0}")]
    Prompt(#[source] io::Error),
    #[error("cannot write the list of removed files, which are {}: {source}", removed.join(", "))]
    Output {
        removed: Vec<String>,
        #[source]
        source: io::Error,
    },
    #[error("{0} is not the file that sauce listed")]
    Changed(Name),
    #[error("sauce stopped at {at}: {cause}; {}", already_removed(removed))]
    Stopped {
        at: String,
        removed: Vec<String>,
        #[source]
        cause: Box<RemoveError>,
    },
    #[error("nothing was removed")]
    NotConfirmed,
    #[error("cannot remove {}: {source}", path.display())]
    Remove {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

struct Leftover {
    name: Name,
    path: PathBuf,
    shown: String,
}

impl Leftover {
    fn file(&self, root: &Path) -> &Path {
        self.path.strip_prefix(root).unwrap_or(&self.path)
    }

    fn label(&self) -> String {
        format!("{} ({})", self.name, self.shown)
    }

    /// Checks the folders and the file, then the folders again, and deletes the file right after.
    /// A folder swapped after the last check is the limit that `checked_path` names.
    fn delete(&self, root: &Path) -> Result<(), RemoveError> {
        checked_path(&self.name, self.file(root), root)?;
        let same = fs::symlink_metadata(&self.path).is_ok_and(|metadata| metadata.is_file())
            && format::load(&self.path)
                .ok()
                .and_then(|text| format::look(&text).ok())
                .is_some_and(|(name, _)| name == self.name);
        if !same {
            return Err(RemoveError::Changed(self.name.clone()));
        }
        checked_path(&self.name, self.file(root), root)?;
        fs::remove_file(&self.path).map_err(|source| RemoveError::Remove {
            path: self.path.clone(),
            source,
        })
    }
}

/// It needs no private key, because it reads only the name in the file.
pub fn remove(
    machines: &Machines,
    root: &Path,
    pattern: &str,
    dry_run: bool,
    yes: bool,
) -> Result<(), RemoveError> {
    let secrets = machines.secrets()?;
    if pattern.contains('*') {
        for (name, secret) in &secrets {
            if matches(pattern, name.as_str()) {
                println!(
                    "skipped {name}, because it is declared by {}",
                    secret.machines.join(", ")
                );
            }
        }
    } else {
        let name = pattern.parse::<Name>()?;
        if let Some(secret) = secrets.get(&name) {
            return Err(RemoveError::Declared {
                name,
                machines: secret.machines.join(", "),
            });
        }
    }

    let declared: BTreeSet<_> = secrets
        .values()
        .map(|secret| root.join(&secret.definition.file))
        .collect();
    let mut files = Vec::new();
    let mut unreadable = Vec::new();
    sauce_files(root, &mut files, &mut unreadable);
    for (folder, error) in &unreadable {
        eprintln!(
            "warning: cannot read {}, so a file in it is not listed: {error}",
            folder.display()
        );
    }
    let mut leftovers = Vec::new();
    for path in files.into_iter().filter(|path| !declared.contains(path)) {
        let Ok(Ok((name, _))) = format::load(&path).map(|text| format::look(&text)) else {
            continue;
        };
        if !matches(pattern, name.as_str()) || secrets.contains_key(&name) {
            continue;
        }
        let file = path.strip_prefix(root).unwrap_or(&path);
        leftovers.push(Leftover {
            path: checked_path(&name, file, root)?,
            shown: file.display().to_string(),
            name,
        });
    }
    if leftovers.is_empty() {
        return Err(RemoveError::NoMatch(pattern.to_owned()));
    }
    leftovers.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.path.cmp(&b.path)));

    if dry_run {
        for leftover in &leftovers {
            println!("would remove {} ({})", leftover.name, leftover.shown);
        }
        return Ok(());
    }
    if !yes {
        if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
            return Err(RemoveError::NotInteractive);
        }
        let items = leftovers.iter().map(Leftover::label);
        if !confirm("These files get removed:", items, "Remove them?")
            .map_err(RemoveError::Prompt)?
        {
            return Err(RemoveError::NotConfirmed);
        }
    }
    let mut removed = Vec::new();
    for leftover in &leftovers {
        if let Err(cause) = leftover.delete(root) {
            return Err(RemoveError::Stopped {
                at: leftover.label(),
                removed,
                cause: Box::new(cause),
            });
        }
        removed.push(leftover.label());
    }
    let mut stdout = io::stdout().lock();
    let failure = removed
        .iter()
        .find_map(|label| writeln!(stdout, "removed {label}").err());
    if let Some(source) = failure {
        return Err(RemoveError::Output { removed, source });
    }
    Ok(())
}

fn already_removed(removed: &[String]) -> String {
    if removed.is_empty() {
        String::from("nothing was removed")
    } else {
        format!("it had removed {}", removed.join(", "))
    }
}
