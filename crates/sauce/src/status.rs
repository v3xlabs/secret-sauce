use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
};

use sauce::format::{self, Date, Name};

use crate::{
    identity::{Admin, IdentityError},
    manifest::{Machines, RuleError, Secret},
};

/// How many days before `expires` a secret shows up, so that a token from a provider can be renewed in time.
const SOON_DAYS: i64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum StatusError {
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("cannot read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

/// Prints one row for each thing that needs attention: the name of the secret or the file, then what is wrong.
///
/// The facts are encrypted, so expiry, a changed generator and `revoke` need the key of an admin.
pub fn status(
    machines: &Machines,
    root: &Path,
    identity: Option<&Path>,
) -> Result<(), StatusError> {
    let secrets = machines.secrets()?;
    let admin = Admin::find_if_set(identity)?;
    let today = Date::today();

    let mut rows = Vec::new();
    for (name, secret) in &secrets {
        let path = root.join(&secret.definition.file);
        let text = match format::load(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let fix = if secret.definition.declaration().is_some() {
                    String::from("`sauce generate` makes it")
                } else {
                    format!("`sauce set {name}` gives it one")
                };
                rows.push((name.to_string(), format!("has no file, and {fix}")));
                continue;
            }
            Err(source) => return Err(StatusError::Read { path, source }),
        };
        rows.extend(
            problems(name, &text, secret, admin.as_ref(), today)
                .into_iter()
                .map(|problem| (name.to_string(), problem)),
        );
    }

    let declared: BTreeSet<_> = secrets
        .values()
        .map(|secret| root.join(&secret.definition.file))
        .collect();
    let mut files = Vec::new();
    sauce_files(root, &mut files, &mut rows);
    for path in files.into_iter().filter(|path| !declared.contains(path)) {
        let shown = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let row = match format::load(&path).map(|text| format::look(&text)) {
            Ok(Ok((name, _))) => (
                name.to_string(),
                format!("has the file {shown}, and no machine declares it"),
            ),
            _ => (
                shown,
                String::from("is not a .sauce file that sauce can read"),
            ),
        };
        rows.push(row);
    }

    let width = rows.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    for (name, problem) in &rows {
        println!("{name:width$}  {problem}");
    }
    if rows.is_empty() {
        println!("Nothing needs attention.");
    }
    if admin.is_none() {
        warn_unchecked();
    }
    Ok(())
}

/// Tells on stderr that no key opened the facts, so `sauce status` and `sauce list` did not check them.
pub fn warn_unchecked() {
    eprintln!(
        "The facts are encrypted, so expiry, changed generators and revoke are not checked, because {}.",
        IdentityError::Missing
    );
}

/// What is wrong with the file of a declared secret.
pub fn problems(
    name: &Name,
    text: &str,
    secret: &Secret<'_>,
    admin: Option<&Admin>,
    today: Date,
) -> Vec<String> {
    let mut problems = Vec::new();
    let Ok((found, readers)) = format::look(text) else {
        problems.push(String::from("has a file that is not in the .sauce format"));
        return problems;
    };
    if found != *name {
        problems.push(format!("has a file that holds secret {found}"));
        return problems;
    }
    let declared = readers.iter().all(|reader| secret.readers.contains(reader))
        && secret.readers.iter().all(|reader| readers.contains(reader));
    if !declared {
        problems.push(String::from(
            "has other readers than the machines declare, and `sauce generate` encrypts it again",
        ));
    }
    let Some(admin) = admin else {
        return problems;
    };
    let facts = match admin.open_facts(text, name) {
        Ok(facts) => facts,
        Err(error) => {
            problems.push(format!("cannot be opened: {error}"));
            return problems;
        }
    };
    if let Some(expires) = facts.expires {
        match today.days_until(expires) {
            ..0 => problems.push(format!("expired on {expires}")),
            0 => problems.push(String::from("expires today")),
            days @ 1..=SOON_DAYS => {
                problems.push(format!("expires on {expires}, in {days} days"));
            }
            _ => {}
        }
    }
    if facts
        .generator
        .is_some_and(|digest| Some(digest) != secret.definition.digest())
    {
        let declaration = secret.definition.declaration().unwrap_or_default();
        let fix = if secret.definition.generator.is_some() {
            format!(", and `sauce rotate {name}` makes it again")
        } else {
            String::new()
        };
        problems.push(format!(
            "was made by a declaration other than `{declaration}`{fix}"
        ));
    }
    if facts.revoke {
        let fix = match (&secret.definition.generator, &secret.definition.once) {
            (Some(_), _) => format!(", and `sauce rotate {name}` makes a new one"),
            (None, None) => format!(", and `sauce set {name}` takes a new one"),
            (None, Some(_)) => String::new(),
        };
        problems.push(format!(
            "is marked revoke, because a former reader knows the value{fix}"
        ));
    }
    problems
}

/// Collects every `.sauce` file under `folder`, and skips hidden folders and symbolic links.
/// A folder that cannot be read becomes a row, and the walk goes on.
fn sauce_files(folder: &Path, files: &mut Vec<PathBuf>, rows: &mut Vec<(String, String)>) {
    let entries = match fs::read_dir(folder) {
        Ok(entries) => entries,
        Err(error) => {
            rows.push((
                folder.display().to_string(),
                format!(
                    "cannot be read, so a .sauce file in it can be missing from this list: {error}"
                ),
            ));
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() && !entry.file_name().to_string_lossy().starts_with('.') {
            sauce_files(&path, files, rows);
        } else if kind.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "sauce")
        {
            files.push(path);
        }
    }
}
