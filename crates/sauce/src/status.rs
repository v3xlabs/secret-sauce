use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
};

use sauce::format::{self, Date, Name};

use crate::{
    color::{Color, Palette},
    identity::{Admin, IdentityError, OpenError},
    manifest::{ReadManifests, RuleError, Secret},
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

struct Row {
    name: String,
    problem: Problem,
}

enum Problem {
    Unset,
    NoReader,
    Warning(String),
}

impl Row {
    fn warning(name: String, detail: String) -> Self {
        Self {
            name,
            problem: Problem::Warning(detail),
        }
    }
}

/// What is wrong with the file of one declared secret.
pub struct Findings {
    pub problems: Vec<String>,
    pub no_reader: bool,
}

impl Findings {
    fn of(problems: Vec<String>) -> Self {
        Self {
            problems,
            no_reader: false,
        }
    }
}

pub struct Evaluator<'a> {
    admin: Option<&'a Admin>,
    today: Date,
    partial: bool,
    tried: usize,
    inaccessible: usize,
    file: Option<PathBuf>,
}

impl<'a> Evaluator<'a> {
    pub fn new(admin: Option<&'a Admin>, partial: bool) -> Self {
        Self {
            admin,
            today: Date::today(),
            partial,
            tried: 0,
            inaccessible: 0,
            file: None,
        }
    }

    /// True when files were tried and the key of the admin is a reader of none of them,
    /// which says more about the key than about the files.
    pub fn all_inaccessible(&self) -> bool {
        self.inaccessible > 0 && self.inaccessible == self.tried
    }

    /// Tells on stderr what the run could not check.
    pub fn finish(self) {
        let all_inaccessible = self.all_inaccessible();
        match (self.admin, self.file) {
            (None, _) => warn_unchecked(),
            (Some(_), Some(file)) if all_inaccessible => eprintln!(
                "No key in {} is a reader of the secrets checked. Facts were not checked. Use `--identity <key-file>` to pick another key.",
                file.display()
            ),
            (Some(_), _) => {}
        }
    }

    /// What is wrong with the file of a declared secret.
    pub fn check(&mut self, name: &Name, text: &str, secret: &Secret<'_>) -> Findings {
        let mut problems = Vec::new();
        let Ok((found, readers)) = format::look(text) else {
            problems.push(String::from("has a file that is not in the .sauce format"));
            return Findings::of(problems);
        };
        if found != *name {
            problems.push(format!("has a file that holds secret {found}"));
            return Findings::of(problems);
        }
        if !self.partial
            && (readers
                .iter()
                .any(|reader| !secret.readers.contains(reader))
                || secret
                    .readers
                    .iter()
                    .any(|reader| !readers.contains(reader)))
        {
            problems.push(String::from(
                "has other readers than the machines declare, and `sauce generate` encrypts it again",
            ));
        }
        let Some(admin) = self.admin else {
            return Findings::of(problems);
        };
        self.tried += 1;
        let facts = match admin.open_facts(text, name) {
            Ok(facts) => facts,
            Err(error) => {
                if let OpenError::NotAReader { file, .. } = error {
                    self.inaccessible += 1;
                    self.file.get_or_insert(file);
                    return Findings {
                        problems,
                        no_reader: true,
                    };
                }
                problems.push(format!("cannot be opened: {error}"));
                return Findings::of(problems);
            }
        };
        if let Some(expires) = facts.expires {
            match self.today.days_until(expires) {
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
        Findings::of(problems)
    }
}

/// Prints one row for each thing that needs attention: the name of the secret or the file, then what is wrong.
///
/// The facts are encrypted, so expiry, a changed generator and `revoke` need the key of an admin.
pub fn status(
    machines: &ReadManifests,
    root: &Path,
    identity: Option<&Path>,
) -> Result<(), StatusError> {
    let secrets = machines.secrets()?;
    let partial = machines.failures().is_some();
    let admin = Admin::find_if_set(identity)?;
    let mut evaluator = Evaluator::new(admin.as_ref(), partial);

    let mut rows = Vec::new();
    for (name, secret) in &secrets {
        let path = root.join(&secret.definition.file);
        let text = match format::load(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let problem =
                    if secret.definition.generator.is_some() || secret.definition.once.is_some() {
                        Problem::Warning(String::from("has no file, and `sauce generate` makes it"))
                    } else {
                        Problem::Unset
                    };
                rows.push(Row {
                    name: name.to_string(),
                    problem,
                });
                continue;
            }
            Err(source) => return Err(StatusError::Read { path, source }),
        };
        let findings = evaluator.check(name, &text, secret);
        rows.extend(
            findings
                .problems
                .into_iter()
                .map(|problem| Row::warning(name.to_string(), problem)),
        );
        if findings.no_reader {
            rows.push(Row {
                name: name.to_string(),
                problem: Problem::NoReader,
            });
        }
    }

    if !partial {
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
            rows.push(match format::load(&path).map(|text| format::look(&text)) {
                Ok(Ok((name, _))) => Row::warning(
                    name.to_string(),
                    format!("has the file {shown}, and no machine declares it"),
                ),
                _ => Row::warning(
                    shown,
                    String::from("is not a .sauce file that sauce can read"),
                ),
            });
        }
    }
    let all_inaccessible = evaluator.all_inaccessible();
    if all_inaccessible {
        rows.retain(|row| !matches!(row.problem, Problem::NoReader));
    }

    let palette = Palette::stdout();
    let width = rows.iter().map(|row| row.name.len()).max().unwrap_or(0);
    for row in &rows {
        let padding = width - row.name.len();
        let detail = match &row.problem {
            Problem::Unset => {
                println!(
                    "{}{:padding$}  {}",
                    row.name,
                    "",
                    palette.paint(Color::Yellow, "unset")
                );
                continue;
            }
            Problem::Warning(detail) => detail,
            Problem::NoReader => "cannot open facts with the selected key",
        };
        println!(
            "{}{:padding$}  {detail}",
            palette.paint(Color::Yellow, &row.name),
            ""
        );
    }
    if rows.is_empty() && !partial && !all_inaccessible {
        println!("Nothing needs attention.");
    }
    evaluator.finish();
    Ok(())
}

/// Tells on stderr that no key opened the facts, so `sauce status` and `sauce list` did not check them.
fn warn_unchecked() {
    eprintln!(
        "The facts are encrypted, so expiry, changed generators and revoke are not checked, because {}.",
        IdentityError::Missing
    );
}

/// Collects every `.sauce` file under `folder`, and skips hidden folders and symbolic links.
/// A folder that cannot be read becomes a row, and the walk goes on.
fn sauce_files(folder: &Path, files: &mut Vec<PathBuf>, rows: &mut Vec<Row>) {
    let entries = match fs::read_dir(folder) {
        Ok(entries) => entries,
        Err(error) => {
            rows.push(Row::warning(
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
