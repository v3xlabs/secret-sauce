use std::{
    fs,
    io::{self, BufRead as _, IsTerminal as _, Write as _},
    path::{Path, PathBuf},
};

use sauce::format::{self, Date, Facts, Name, Reader};

use crate::{
    identity::{Admin, IdentityError, OpenError},
    make::{Recipe, RecipeError, SET_BOUND},
    manifest::{Machines, RuleError, Secret},
};

#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("secret {name}: {source}")]
    Recipe {
        name: Name,
        #[source]
        source: RecipeError,
    },
    #[error("cannot read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} is not a .sauce file: {source}", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: format::ParseError,
    },
    #[error("{} holds secret {found}, and the declaration of {name} points to it", path.display())]
    OtherName {
        path: PathBuf,
        name: Name,
        found: Name,
    },
    #[error("cannot encrypt {name}: {source}")]
    Encrypt {
        name: Name,
        #[source]
        source: Box<format::WriteError>,
    },
    #[error("cannot write {}: {source}", path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot ask on the terminal: {0}")]
    Prompt(#[source] io::Error),
    #[error(
        "some secrets have other readers than the machines declare, and sauce re-encrypts them only after a yes on a terminal"
    )]
    NotConfirmed,
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Open(#[from] OpenError),
}

/// What `sauce generate` does with one secret.
enum Step<'a> {
    Create(PathBuf, Recipe),
    Change(Change<'a>),
    /// The secret has no file, and `sauce set` gives it one.
    Set,
    None,
}

/// A secret whose file has other readers than the machines declare.
struct Change<'a> {
    name: &'a Name,
    path: PathBuf,
    text: String,
    readers: &'a [Reader],
    gained: Vec<&'a Reader>,
    lost: Vec<Reader>,
    bound: usize,
}

/// Creates the file of every secret that `sauce` can make and that has none, and re-encrypts every file whose readers changed.
pub fn generate(
    machines: &Machines,
    root: &Path,
    identity: Option<&Path>,
) -> Result<(), GenerateError> {
    let secrets = machines.secrets()?;
    let mut created = Vec::new();
    let mut changes = Vec::new();
    let mut unset = Vec::new();
    for (name, secret) in &secrets {
        match step(name, secret, root)? {
            Step::Create(path, recipe) => {
                let made = recipe.make();
                let facts = Facts {
                    version: 1,
                    set: Date::today(),
                    issued: None,
                    expires: None,
                    generator: secret.definition.digest(),
                    formerly: Vec::new(),
                    revoke: false,
                };
                let text =
                    format::write(name, &made.value, &facts, recipe.bound(), &secret.readers)
                        .map_err(|source| GenerateError::Encrypt {
                            name: name.clone(),
                            source: Box::new(source),
                        })?;
                created.push((name, path, text, made.public));
            }
            Step::Change(change) => changes.push(change),
            Step::Set => unset.push(name),
            Step::None => {}
        }
    }

    for (name, path, text, public) in created {
        // The public half goes first, so that a failed write leaves no private key without it.
        let public_path = path.with_extension("pub");
        if let Some(public) = &public {
            save(&public_path, &format!("{public}\n")).map_err(|source| GenerateError::Write {
                path: public_path.clone(),
                source,
            })?;
        }
        save(&path, &text).map_err(|source| GenerateError::Write {
            path: path.clone(),
            source,
        })?;
        if public.is_some() {
            let shown = public_path.strip_prefix(root).unwrap_or(&public_path);
            println!("created {name}, with its public key in {}", shown.display());
        } else {
            println!("created {name}");
        }
    }
    for name in unset {
        println!("{name} has no file, and `sauce set {name}` gives it one");
    }

    if changes.is_empty() {
        return Ok(());
    }
    if !confirm(&changes).map_err(GenerateError::Prompt)? {
        return Err(GenerateError::NotConfirmed);
    }
    let admin = Admin::find(identity)?;
    for change in changes {
        let (value, mut facts) = admin.open(&change.text, change.name)?;
        facts.revoke |= !change.lost.is_empty();
        let text = format::write(change.name, &value, &facts, change.bound, change.readers)
            .map_err(|source| GenerateError::Encrypt {
                name: change.name.clone(),
                source: Box::new(source),
            })?;
        save(&change.path, &text).map_err(|source| GenerateError::Write {
            path: change.path.clone(),
            source,
        })?;
        println!("re-encrypted {}", change.name);
    }
    Ok(())
}

/// Prints every reader that changes, with every key that gets access to a value that exists, and asks on the terminal.
fn confirm(changes: &[Change<'_>]) -> io::Result<bool> {
    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "These readers change, and a key that gets access learns a value that exists:"
    )?;
    for change in changes {
        for reader in &change.gained {
            writeln!(
                stderr,
                "  {}  gets {} {}",
                change.name, reader.r#for, reader.age
            )?;
        }
        for reader in &change.lost {
            writeln!(
                stderr,
                "  {}  loses {} {}",
                change.name, reader.r#for, reader.age
            )?;
        }
    }
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    write!(
        stderr,
        "Encrypt these secrets again with the key of an admin? [y/N] "
    )?;
    stderr.flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(answer.trim() == "y")
}

/// Writes a file through a temporary file next to it, so that a failed write leaves the old file whole.
pub fn save(path: &Path, text: &str) -> io::Result<()> {
    fs::rename(stage(path, text)?, path)
}

/// Writes the text for `path` to `<path>.new`, which a rename then puts in place.
pub fn stage(path: &Path, text: &str) -> io::Result<PathBuf> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".new");
    let temporary = PathBuf::from(temporary);
    fs::write(&temporary, text)?;
    Ok(temporary)
}

fn step<'a>(
    name: &'a Name,
    secret: &'a Secret<'_>,
    root: &Path,
) -> Result<Step<'a>, GenerateError> {
    let recipe = Recipe::new(secret.definition).map_err(|source| GenerateError::Recipe {
        name: name.clone(),
        source,
    })?;
    let path = root.join(&secret.definition.file);
    let text = match format::load(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(recipe.map_or(Step::Set, |recipe| Step::Create(path, recipe)));
        }
        Err(source) => return Err(GenerateError::Read { path, source }),
    };
    let (found, readers) = format::look(&text).map_err(|source| GenerateError::Parse {
        path: path.clone(),
        source,
    })?;
    if found != *name {
        return Err(GenerateError::OtherName {
            path,
            name: name.clone(),
            found,
        });
    }
    let lost: Vec<_> = readers
        .iter()
        .filter(|reader| !secret.readers.contains(reader))
        .cloned()
        .collect();
    let gained: Vec<_> = secret
        .readers
        .iter()
        .filter(|reader| !readers.contains(reader))
        .collect();
    if lost.is_empty() && gained.is_empty() {
        return Ok(Step::None);
    }
    Ok(Step::Change(Change {
        name,
        path,
        text,
        readers: &secret.readers,
        gained,
        lost,
        bound: recipe.as_ref().map_or(SET_BOUND, Recipe::bound),
    }))
}
