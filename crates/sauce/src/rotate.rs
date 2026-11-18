use std::{
    fs,
    io::{self, BufRead as _, Write as _},
    path::{Path, PathBuf},
};

use sauce::format::{self, Date, Facts, Name, NameError};

use crate::{
    generate,
    identity::{Admin, IdentityError, OpenError},
    make::{Recipe, RecipeError},
    manifest::{Machines, RuleError, Secret},
};

#[derive(Debug, thiserror::Error)]
pub enum RotateError {
    #[error(transparent)]
    Name(#[from] NameError),
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("no machine declares secret {0}")]
    NotDeclared(Name),
    #[error("no declared secret matches {0}")]
    NoMatch(String),
    #[error("{0} is `once`, and a new value would lose what the old one protects")]
    Once(Name),
    #[error("{0} has no generator, and `sauce set {0}` gives it a new value")]
    NoGenerator(Name),
    #[error("{0} has no file, and `sauce generate` makes it")]
    Missing(Name),
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
    #[error("{0} changed while sauce rotate ran, and nothing was written")]
    Changed(Name),
    #[error("{0} is at the last version that a file can count")]
    Version(Name),
    #[error("cannot ask: {0}")]
    Prompt(#[source] io::Error),
    #[error("nothing was rotated")]
    NotConfirmed,
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
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Open(#[from] OpenError),
}

/// One secret that gets a new value.
struct Rotation<'a> {
    name: &'a Name,
    secret: &'a Secret<'a>,
    recipe: Recipe,
    path: PathBuf,
    text: String,
}

/// Makes a new value for each declared secret that matches `pattern` and has a generator.
///
/// A pattern with `*` lists the secrets and asks first, and an exact name does not.
/// The new value keeps the facts of the old one, so it needs the key of an admin.
pub fn rotate(
    machines: &Machines,
    root: &Path,
    pattern: &str,
    identity: Option<&Path>,
) -> Result<(), RotateError> {
    let secrets = machines.secrets()?;
    let admin = Admin::find(identity)?;
    let mut rotations = Vec::new();
    if pattern.contains('*') {
        let mut matched = false;
        for (name, secret) in &secrets {
            if !matches(pattern, name.as_str()) {
                continue;
            }
            matched = true;
            let skip = match rotation(name, secret, root) {
                Ok(rotation) => {
                    rotations.push(rotation);
                    continue;
                }
                Err(RotateError::Once(_)) => "it is `once`",
                Err(RotateError::NoGenerator(_)) => "it has no generator",
                Err(RotateError::Missing(_)) => "it has no file",
                Err(error) => return Err(error),
            };
            println!("skipped {name}, because {skip}");
        }
        if !matched {
            return Err(RotateError::NoMatch(pattern.to_owned()));
        }
        if rotations.is_empty() {
            return Ok(());
        }
        if !confirm(&rotations).map_err(RotateError::Prompt)? {
            return Err(RotateError::NotConfirmed);
        }
    } else {
        let name = pattern.parse::<Name>()?;
        let (name, secret) = secrets
            .get_key_value(&name)
            .ok_or(RotateError::NotDeclared(name))?;
        rotations.push(rotation(name, secret, root)?);
    }

    let mut outputs = Vec::new();
    let mut versions = Vec::new();
    for rotation in &rotations {
        if format::load(&rotation.path).ok().as_deref() != Some(rotation.text.as_str()) {
            return Err(RotateError::Changed(rotation.name.clone()));
        }
        let old = admin.open_facts(&rotation.text, rotation.name)?;
        let made = rotation.recipe.make();
        let facts = Facts {
            version: old
                .version
                .checked_add(1)
                .ok_or_else(|| RotateError::Version(rotation.name.clone()))?,
            set: Date::today(),
            generator: rotation.secret.definition.digest(),
            revoke: false,
            ..old
        };
        let text = format::write(
            rotation.name,
            &made.value,
            &facts,
            rotation.recipe.bound(),
            &rotation.secret.readers,
        )
        .map_err(|source| RotateError::Encrypt {
            name: rotation.name.clone(),
            source: Box::new(source),
        })?;
        if let Some(public) = made.public {
            outputs.push((rotation.path.with_extension("pub"), format!("{public}\n")));
        }
        outputs.push((rotation.path.clone(), text));
        versions.push((rotation.name, facts.version));
    }

    // Every file is written before the first rename, so a failed write leaves all secrets and key pairs as they were.
    let mut staged = Vec::new();
    for (path, text) in &outputs {
        match generate::stage(path, text) {
            Ok(temporary) => staged.push((temporary, path)),
            Err(source) => {
                for (temporary, _) in &staged {
                    // The original files are untouched, and a leftover `.new` file is only clutter.
                    let _ = fs::remove_file(temporary);
                }
                return Err(RotateError::Write {
                    path: path.clone(),
                    source,
                });
            }
        }
    }
    for (temporary, path) in staged {
        fs::rename(&temporary, path).map_err(|source| RotateError::Write {
            path: path.clone(),
            source,
        })?;
    }
    for (name, version) in versions {
        println!("rotated {name}, version {version}");
    }
    Ok(())
}

fn confirm(rotations: &[Rotation<'_>]) -> io::Result<bool> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "These secrets get a new value:")?;
    for rotation in rotations {
        writeln!(stderr, "  {}", rotation.name)?;
    }
    write!(stderr, "Rotate them? [y/N] ")?;
    stderr.flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(answer.trim() == "y")
}

/// Whether `name` matches `pattern`, where `*` stands for any text, `/` included.
pub fn matches(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let mut parts: Vec<&str> = parts.collect();
    let Some(last) = parts.pop() else {
        return rest.is_empty();
    };
    for part in parts {
        match rest.find(part) {
            Some(index) => rest = &rest[index + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

fn rotation<'a>(
    name: &'a Name,
    secret: &'a Secret<'a>,
    root: &Path,
) -> Result<Rotation<'a>, RotateError> {
    if secret.definition.once.is_some() {
        return Err(RotateError::Once(name.clone()));
    }
    let recipe = Recipe::new(secret.definition)
        .map_err(|source| RotateError::Recipe {
            name: name.clone(),
            source,
        })?
        .ok_or_else(|| RotateError::NoGenerator(name.clone()))?;
    let path = root.join(&secret.definition.file);
    let text = format::load(&path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            RotateError::Missing(name.clone())
        } else {
            RotateError::Read {
                path: path.clone(),
                source,
            }
        }
    })?;
    Ok(Rotation {
        name,
        secret,
        recipe,
        path,
        text,
    })
}
