use std::{
    io,
    path::{Path, PathBuf},
};

use sauce::format::{self, Date, Facts, Name, NameError};

use crate::{
    generate, gpg,
    identity::{Admin, IdentityError, OpenError},
    make::{Recipe, RecipeError},
    manifest::{FolderError, Machines, RuleError},
    spinner::Step,
};

#[derive(Debug, thiserror::Error)]
pub enum ExpireError {
    #[error(transparent)]
    Name(#[from] NameError),
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("no machine declares secret {0}")]
    NotDeclared(Name),
    #[error("secret {name}: {source}")]
    Recipe {
        name: Name,
        #[source]
        source: RecipeError,
    },
    #[error(transparent)]
    Folder(#[from] FolderError),
    #[error("{0} has no file yet, and `sauce set {0}` or `sauce generate` makes it")]
    Missing(Name),
    #[error("cannot read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} is not a .sauce.yaml file: {source}", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: format::ParseError,
    },
    #[error("readers of {0} differ from the declaration; run `sauce generate` first")]
    Readers(Name),
    #[error(
        "the value of {0} has another padding step than its declaration; run `sauce generate` first"
    )]
    Padding(Name),
    #[error("{0} changed while sauce expire ran, and nothing was written")]
    Changed(Name),
    #[error(transparent)]
    Encrypt(#[from] format::WriteError),
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

/// The file is encrypted again for the declared readers, and the declared bound must still give the padding step of the stored value.
pub fn expire(
    machines: &Machines,
    root: &Path,
    name: &str,
    expires: Option<Date>,
    identity: Option<&Path>,
) -> Result<(), ExpireError> {
    let name = name.parse::<Name>()?;
    let secrets = machines.secrets()?;
    let secret = secrets
        .get(&name)
        .ok_or_else(|| ExpireError::NotDeclared(name.clone()))?;
    let recipe = Recipe::new(secret.definition).map_err(|source| ExpireError::Recipe {
        name: name.clone(),
        source,
    })?;
    let bound = secret.definition.bound(recipe.as_ref());
    let path = secret.path(&name, root)?;
    let text = format::load(&path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            ExpireError::Missing(name.clone())
        } else {
            ExpireError::Read {
                path: path.clone(),
                source,
            }
        }
    })?;
    let (_, readers) = format::look(&text).map_err(|source| ExpireError::Parse {
        path: path.clone(),
        source,
    })?;
    let declared = readers.iter().all(|reader| secret.readers.contains(reader))
        && secret.readers.iter().all(|reader| readers.contains(reader));
    if !declared {
        return Err(ExpireError::Readers(name));
    }

    if !format::has_step(&text, bound).map_err(|source| ExpireError::Parse {
        path: path.clone(),
        source,
    })? {
        return Err(ExpireError::Padding(name));
    }

    let (value, old) = {
        let _step = Step::show(format!("Opening {name}…"));
        Admin::find(identity)?.open(&text, &name)?
    };
    if old.expires == expires {
        println!("{name} did not change");
        return Ok(());
    }
    let facts = Facts { expires, ..old };
    let step = Step::show(format!("Encrypting {name}…"));
    let new = format::write(&name, &value, &facts, bound, &secret.readers, gpg::wrap)?;
    if format::load(&path).ok().as_deref() != Some(text.as_str()) {
        return Err(ExpireError::Changed(name));
    }
    generate::save(&path, &new).map_err(|source| ExpireError::Write {
        path: path.clone(),
        source,
    })?;
    drop(step);
    match expires {
        Some(date) => println!("{name} expires on {date}"),
        None => println!("{name} has no expiry date"),
    }
    Ok(())
}
