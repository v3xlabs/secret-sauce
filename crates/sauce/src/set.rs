use std::{
    io::{self, IsTerminal as _, Read as _},
    path::{Path, PathBuf},
};

use sauce::format::{self, Date, Facts, Name, NameError, Value};

use crate::{
    generate,
    identity::{Admin, IdentityError, OpenError},
    make::{Recipe, RecipeError, SET_BOUND},
    manifest::{Machines, RuleError},
};

#[derive(Debug, thiserror::Error)]
pub enum SetError {
    #[error(transparent)]
    Name(#[from] NameError),
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("no machine declares secret {0}")]
    NotDeclared(Name),
    #[error("{0} is a key pair, and sauce generate makes it with its public key")]
    KeyPair(Name),
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
    #[error("cannot read the value: {0}")]
    Value(#[source] io::Error),
    #[error("the value is empty")]
    Empty,
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

/// The dates that a provider gives with a value.
#[derive(Clone, Copy)]
pub struct Dates {
    pub issued: Option<Date>,
    pub expires: Option<Date>,
}

/// Writes a value from stdin, or from a hidden prompt on a terminal, for the readers that the machines declare.
///
/// A new file needs no private key.
/// A file that exists needs the key of an admin, so that the new value keeps the facts of the old one.
pub fn set(
    machines: &Machines,
    root: &Path,
    name: &str,
    dates: Dates,
    identity: Option<&Path>,
) -> Result<(), SetError> {
    let name = name.parse::<Name>()?;
    let secrets = machines.secrets()?;
    let secret = secrets
        .get(&name)
        .ok_or_else(|| SetError::NotDeclared(name.clone()))?;
    let bound = match Recipe::new(secret.definition) {
        Ok(Some(Recipe::Ed25519)) => return Err(SetError::KeyPair(name)),
        Ok(recipe) => recipe.map_or(
            secret.definition.max_length.unwrap_or(SET_BOUND),
            |recipe| recipe.bound(),
        ),
        Err(source) => return Err(SetError::Recipe { name, source }),
    };
    let path = root.join(&secret.definition.file);
    let old = match format::load(&path) {
        Ok(text) => Some(Admin::find(identity)?.open(&text, &name)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(source) => return Err(SetError::Read { path, source }),
    };

    let value = if io::stdin().is_terminal() {
        rpassword::prompt_password(format!("Value of {name}: ")).map(String::into_bytes)
    } else {
        // One byte more than the bound is enough for `format::write` to refuse the value.
        let mut bytes = Vec::with_capacity(bound + 1);
        io::stdin()
            .take(u64::try_from(bound + 1).expect("a bound fits in u64"))
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    }
    .map(Value::from)
    .map_err(SetError::Value)?;
    if value.expose().is_empty() {
        return Err(SetError::Empty);
    }

    // A former reader knows the old value, so only a new value clears `revoke`.
    let revoke = old
        .as_ref()
        .is_some_and(|(old_value, old)| old.revoke && old_value.expose() == value.expose());
    let facts = Facts {
        version: old.as_ref().map_or(1, |(_, old)| old.version + 1),
        set: Date::today(),
        issued: dates.issued,
        expires: dates.expires,
        generator: None,
        formerly: old.map(|(_, old)| old.formerly).unwrap_or_default(),
        revoke,
    };
    let text = format::write(&name, &value, &facts, bound, &secret.readers)?;
    generate::save(&path, &text).map_err(|source| SetError::Write {
        path: path.clone(),
        source,
    })?;
    println!("set {name}, version {}", facts.version);
    if revoke {
        println!("{name} stays marked revoke, because the value is the same as before");
    }
    Ok(())
}
