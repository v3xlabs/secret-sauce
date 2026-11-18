use std::{
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use sauce::format::{self, Name, NameError};

use crate::{
    clipboard::{self, CopyError},
    identity::{Admin, IdentityError, OpenError},
    manifest::{Machines, RuleError},
};

#[derive(Debug, thiserror::Error)]
pub enum GetError {
    #[error(transparent)]
    Name(#[from] NameError),
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("no machine declares secret {0}")]
    NotDeclared(Name),
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
    #[error("cannot print: {0}")]
    Print(#[from] io::Error),
    #[error(transparent)]
    Copy(#[from] CopyError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Open(#[from] OpenError),
}

/// What `sauce get` gives.
#[derive(Clone, Copy)]
pub enum Out {
    /// The readers, and the facts with the key of an admin.
    Facts,
    /// The value on stdout, and nothing else.
    Print,
    /// The value on the clipboard.
    Copy,
}

/// Prints the note and the readers of a secret, and its facts when the key of an admin is found.
/// With [`Out::Print`] it writes the value to stdout and nothing else, and with [`Out::Copy`] it puts the value on the clipboard.
pub fn get(
    machines: &Machines,
    root: &Path,
    name: &str,
    out: Out,
    identity: Option<&Path>,
) -> Result<(), GetError> {
    let name = name.parse::<Name>()?;
    let secrets = machines.secrets()?;
    let secret = secrets
        .get(&name)
        .ok_or_else(|| GetError::NotDeclared(name.clone()))?;
    let path = root.join(&secret.definition.file);
    let text = format::load(&path).map_err(|source| GetError::Read {
        path: path.clone(),
        source,
    })?;

    match out {
        Out::Facts => {}
        Out::Print => {
            let (value, _) = Admin::find(identity)?.open(&text, &name)?;
            return Ok(io::stdout().write_all(value.expose())?);
        }
        Out::Copy => {
            let (value, _) = Admin::find(identity)?.open(&text, &name)?;
            clipboard::copy(&value)?;
            eprintln!(
                "Copied {name} to the clipboard for {} seconds. A clipboard history of the desktop keeps a copy of its own.",
                clipboard::CLEAR_SECONDS
            );
            return Ok(());
        }
    }

    let (_, readers) = format::look(&text).map_err(|source| GetError::Parse {
        path: path.clone(),
        source,
    })?;
    let mut out = io::stdout().lock();
    writeln!(out, "name: {name}")?;
    writeln!(out, "file: {}", secret.definition.file.display())?;
    if let Some(note) = &secret.definition.note {
        writeln!(out, "note: {note}")?;
    }
    for reader in &readers {
        writeln!(out, "reader: {} {}", reader.r#for, reader.age)?;
    }

    let admin = match Admin::find(identity) {
        Ok(admin) => admin,
        Err(IdentityError::Missing) => {
            eprintln!("The facts are encrypted, and {}.", IdentityError::Missing);
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let facts = admin.open_facts(&text, &name)?;
    writeln!(out, "version: {}", facts.version)?;
    writeln!(out, "set: {}", facts.set)?;
    if let Some(date) = facts.issued {
        writeln!(out, "issued: {date}")?;
    }
    if let Some(date) = facts.expires {
        writeln!(out, "expires: {date}")?;
    }
    let made_by = match facts.generator {
        None => String::from("sauce set"),
        Some(digest) if Some(digest) == secret.definition.digest() => {
            secret.definition.declaration().unwrap_or_default()
        }
        Some(_) => String::from("a generator that differs from the declaration now"),
    };
    writeln!(out, "made by: {made_by}")?;
    for former in &facts.formerly {
        writeln!(out, "formerly: {former}")?;
    }
    if facts.revoke {
        writeln!(out, "revoke: a former reader knows this value")?;
    }
    Ok(())
}
