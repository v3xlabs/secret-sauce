use std::{
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use sauce::format::{self, Name, NameError};

use crate::{
    clipboard::{self, CopyError},
    identity::{Admin, IdentityError, OpenError},
    manifest::{ReadManifests, RuleError},
};

#[derive(Debug, thiserror::Error)]
pub enum GetError {
    #[error(transparent)]
    Name(#[from] NameError),
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("no machine declares secret {0}; run `sauce search` to find its name")]
    NotDeclared(Name),
    #[error("secret {0} is not in the partial manifest and may be on a failed machine")]
    NotInPartial(Name),
    #[error("{0} has no file yet; run `sauce set {0}`")]
    MissingManual(Name),
    #[error("{0} has no file yet; run `sauce generate`")]
    MissingGenerated(Name),
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
    #[error("{} holds {found}, not {name}", path.display())]
    OtherName {
        path: PathBuf,
        found: Name,
        name: Name,
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
    machines: &ReadManifests,
    root: &Path,
    name: &str,
    out: Out,
    identity: Option<&Path>,
) -> Result<(), GetError> {
    let name = name.parse::<Name>()?;
    let secrets = machines.secrets()?;
    let Some(secret) = secrets.get(&name) else {
        if machines.failures().is_some() {
            return Err(GetError::NotInPartial(name));
        }
        return Err(GetError::NotDeclared(name));
    };
    let path = root.join(&secret.definition.file);
    let text = match format::load(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let error = match (&secret.definition.generator, &secret.definition.once) {
                (None, None) => GetError::MissingManual(name),
                _ => GetError::MissingGenerated(name),
            };
            return Err(error);
        }
        Err(source) => return Err(GetError::Read { path, source }),
    };

    if !matches!(out, Out::Facts) {
        let (value, _) = Admin::find(identity)?.open(&text, &name)?;
        if matches!(out, Out::Print) {
            return Ok(io::stdout().write_all(value.expose())?);
        }
        clipboard::copy(&value)?;
        eprintln!(
            "Copied {name} to the clipboard for {} seconds. A clipboard history of the desktop keeps a copy of its own.",
            clipboard::CLEAR_SECONDS
        );
        return Ok(());
    }

    let (found, readers) = format::look(&text).map_err(|source| GetError::Parse {
        path: path.clone(),
        source,
    })?;
    if found != name {
        return Err(GetError::OtherName { path, found, name });
    }
    let mut out = io::stdout().lock();
    writeln!(out, "name: {name}")?;
    writeln!(out, "file: {}", secret.definition.file.display())?;
    if let Some(note) = &secret.definition.note {
        writeln!(out, "note: {note}")?;
    }
    writeln!(out, "machines: {}", secret.machines.join(", "))?;
    write!(out, "readers: ")?;
    for (index, reader) in readers.iter().enumerate() {
        let separator = if index == 0 { "" } else { ", " };
        write!(out, "{separator}{}", reader.r#for)?;
    }
    writeln!(out)?;
    if machines.failures().is_none()
        && (readers.len() != secret.readers.len()
            || !readers.iter().all(|reader| secret.readers.contains(reader))
            || !secret.readers.iter().all(|reader| readers.contains(reader)))
    {
        writeln!(
            out,
            "readers differ from the declaration; run `sauce generate` to review the changes"
        )?;
    }

    let facts = match Admin::find(identity)?.open_facts(&text, &name) {
        Err(OpenError::NoKey { .. }) => {
            return Ok(writeln!(
                out,
                "\nFacts are locked. Run `sauce get {name} --identity <admin-key-file>`."
            )?);
        }
        facts => facts?,
    };
    writeln!(out, "version: {}", facts.version)?;
    writeln!(out, "set: {}", facts.set)?;
    for (label, date) in [("issued", facts.issued), ("expires", facts.expires)] {
        if let Some(date) = date {
            writeln!(out, "{label}: {date}")?;
        }
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
    writeln!(out, "\nTo use the value: sauce get {name} --copy")?;
    let generator = secret.definition.generator.as_ref();
    if generator.is_some_and(|generator| generator.keypair.is_some()) {
        writeln!(out, "To replace it: sauce rotate {name}")?;
    } else {
        writeln!(out, "To edit it: sauce edit {name}")?;
    }
    Ok(())
}
