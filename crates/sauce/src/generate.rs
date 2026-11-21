use std::{
    fs::{self, OpenOptions},
    io::{self, BufRead as _, IsTerminal as _, Write as _},
    path::{Path, PathBuf},
};

use rand::{RngCore as _, rngs::OsRng};
use sauce::format::{self, Date, Facts, Name, Reader};

use crate::{
    color::{Color, Palette},
    gpg,
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
    #[error("{} is not a .sauce.yaml file: {source}", path.display())]
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
    #[error("reader changes not approved; no files changed")]
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

struct Creation<'a> {
    name: &'a Name,
    secret: &'a Secret<'a>,
    path: PathBuf,
    recipe: Recipe,
}

/// Creates the file of every secret that `sauce` can make and that has none, and re-encrypts every file whose readers changed.
pub fn generate(
    machines: &Machines,
    root: &Path,
    identity: Option<&Path>,
    dry_run: bool,
) -> Result<(), GenerateError> {
    let secrets = machines.secrets()?;
    let mut creations = Vec::new();
    let mut changes = Vec::new();
    let mut unset = Vec::new();
    for (name, secret) in &secrets {
        match step(name, secret, root)? {
            Step::Create(path, recipe) => creations.push(Creation {
                name,
                secret,
                path,
                recipe,
            }),
            Step::Change(change) => changes.push(change),
            Step::Set => unset.push(name),
            Step::None => {}
        }
    }

    let palette = Palette::stdout();
    if dry_run {
        let readers = creations
            .iter()
            .map(|creation| (creation.name, creation.secret.readers.as_slice()))
            .chain(changes.iter().map(|change| (change.name, change.readers)));
        for (name, readers) in readers {
            format::validate_readers(readers).map_err(|source| GenerateError::Encrypt {
                name: name.clone(),
                source: Box::new(source),
            })?;
        }
        println!("Dry run. No files will be written.");
        for creation in &creations {
            let public =
                matches!(creation.recipe, Recipe::Ed25519).then(|| public_path(&creation.path));
            print_created(creation.name, public.as_deref(), root, palette);
        }
        for change in &changes {
            print_reencrypted(change.name, palette);
        }
        summarize(creations.len(), changes.len(), &unset, palette);
        return Ok(());
    }

    apply(creations, changes, &unset, root, identity, palette)
}

fn apply(
    creations: Vec<Creation<'_>>,
    changes: Vec<Change<'_>>,
    unset: &[&Name],
    root: &Path,
    identity: Option<&Path>,
    palette: Palette,
) -> Result<(), GenerateError> {
    if !changes.is_empty() && !confirm(&changes, creations.len()).map_err(GenerateError::Prompt)? {
        return Err(GenerateError::NotConfirmed);
    }
    let created_count = creations.len();
    let mut created = Vec::with_capacity(created_count);
    for Creation {
        name,
        secret,
        path,
        recipe,
    } in creations
    {
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
        let text = format::write(
            name,
            &made.value,
            &facts,
            recipe.bound(),
            &secret.readers,
            gpg::wrap,
        )
        .map_err(|source| GenerateError::Encrypt {
            name: name.clone(),
            source: Box::new(source),
        })?;
        created.push((name, path, text, made.public));
    }
    let mut reencrypted = Vec::with_capacity(changes.len());
    if !changes.is_empty() {
        let admin = Admin::find(identity)?;
        for change in changes {
            let (value, mut facts) = admin.open(&change.text, change.name)?;
            facts.revoke |= !change.lost.is_empty();
            let text = format::write(
                change.name,
                &value,
                &facts,
                change.bound,
                change.readers,
                gpg::wrap,
            )
            .map_err(|source| GenerateError::Encrypt {
                name: change.name.clone(),
                source: Box::new(source),
            })?;
            reencrypted.push((change.name, change.path, text));
        }
    }

    for (name, path, text, public) in created {
        // The public half goes first, so that a failed write leaves no private key without it.
        let sidecar = if let Some(public) = public {
            let sidecar = public_path(&path);
            save(&sidecar, &format!("{public}\n")).map_err(|source| GenerateError::Write {
                path: sidecar.clone(),
                source,
            })?;
            Some(sidecar)
        } else {
            None
        };
        save(&path, &text).map_err(|source| GenerateError::Write {
            path: path.clone(),
            source,
        })?;
        print_created(name, sidecar.as_deref(), root, palette);
    }
    let reencrypted_count = reencrypted.len();
    for (name, path, text) in reencrypted {
        save(&path, &text).map_err(|source| GenerateError::Write {
            path: path.clone(),
            source,
        })?;
        print_reencrypted(name, palette);
    }
    summarize(created_count, reencrypted_count, unset, palette);
    Ok(())
}

pub fn public_path(path: &Path) -> PathBuf {
    let mut path = path.with_extension("");
    path.set_extension("pub");
    path
}

fn print_created(name: &Name, public: Option<&Path>, root: &Path, palette: Palette) {
    let label = palette.paint(Color::Green, "created");
    let Some(public) = public else {
        println!("{label} {name}");
        return;
    };
    let logical = Path::new(name.as_str());
    if public.file_stem() == logical.file_name()
        && public
            .parent()
            .zip(logical.parent())
            .is_some_and(|(dir, prefix)| dir.ends_with(prefix))
    {
        println!("{label} {name} & {name}.pub");
    } else {
        let shown = public.strip_prefix(root).unwrap_or(public);
        println!("{label} {name} & {}", shown.display());
    }
}

fn print_reencrypted(name: &Name, palette: Palette) {
    println!("{} {name}", palette.paint(Color::Cyan, "re-encrypted"));
}

fn summarize(created: usize, reencrypted: usize, unset: &[&Name], palette: Palette) {
    if !unset.is_empty() {
        println!(
            "{}",
            palette.paint(Color::Yellow, "Set these secrets manually:")
        );
        for name in unset {
            println!("  sauce set {name}");
        }
    }
    let unset = unset.len();
    let needs = if unset == 1 { "needs" } else { "need" };
    if created == 0 && reencrypted == 0 {
        if unset == 0 {
            println!("No files changed.");
        } else {
            println!("No files changed. {unset} {needs} a value.");
        }
    } else {
        println!(
            "Generated: {created} created, {reencrypted} re-encrypted, {unset} {needs} a value."
        );
    }
}

/// Prints every reader that changes, with every key that gets access to a value that exists, and asks on the terminal.
fn confirm(changes: &[Change<'_>], pending: usize) -> io::Result<bool> {
    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "These readers change. A key that gets access learns a value that exists:"
    )?;
    for change in changes {
        for reader in &change.gained {
            writeln!(
                stderr,
                "  {}  gets {} {}",
                change.name, reader.r#for, reader.key
            )?;
        }
        for reader in &change.lost {
            writeln!(
                stderr,
                "  {}  loses {} {}",
                change.name, reader.r#for, reader.key
            )?;
        }
    }
    if !(io::stdin().is_terminal() && stderr.is_terminal()) {
        return Ok(false);
    }
    match pending {
        0 => write!(
            stderr,
            "Encrypt these secrets again with the key of an admin? [y/N] "
        )?,
        1 => write!(
            stderr,
            "Apply reader changes and create 1 missing file? [y/N] "
        )?,
        count => write!(
            stderr,
            "Apply reader changes and create {count} missing files? [y/N] "
        )?,
    }
    stderr.flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(answer.trim() == "y")
}

/// Writes a file through a temporary file next to it, so that a failed write leaves the old file whole.
pub fn save(path: &Path, text: &str) -> io::Result<()> {
    fs::rename(stage(path, text)?, path)
}

/// Writes the text for `path` to a new file with a random name next to it, which a rename or a hard link then puts in place.
///
/// The file is created exclusively, so a file or symbolic link that is already at that name, maybe the staged file of another writer, stays as it is.
pub fn stage(path: &Path, text: &str) -> io::Result<PathBuf> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut suffix = [0; 8];
    OsRng
        .try_fill_bytes(&mut suffix)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".{:016x}.new", u64::from_ne_bytes(suffix)));
    let temporary = PathBuf::from(temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    if let Err(error) = file.write_all(text.as_bytes()) {
        // The file has only part of the text, and nothing links to it yet.
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
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
        bound: recipe.as_ref().map_or(
            secret.definition.max_length.unwrap_or(SET_BOUND),
            Recipe::bound,
        ),
    }))
}
