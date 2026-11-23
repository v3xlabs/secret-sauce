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
    make::{Recipe, RecipeError},
    manifest::{FolderError, Machines, RuleError, Secret},
    spinner,
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
    #[error(transparent)]
    Folder(#[from] FolderError),
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
    #[error(
        "{name} has a value longer than its bound of {bound} bytes, so sauce generate does not encrypt it again; give it a shorter value with `sauce set {name}`, or raise its maxLength"
    )]
    LongerThanBound { name: Name, bound: usize },
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

/// A secret whose file has other readers than the machines declare, or a `value` in another step than its bound chooses.
struct Change<'a> {
    name: &'a Name,
    path: PathBuf,
    text: String,
    readers: &'a [Reader],
    access: ReaderChange<'a>,
    bound: usize,
}

/// The readers that a secret gains and loses, from the readers of its file to the declared ones.
pub struct ReaderChange<'a> {
    gained: Vec<&'a Reader>,
    lost: Vec<Reader>,
}

struct Creation<'a> {
    name: &'a Name,
    secret: &'a Secret<'a>,
    path: PathBuf,
    recipe: Recipe,
}

impl<'a> ReaderChange<'a> {
    pub fn new(found: &[Reader], declared: &'a [Reader]) -> Self {
        Self {
            gained: declared
                .iter()
                .filter(|reader| !found.contains(reader))
                .collect(),
            lost: found
                .iter()
                .filter(|reader| !declared.contains(reader))
                .cloned()
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.gained.is_empty() && self.lost.is_empty()
    }

    /// Whether a reader of the file is not declared, so that it knows the value that the file holds.
    pub fn loses(&self) -> bool {
        !self.lost.is_empty()
    }
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
    let reading = spinner::Step::secrets("Reading", secrets.len());
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

    drop(reading);
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
    let readers_change = changes.iter().any(|change| !change.access.is_empty());
    if readers_change && !confirm(&changes, creations.len()).map_err(GenerateError::Prompt)? {
        return Err(GenerateError::NotConfirmed);
    }
    let step = spinner::Step::secrets("Encrypting", creations.len() + changes.len());
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
            secret.definition.bound(Some(&recipe)),
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
            if value.expose().len() > change.bound {
                return Err(GenerateError::LongerThanBound {
                    name: change.name.clone(),
                    bound: change.bound,
                });
            }
            facts.revoke |= change.access.loses();
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

    drop(step);
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

/// Asks on the terminal whether to apply the reader changes of `changes` and create `pending` files.
fn confirm(changes: &[Change<'_>], pending: usize) -> io::Result<bool> {
    print_reader_changes(changes.iter().map(|change| (change.name, &change.access)))?;
    let question = match pending {
        0 => "Encrypt these secrets again with the key of an admin?".to_owned(),
        1 => "Apply reader changes and create 1 missing file?".to_owned(),
        count => format!("Apply reader changes and create {count} missing files?"),
    };
    ask(&question)
}

/// Prints every reader that changes, with every key that gets access to a value that exists.
pub fn print_reader_changes<'a, 'b: 'a>(
    changes: impl IntoIterator<Item = (&'a Name, &'a ReaderChange<'b>)>,
) -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "These readers change. A key that gets access learns a value that exists:"
    )?;
    for (name, change) in changes {
        for reader in &change.gained {
            writeln!(stderr, "  {name}  gets {} {}", reader.r#for, reader.key)?;
        }
        for reader in &change.lost {
            writeln!(stderr, "  {name}  loses {} {}", reader.r#for, reader.key)?;
        }
    }
    Ok(())
}

/// Asks a yes or no question on the terminal, and gives `false` with no terminal.
pub fn ask(question: &str) -> io::Result<bool> {
    let mut stderr = io::stderr().lock();
    if !(io::stdin().is_terminal() && stderr.is_terminal()) {
        return Ok(false);
    }
    write!(stderr, "{question} [y/N] ")?;
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
    let path = secret.path(name, root)?;
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
    let access = ReaderChange::new(&readers, &secret.readers);
    let bound = secret.definition.bound(recipe.as_ref());
    let restep = !format::has_step(&text, bound).map_err(|source| GenerateError::Parse {
        path: path.clone(),
        source,
    })?;
    if access.is_empty() && !restep {
        return Ok(Step::None);
    }
    Ok(Step::Change(Change {
        name,
        path,
        text,
        readers: &secret.readers,
        access,
        bound,
    }))
}
