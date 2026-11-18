use std::{
    env,
    ffi::{OsStr, OsString},
    fs::{self, DirBuilder, OpenOptions},
    io::{self, BufRead as _, IsTerminal as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    process::{self, Command, ExitStatus, Stdio},
};

use sauce::format::{self, Date, Facts, Name, NameError, Value};

use crate::{
    generate,
    identity::{Admin, IdentityError, OpenError},
    make::{Recipe, RecipeError, SET_BOUND},
    manifest::{Machines, RuleError, Secret},
    rotate::matches,
};

#[derive(Debug, thiserror::Error)]
pub enum EditError {
    #[error(transparent)]
    Name(#[from] NameError),
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("no machine declares secret {0}; run `sauce search` to find its name")]
    NotDeclared(Name),
    #[error("no declared secret matches {0}")]
    NoMatch(String),
    #[error("{0} is a key pair, and `sauce rotate {0}` makes a new one with its public key")]
    KeyPair(Name),
    #[error("secret {name}: {source}")]
    Recipe {
        name: Name,
        #[source]
        source: RecipeError,
    },
    #[error("{0} has no file yet, and `sauce set {0}` or `sauce generate` makes it")]
    Missing(Name),
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
    #[error("readers of {0} differ from the declaration; run `sauce generate` before editing")]
    Readers(Name),
    #[error("EDITOR is not set, and sauce edit opens the value in it")]
    NoEditor,
    #[error(
        "XDG_RUNTIME_DIR is not set, and sauce edit keeps the value only in that memory-backed folder"
    )]
    NoRuntimeDir,
    #[error("{} is not in memory, and sauce edit keeps the value only in a tmpfs folder", .0.display())]
    NotInMemory(PathBuf),
    #[error(
        "pattern {0:?} needs a terminal to confirm each secret; name one secret to edit without a prompt"
    )]
    NotInteractive(String),
    #[error("cannot ask: {0}")]
    Prompt(#[source] io::Error),
    #[error("{0} changed while the editor was open, and nothing was written")]
    Changed(Name),
    #[error("{0} is at the last version that a file can count")]
    Version(Name),
    #[error("cannot make the buffer {}: {source}", path.display())]
    Buffer {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot start the editor: {0}")]
    Start(#[source] io::Error),
    #[error("the editor exited with {0}, and the value stays as it was")]
    Editor(ExitStatus),
    #[error("the value is empty, and it stays as it was")]
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

/// The folder that holds the value while the editor runs, and that is removed when it drops.
struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        // The shell of the editor may have removed it already, and a drop cannot report an error.
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Session {
    editor: OsString,
    runtime: PathBuf,
    admin: Admin,
}

enum Answer {
    Yes,
    No,
    Quit,
}

/// Exact names open one value; patterns need a separate confirmation for each value.
pub fn edit(
    machines: &Machines,
    root: &Path,
    pattern: &str,
    identity: Option<&Path>,
) -> Result<(), EditError> {
    if pattern.contains('*') {
        return edit_matching(machines, root, pattern, identity);
    }
    let name = pattern.parse::<Name>()?;
    let secrets = machines.secrets()?;
    let (name, secret) = secrets
        .get_key_value(&name)
        .ok_or_else(|| EditError::NotDeclared(name.clone()))?;
    let bound = bound(name, secret)?;
    let (editor, runtime) = environment()?;
    let (path, text) = load(name, secret, root)?;
    let admin = Admin::find(identity)?;
    let session = Session {
        editor,
        runtime,
        admin,
    };
    edit_one(name, secret, bound, &path, &text, &session)
}

fn edit_matching(
    machines: &Machines,
    root: &Path,
    pattern: &str,
    identity: Option<&Path>,
) -> Result<(), EditError> {
    let secrets = machines.secrets()?;
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
        return Err(EditError::NotInteractive(pattern.to_owned()));
    }
    let matched: Vec<_> = secrets
        .iter()
        .filter(|(name, _)| matches(pattern, name.as_str()))
        .collect();
    if matched.is_empty() {
        return Err(EditError::NoMatch(pattern.to_owned()));
    }
    let (editor, runtime) = environment()?;
    let session = Session {
        editor,
        runtime,
        admin: Admin::find(identity)?,
    };

    let mut stderr = io::stderr();
    let mut eligible = Vec::new();
    for (name, secret) in matched {
        let skip = match bound(name, secret) {
            Ok(bound) => match load(name, secret, root) {
                Ok(_) => {
                    eligible.push((name, secret, bound));
                    continue;
                }
                Err(EditError::Missing(_)) => {
                    format!("it has no file, and `sauce set {name}` or `sauce generate` makes it")
                }
                Err(error) => return Err(error),
            },
            Err(EditError::KeyPair(_)) => format!(
                "it is a key pair, and `sauce rotate {name}` makes a new one with its public key"
            ),
            Err(error) => return Err(error),
        };
        writeln!(stderr, "skipped {name}, because {skip}").map_err(EditError::Prompt)?;
    }
    if eligible.is_empty() {
        writeln!(stderr, "no secret that matches {pattern} can be edited")
            .map_err(EditError::Prompt)?;
        return Ok(());
    }

    writeln!(
        stderr,
        "{} secrets match. The editor shows only the value you choose.",
        eligible.len()
    )
    .map_err(EditError::Prompt)?;
    for (name, ..) in &eligible {
        writeln!(stderr, "  {name}").map_err(EditError::Prompt)?;
    }
    for (index, &(name, secret, bound)) in eligible.iter().enumerate() {
        match ask(name).map_err(EditError::Prompt)? {
            Answer::Yes => {
                let (path, text) = load(name, secret, root)?;
                edit_one(name, secret, bound, &path, &text, &session)?;
            }
            Answer::No => {
                writeln!(stderr, "skipped {name}").map_err(EditError::Prompt)?;
            }
            Answer::Quit => {
                writeln!(stderr, "Stopped. These values were not opened:")
                    .map_err(EditError::Prompt)?;
                for (name, ..) in &eligible[index..] {
                    writeln!(stderr, "  {name}").map_err(EditError::Prompt)?;
                }
                return Ok(());
            }
        }
    }
    Ok(())
}

fn ask(name: &Name) -> io::Result<Answer> {
    let mut stderr = io::stderr();
    write!(stderr, "Open {name} in $EDITOR? [y/N/q] ")?;
    stderr.flush()?;
    let mut answer = String::new();
    if io::stdin().lock().read_line(&mut answer)? == 0 {
        // The terminal does not echo the end of input, so the next line would start after the prompt.
        writeln!(stderr)?;
        return Ok(Answer::Quit);
    }
    Ok(match answer.trim() {
        "y" => Answer::Yes,
        "q" => Answer::Quit,
        _ => Answer::No,
    })
}

/// The longest value that the declaration of the secret allows, unless the secret is a key pair, which `sauce rotate` makes.
fn bound(name: &Name, secret: &Secret<'_>) -> Result<usize, EditError> {
    match Recipe::new(secret.definition) {
        Ok(Some(Recipe::Ed25519)) => Err(EditError::KeyPair(name.clone())),
        Ok(recipe) => Ok(recipe.map_or(SET_BOUND, |recipe| recipe.bound())),
        Err(source) => Err(EditError::Recipe {
            name: name.clone(),
            source,
        }),
    }
}

fn environment() -> Result<(OsString, PathBuf), EditError> {
    let editor = env::var_os("EDITOR")
        .filter(|editor| !editor.is_empty())
        .ok_or(EditError::NoEditor)?;
    let runtime = env::var_os("XDG_RUNTIME_DIR")
        .filter(|folder| !folder.is_empty())
        .ok_or(EditError::NoRuntimeDir)?;
    let runtime = PathBuf::from(runtime);
    if !memory_backed(&runtime) {
        return Err(EditError::NotInMemory(runtime));
    }
    Ok((editor, runtime))
}

/// Reads the file of a secret, and refuses it when its readers are not the declared ones, so that an edit never changes who can read the value.
fn load(name: &Name, secret: &Secret<'_>, root: &Path) -> Result<(PathBuf, String), EditError> {
    let path = root.join(&secret.definition.file);
    let text = format::load(&path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            EditError::Missing(name.clone())
        } else {
            EditError::Read {
                path: path.clone(),
                source,
            }
        }
    })?;
    let (_, readers) = format::look(&text).map_err(|source| EditError::Parse {
        path: path.clone(),
        source,
    })?;
    let declared = readers.iter().all(|reader| secret.readers.contains(reader))
        && secret.readers.iter().all(|reader| readers.contains(reader));
    if !declared {
        return Err(EditError::Readers(name.clone()));
    }
    Ok((path, text))
}

fn edit_one(
    name: &Name,
    secret: &Secret<'_>,
    bound: usize,
    path: &Path,
    text: &str,
    session: &Session,
) -> Result<(), EditError> {
    let (old, facts) = session.admin.open(text, name)?;

    let mut new = in_editor(&session.editor, &session.runtime, name, &old)?;
    // Editors end the last line with a newline, which is not part of a value that had none.
    if !old.expose().ends_with(b"\n") && new.ends_with(b"\n") {
        new.pop();
    }
    let new = Value::from(new);
    if new.expose() == old.expose() {
        println!("{name} did not change");
        return Ok(());
    }
    if new.expose().is_empty() {
        return Err(EditError::Empty);
    }

    if format::load(path).ok().as_deref() != Some(text) {
        return Err(EditError::Changed(name.clone()));
    }
    let facts = Facts {
        version: facts
            .version
            .checked_add(1)
            .ok_or_else(|| EditError::Version(name.clone()))?,
        set: Date::today(),
        generator: None,
        revoke: false,
        ..facts
    };
    let text = format::write(name, &new, &facts, bound, &secret.readers)?;
    generate::save(path, &text).map_err(|source| EditError::Write {
        path: path.to_owned(),
        source,
    })?;
    println!("edited {name}, version {}", facts.version);
    Ok(())
}

/// Writes the value to a buffer in a folder of its own in `runtime`, opens it in `editor`, and gives what the editor saved.
fn in_editor(
    editor: &OsStr,
    runtime: &Path,
    name: &Name,
    old: &Value,
) -> Result<Vec<u8>, EditError> {
    if !memory_backed(runtime) {
        return Err(EditError::NotInMemory(runtime.to_owned()));
    }
    // Backups next to the buffer stay in memory and are removed with it.
    let folder = runtime.join(format!("sauce-edit-{}", process::id()));
    let folder_error = |source| EditError::Buffer {
        path: folder.clone(),
        source,
    };
    DirBuilder::new()
        .mode(0o700)
        .create(&folder)
        .map_err(folder_error)?;
    let folder = Folder(folder);
    let buffer = folder.0.join(name.as_str().replace('/', "-"));
    let buffer_error = |source| EditError::Buffer {
        path: buffer.clone(),
        source,
    };
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&buffer)
        .and_then(|mut file| file.write_all(old.expose()))
        .map_err(buffer_error)?;
    // When a signal stops sauce while the editor runs, the shell outlives it and removes the folder after the editor.
    let mut script = OsString::from("trap : HUP INT TERM; ");
    script.push(editor);
    // The parent in `/proc/$$/stat` changes at once when sauce ends, also while sauce waits to be reaped.
    script.push(
        r#" "$1"; status=$?; read -r _ _ _ parent _ < /proc/$$/stat; [ "$parent" = "$3" ] || rm -rf "$2"; exit $status"#,
    );
    let mut editor = Command::new("sh");
    editor
        .arg("-c")
        .arg(script)
        .arg("sh")
        .arg(&buffer)
        .arg(&folder.0)
        .arg(process::id().to_string());
    // A terminal editor draws the value on its screen, which must not go into a redirected stdout.
    match OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(tty) => {
            let (output, error) = (tty.try_clone(), tty.try_clone());
            editor
                .stdin(tty)
                .stdout(output.map_err(EditError::Start)?)
                .stderr(error.map_err(EditError::Start)?);
        }
        Err(_) => {
            editor.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    let status = editor.status().map_err(EditError::Start)?;
    if !status.success() {
        return Err(EditError::Editor(status));
    }
    let new = fs::read(&buffer);
    drop(folder);
    new.map_err(buffer_error)
}

/// Whether `folder` is on a tmpfs or ramfs mount, from the longest mount point in `/proc/self/mounts` that holds it.
fn memory_backed(folder: &Path) -> bool {
    let (Ok(folder), Ok(mounts)) = (
        fs::canonicalize(folder),
        fs::read_to_string("/proc/self/mounts"),
    ) else {
        return false;
    };
    mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(' ');
            let (_, point, kind) = (fields.next()?, fields.next()?, fields.next()?);
            folder.starts_with(point).then_some((point.len(), kind))
        })
        .max_by_key(|(length, _)| *length)
        .is_some_and(|(_, kind)| kind == "tmpfs" || kind == "ramfs")
}
