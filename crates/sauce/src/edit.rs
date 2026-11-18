use std::{
    env,
    ffi::OsString,
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    process::{self, Command, ExitStatus, Stdio},
};

use sauce::format::{self, Date, Facts, Name, NameError, Value};

use crate::{
    generate,
    identity::{Admin, IdentityError, OpenError},
    make::{Recipe, RecipeError, SET_BOUND},
    manifest::{Machines, RuleError},
};

#[derive(Debug, thiserror::Error)]
pub enum EditError {
    #[error(transparent)]
    Name(#[from] NameError),
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("no machine declares secret {0}")]
    NotDeclared(Name),
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
    #[error("EDITOR is not set, and sauce edit opens the value in it")]
    NoEditor,
    #[error(
        "XDG_RUNTIME_DIR is not set, and sauce edit keeps the value only in that memory-backed folder"
    )]
    NoRuntimeDir,
    #[error("{} is not in memory, and sauce edit keeps the value only in a tmpfs folder", .0.display())]
    NotInMemory(PathBuf),
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

/// Opens the value of one secret in `$EDITOR`, in a file with mode 0600 in a folder of its own in `$XDG_RUNTIME_DIR`, and writes it back when it changed.
pub fn edit(
    machines: &Machines,
    root: &Path,
    name: &str,
    identity: Option<&Path>,
) -> Result<(), EditError> {
    let name = name.parse::<Name>()?;
    let secrets = machines.secrets()?;
    let secret = secrets
        .get(&name)
        .ok_or_else(|| EditError::NotDeclared(name.clone()))?;
    let bound = match Recipe::new(secret.definition) {
        Ok(Some(Recipe::Ed25519)) => return Err(EditError::KeyPair(name)),
        Ok(recipe) => recipe.map_or(SET_BOUND, |recipe| recipe.bound()),
        Err(source) => return Err(EditError::Recipe { name, source }),
    };
    let editor = env::var_os("EDITOR")
        .filter(|editor| !editor.is_empty())
        .ok_or(EditError::NoEditor)?;
    let runtime = env::var_os("XDG_RUNTIME_DIR")
        .filter(|folder| !folder.is_empty())
        .ok_or(EditError::NoRuntimeDir)?;
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
    let (old, facts) = Admin::find(identity)?.open(&text, &name)?;

    let mut new = in_editor(editor, PathBuf::from(runtime), &name, &old)?;
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

    if format::load(&path).ok().as_deref() != Some(text.as_str()) {
        return Err(EditError::Changed(name));
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
    let text = format::write(&name, &new, &facts, bound, &secret.readers)?;
    generate::save(&path, &text).map_err(|source| EditError::Write {
        path: path.clone(),
        source,
    })?;
    println!("edited {name}, version {}", facts.version);
    Ok(())
}

/// Writes the value to a buffer in a folder of its own in `runtime`, opens it in `editor`, and gives what the editor saved.
fn in_editor(
    editor: OsString,
    runtime: PathBuf,
    name: &Name,
    old: &Value,
) -> Result<Vec<u8>, EditError> {
    if !memory_backed(&runtime) {
        return Err(EditError::NotInMemory(runtime));
    }
    // The editor keeps its swap and backup files next to the buffer, so a folder of its own holds them all.
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
