//! The private key of a machine on disk, found through folders that only root can change and read into memory that is wiped.

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read as _},
    os::unix::{
        ffi::OsStrExt as _,
        fs::{MetadataExt as _, OpenOptionsExt as _},
    },
    path::{Component, Path, PathBuf},
};

use zeroize::Zeroizing;

/// The largest key file that sauce-install reads, in bytes.
/// An ed25519 key or an age identity file is far smaller, and a larger file is refused before it is read in full.
const LARGEST: usize = 16 * 1024;
/// The most links that a key path may go through, as `MAXSYMLINKS` of Linux.
const LINKS: usize = 40;

#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    #[error(
        "{0} is not a regular file of the user that runs sauce-install, root on a machine, with no permission for its group and other users, so sauce-install does not use it as a key"
    )]
    Access(PathBuf),
    #[error(
        "{0} goes through a folder or link that a user other than root can change, so sauce-install does not use it as a key"
    )]
    Folder(PathBuf),
    #[error("{action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("{0} is larger than {LARGEST} bytes, so it is not a key")]
    TooLarge(PathBuf),
}

/// An open key file that passed every check, as the path named it.
pub struct KeyFile {
    file: File,
    path: PathBuf,
}

impl KeyFile {
    /// Opens the key at `path` only if no user but root and `owner` can change a folder on the way or read the file, as sshd demands of its host keys.
    pub fn open(path: &Path, owner: u32) -> Result<Self, KeyFileError> {
        let refused = || KeyFileError::Folder(path.to_owned());
        let folder = |meta: &fs::Metadata| {
            meta.is_dir() && (meta.uid() == 0 || meta.uid() == owner) && meta.mode() & 0o022 == 0
        };
        if !path.is_absolute() {
            return Err(refused());
        }
        let mut resolved = PathBuf::from("/");
        if !folder(&fs::metadata(&resolved).map_err(io_error("cannot read", &resolved))?) {
            return Err(refused());
        }
        let (mut pending, ends_in_folder) = names(path);
        // A path whose last name ends in `/` or `/.` names a folder and never a key file; in an earlier name it only asks for the folder that the walk needs anyway.
        if ends_in_folder {
            return Err(refused());
        }
        let mut links = 0;
        while let Some(name) = pending.pop() {
            if name == ".." {
                resolved.pop();
                continue;
            }
            let candidate = resolved.join(&name);
            let meta =
                fs::symlink_metadata(&candidate).map_err(io_error("cannot read", &candidate))?;
            if meta.is_symlink() {
                links += 1;
                if links > LINKS {
                    return Err(refused());
                }
                let target =
                    fs::read_link(&candidate).map_err(io_error("cannot read", &candidate))?;
                if target.is_absolute() {
                    resolved = PathBuf::from("/");
                }
                let (target, ends_in_folder) = names(&target);
                if ends_in_folder && pending.is_empty() {
                    return Err(refused());
                }
                pending.extend(target);
            } else if pending.is_empty() {
                return Self::open_file(&candidate, path, owner);
            } else if folder(&meta) {
                resolved = candidate;
            } else {
                return Err(refused());
            }
        }
        Err(refused())
    }

    /// Opens the file at `resolved`, which the walk of [`KeyFile::open`] accepted, and checks the open file before any read.
    /// A FIFO opens at once with `O_NONBLOCK` and is then refused, and `O_NOFOLLOW` refuses a link that took the place of the file after the walk.
    fn open_file(resolved: &Path, path: &Path, owner: u32) -> Result<Self, KeyFileError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(resolved)
            .map_err(io_error("cannot read", path))?;
        let meta = file.metadata().map_err(io_error("cannot read", path))?;
        if !meta.is_file() || meta.uid() != owner || meta.mode() & 0o077 != 0 {
            return Err(KeyFileError::Access(path.to_owned()));
        }
        Ok(Self {
            file,
            path: path.to_owned(),
        })
    }

    /// The content of the key, in memory that is wiped on drop, with no copy that is not.
    pub fn read(mut self) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
        let mut key = Zeroizing::new(vec![0; LARGEST + 1]);
        let mut filled = 0;
        while filled < key.len() {
            match self.file.read(&mut key[filled..]) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(io_error("cannot read", &self.path)(error)),
            }
        }
        if filled > LARGEST {
            return Err(KeyFileError::TooLarge(self.path));
        }
        key.truncate(filled);
        Ok(key)
    }
}

fn io_error(
    action: &'static str,
    path: impl AsRef<Path>,
) -> impl FnOnce(io::Error) -> KeyFileError {
    let path = path.as_ref().to_owned();
    move |source| KeyFileError::Io {
        action,
        path,
        source,
    }
}

/// The names of `path` to walk, the next one last, and whether it ends in `/` or `/.`.
fn names(path: &Path) -> (Vec<OsString>, bool) {
    let bytes = path.as_os_str().as_bytes();
    let ends_in_folder = bytes.ends_with(b"/") || bytes.ends_with(b"/.");
    let names = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_owned()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        })
        .rev()
        .collect();
    (names, ends_in_folder)
}
