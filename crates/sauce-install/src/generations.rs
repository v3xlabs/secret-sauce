//! The generations of files that one link serves from one mount point: a new generation, made in a staging folder that only root can enter, takes the place of the served one in one exchange.

use std::{
    ffi::CString,
    fs::{self, DirBuilder, File, OpenOptions, Permissions},
    io,
    os::{
        fd::FromRawFd as _,
        unix::{
            ffi::OsStrExt as _,
            fs::{
                DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
                symlink,
            },
        },
    },
    path::{Path, PathBuf},
};

/// The generation that a new link points at, under the mount point.
const ACTIVE: &str = "active";
/// A folder under the mount point that only root can enter, which holds the new generation before its exchange and the old one after it.
const STAGING: &str = "staging";

#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error("{action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("SAUCE_LOCK_FD is {fd}, which is not an open descriptor of {path}")]
    Lock { fd: String, path: PathBuf },
    #[error(
        "{0} is in the way, because it is not a link that sauce-install made, so remove it by hand"
    )]
    Occupied(PathBuf),
}

/// The link that serves the files, and the mount point of its generations.
pub struct Generations {
    link: PathBuf,
    mount_point: PathBuf,
}

impl Generations {
    pub fn new(link: &Path, mount_point: &Path) -> Self {
        Self {
            link: link.to_owned(),
            mount_point: mount_point.to_owned(),
        }
    }

    pub fn link(&self) -> &Path {
        &self.link
    }

    /// Holds `<link>.lock`, which every run on one link holds, so no two runs remove each other's generations.
    ///
    /// The NixOS module takes it before its look at the mount and passes it down in `SAUCE_LOCK_FD`, and the lock of that same open file returns at once.
    /// A run started by hand opens and takes it itself, so it waits for any other run.
    pub fn lock(&self) -> Result<File, GenerationError> {
        let path = self.next_to_link(".lock");
        let file = if let Ok(fd) = std::env::var("SAUCE_LOCK_FD") {
            let refused = || GenerationError::Lock {
                fd: fd.clone(),
                path: path.clone(),
            };
            let Ok(number) = fd.parse::<i32>() else {
                return Err(refused());
            };
            // SAFETY: `F_GETFD` reads the flags of a descriptor number and touches no memory of this process.
            if number < 0 || unsafe { libc::fcntl(number, libc::F_GETFD) } == -1 {
                return Err(refused());
            }
            // SAFETY: the descriptor is open, as `fcntl` showed, and one of another file is given back below before any use.
            let file = unsafe { File::from_raw_fd(number) };
            let same = match (file.metadata(), fs::metadata(&path)) {
                (Ok(held), Ok(named)) => held.dev() == named.dev() && held.ino() == named.ino(),
                _ => false,
            };
            if !same {
                // The descriptor stays open for whoever owns it.
                std::mem::forget(file);
                return Err(refused());
            }
            file
        } else {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&path)
                .map_err(io_error("cannot open", &path))?
        };
        file.lock().map_err(io_error("cannot lock", &path))?;
        Ok(file)
    }

    /// Removes what a stopped run left, once it checked that the link is absent or a link that sauce-install made: the new link, the staging folder, and every generation that the link does not serve.
    pub fn clean(&self) -> Result<(), GenerationError> {
        // A name such as `01` is refused, because the prune below keeps a numbered generation by its name as an earlier version wrote it.
        let served = match fs::symlink_metadata(&self.link) {
            Ok(meta) if meta.is_symlink() => {
                let target =
                    fs::read_link(&self.link).map_err(io_error("cannot read", &self.link))?;
                let made = target.strip_prefix(&self.mount_point).is_ok_and(|name| {
                    let name = name.to_str().unwrap_or_default();
                    name == ACTIVE
                        || name
                            .parse::<u64>()
                            .is_ok_and(|number| number.to_string() == name)
                });
                if !made {
                    return Err(GenerationError::Occupied(self.link.clone()));
                }
                Some(target)
            }
            Ok(_) => return Err(GenerationError::Occupied(self.link.clone())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_error("cannot read", &self.link)(error)),
        };
        let stale = self.next_to_link(".new");
        match fs::symlink_metadata(&stale) {
            Ok(meta) if meta.is_symlink() => {
                fs::remove_file(&stale).map_err(io_error("cannot remove", &stale))?;
            }
            Ok(_) => return Err(GenerationError::Occupied(stale)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("cannot read", &stale)(error)),
        }
        self.prune(served.as_deref())
    }

    /// The folder of the next generation, `next` in a new staging folder that only root can enter, with its final mode, so every file of it is complete before any other user can reach it.
    /// The modes are set after `mkdir`, so a umask such as `0077` does not close the folder to the owners of its files.
    pub fn stage(&self) -> Result<PathBuf, GenerationError> {
        let staging = self.mount_point.join(STAGING);
        let next = staging.join("next");
        for (folder, mode) in [(&staging, 0o700), (&next, 0o751)] {
            DirBuilder::new()
                .mode(0o700)
                .create(folder)
                .map_err(io_error("cannot create", folder))?;
            fs::set_permissions(folder, Permissions::from_mode(mode))
                .map_err(io_error("cannot set the mode of", folder))?;
        }
        Ok(next)
    }

    /// Removes the staging folder after a failed run, which holds only values that nothing serves.
    pub fn discard(&self) {
        drop(fs::remove_dir_all(self.mount_point.join(STAGING)));
    }

    /// Serves `next`, with its final mode, in one step: an exchange with the served generation, or with no served generation a rename to `active`, where the link already points.
    /// Returns the path of the generation that the link now serves.
    pub fn publish(&self, next: &Path) -> Result<PathBuf, GenerationError> {
        let target = match fs::read_link(&self.link) {
            Ok(target) => Some(target),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_error("cannot read", &self.link)(error)),
        };
        if let Some(served) = target.as_deref() {
            match fs::symlink_metadata(served) {
                Ok(meta) if meta.is_dir() => {
                    exchange(next, served).map_err(io_error("cannot exchange", served))?;
                    return Ok(served.to_owned());
                }
                Ok(_) => return Err(GenerationError::Occupied(served.to_owned())),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error("cannot read", served)(error)),
            }
        }
        let active = self.mount_point.join(ACTIVE);
        if target.as_deref() != Some(active.as_path()) {
            // `clean` removed a new link that an earlier run left, so the new link is made here or the run fails.
            let temporary = self.next_to_link(".new");
            symlink(&active, &temporary).map_err(io_error("cannot create", &temporary))?;
            fs::rename(&temporary, &self.link).map_err(io_error("cannot point", &self.link))?;
        }
        fs::rename(next, &active).map_err(io_error("cannot create", &active))?;
        Ok(active)
    }

    /// Removes the old generation, which the exchange left in the staging folder, and every generation but `served`.
    pub fn retire(&self, served: &Path) -> Result<(), GenerationError> {
        self.prune(Some(served))
    }

    fn next_to_link(&self, suffix: &str) -> PathBuf {
        let mut path = self.link.as_os_str().to_owned();
        path.push(suffix);
        PathBuf::from(path)
    }

    /// Removes the staging folder, `active`, and every numbered generation of an earlier version, but `keep`.
    fn prune(&self, keep: Option<&Path>) -> Result<(), GenerationError> {
        let entries =
            fs::read_dir(&self.mount_point).map_err(io_error("cannot read", &self.mount_point))?;
        for entry in entries {
            let path = entry
                .map_err(io_error("cannot read", &self.mount_point))?
                .path();
            let name = path.file_name().and_then(|name| name.to_str());
            let stale = name.is_some_and(|name| {
                name == STAGING || name == ACTIVE || name.parse::<u64>().is_ok()
            });
            if stale && Some(path.as_path()) != keep {
                fs::remove_dir_all(&path).map_err(io_error("cannot remove", &path))?;
            }
        }
        Ok(())
    }
}

/// Swaps two folders in one step, so a reader of either path sees the one generation or the other and never neither.
fn exchange(from: &Path, to: &Path) -> io::Result<()> {
    let from = CString::new(from.as_os_str().as_bytes())?;
    let to = CString::new(to.as_os_str().as_bytes())?;
    // SAFETY: both pointers are strings that end in NUL and live until the call returns.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn io_error(
    action: &'static str,
    path: impl AsRef<Path>,
) -> impl FnOnce(io::Error) -> GenerationError {
    let path = path.as_ref().to_owned();
    move |source| GenerationError::Io {
        action,
        path,
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};

    use super::Generations;

    fn folder(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sauce-generations-{}-{name}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        fs::create_dir_all(dir.join("sauce.d/7")).expect("a writable test folder");
        dir
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, Permissions::from_mode(mode)).expect("a test folder");
    }

    #[test]
    fn retire_keeps_the_served_generation_when_the_link_cannot_be_read() {
        let dir = folder("retire");
        let mount_point = dir.join("sauce.d");
        let links = dir.join("links");
        fs::create_dir(&links).expect("a writable test folder");
        let link = links.join("sauce");
        symlink(mount_point.join("7"), &link).expect("a writable test folder");
        let generations = Generations::new(&link, &mount_point);
        let next = generations.stage().unwrap();
        let served = generations.publish(&next).unwrap();

        set_mode(&links, 0o000);
        let retired = generations.retire(&served);
        set_mode(&links, 0o755);
        retired.unwrap();
        let left: Vec<_> = fs::read_dir(&mount_point)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(left, ["7"]);
    }

    #[test]
    fn publish_keeps_the_link_when_the_served_generation_cannot_be_read() {
        let dir = folder("publish");
        let mount_point = dir.join("sauce.d");
        let link = dir.join("sauce");
        symlink(mount_point.join("7"), &link).expect("a writable test folder");
        let generations = Generations::new(&link, &mount_point);
        let next = generations.stage().unwrap();

        // Without search permission on the mount point, the lookup of the served generation fails with an error other than NotFound.
        set_mode(&mount_point, 0o000);
        let published = generations.publish(&next);
        set_mode(&mount_point, 0o755);
        assert!(published.is_err());
        assert_eq!(fs::read_link(&link).unwrap(), mount_point.join("7"));
    }
}
