//! The `.sauce.yaml` files under a source root, and the files that the secrets declare, in one place for `sauce status`, `sauce remove` and the completion.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs, io,
    path::{Path, PathBuf},
    time::Instant,
};

use sauce::format::{self, Name};

use crate::manifest::Secret;

/// The files that the secrets declare, in `root`.
pub fn declared_files(secrets: &BTreeMap<Name, Secret<'_>>, root: &Path) -> BTreeSet<PathBuf> {
    secrets
        .values()
        .map(|secret| root.join(&secret.definition.file))
        .collect()
}

/// Collects every `.sauce.yaml` file under `root`, nearest folders first, and skips hidden folders and symbolic links.
///
/// With `until` it stops at that time and gives the files that it found, and a caller that must answer fast uses it.
pub fn sauce_files(
    root: &Path,
    until: Option<Instant>,
    unreadable: &mut Vec<(PathBuf, io::Error)>,
) -> Vec<PathBuf> {
    let late = || until.is_some_and(|until| Instant::now() >= until);
    let mut files = Vec::new();
    let mut folders = VecDeque::from([root.to_owned()]);
    while let Some(folder) = folders.pop_front() {
        if late() {
            break;
        }
        let entries = match fs::read_dir(&folder) {
            Ok(entries) => entries,
            Err(error) => {
                unreadable.push((folder, error));
                continue;
            }
        };
        for entry in entries.flatten() {
            if late() {
                return files;
            }
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() && !entry.file_name().to_string_lossy().starts_with('.') {
                folders.push_back(path);
            } else if kind.is_file() && format::has_suffix(&path) {
                files.push(path);
            }
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::Instant};

    use super::sauce_files;

    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("sauce-files-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("a/b")).expect("a folder");
        fs::create_dir_all(root.join(".hidden")).expect("a hidden folder");
        for file in [
            "top.sauce.yaml",
            "a/mid.sauce.yaml",
            "a/b/low.sauce.yaml",
            ".hidden/no.sauce.yaml",
            "a/other.txt",
        ] {
            fs::write(root.join(file), "").expect("a file");
        }
        root
    }

    #[test]
    fn the_walk_finds_the_files_that_status_and_remove_find() {
        let root = tree("walk");
        let mut files: Vec<_> = sauce_files(&root, None, &mut Vec::new())
            .into_iter()
            .map(|path| path.strip_prefix(&root).expect("under the root").to_owned())
            .collect();
        files.sort();
        fs::remove_dir_all(&root).expect("clean up");
        let expected: Vec<PathBuf> = ["a/b/low.sauce.yaml", "a/mid.sauce.yaml", "top.sauce.yaml"]
            .into_iter()
            .map(PathBuf::from)
            .collect();
        assert_eq!(files, expected, "no hidden folder and no other suffix");
    }

    #[test]
    fn a_walk_that_is_out_of_time_gives_what_it_has() {
        let root = tree("late");
        let past = Instant::now();
        let files = sauce_files(&root, Some(past), &mut Vec::new());
        fs::remove_dir_all(&root).expect("clean up");
        assert_eq!(files.len(), 0);
    }
}
