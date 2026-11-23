//! Tab completion of secret names, which never starts `nix`.
//!
//! The names come from the saved evaluation of the flake in the current folder, and from the `.sauce.yaml` files under its source root.
//! The files are found as `sauce status` and `sauce remove` find them, and a file gives its name through `format::look`, as they read it.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsStr,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use clap_complete::engine::CompletionCandidate;
use sauce::format::{self, Name};

use crate::{
    files::{declared_files, sauce_files},
    manifest::source_root,
    manifest_cache,
};

/// The variable that only the script of bash sets for a completion.
const BASH_COMPLETION_TYPE: &str = "_CLAP_COMPLETE_COMP_TYPE";

/// The variable that makes `sauce` complete, and gives the shell: `bash`, `zsh` or `fish`.
///
/// It is not `COMPLETE`, which other programs set too, and which would make a normal command print a script and do nothing else.
pub const VARIABLE: &str = "SAUCE_COMPLETE";

/// How long the search for `.sauce.yaml` files may take, the walk and the reading of the names together.
///
/// A completion must end within about 20 ms, and starting sauce and reading the saved evaluation take the rest.
/// A search that runs out of time keeps what it found, because the folders nearest to the root come first.
/// The time is checked between files, so one file that the format allows, up to 1 MiB, can run past it.
const SEARCH_BUDGET: Duration = Duration::from_millis(8);

/// The names, and the folders of the names up to the next `/`, that go on from `current`.
pub fn names(current: &OsStr) -> Vec<CompletionCandidate> {
    candidates(current, false, false)
}

/// Like [`names`], and a folder also gives its pattern, such as `sso/*`.
pub fn patterns(current: &OsStr) -> Vec<CompletionCandidate> {
    candidates(current, true, false)
}

/// Like [`patterns`], from the files on disk that the saved evaluation does not declare, because a secret that a machine declares cannot be removed.
/// With no saved evaluation every file counts, and the command itself refuses a declared secret.
pub fn leftovers(current: &OsStr) -> Vec<CompletionCandidate> {
    candidates(current, true, true)
}

fn candidates(current: &OsStr, patterns: bool, leftovers: bool) -> Vec<CompletionCandidate> {
    let Some(current) = current.to_str() else {
        return Vec::new();
    };
    let (quote, current) = match current.chars().next() {
        Some(quote @ ('\'' | '"')) => (Some(quote), &current[1..]),
        _ => (None, current),
    };
    // A word that already has a quote goes on with it, and the user types the `*` of a pattern in it.
    let patterns = patterns && quote.is_none();
    // Only the script of bash gives the type of completion, and `clap_complete` takes the variable of the shell out of the environment before it asks for candidates.
    let bash = env::var_os(BASH_COMPLETION_TYPE).is_some();
    // The script of bash puts a candidate in the line as it is, so the `*` has its backslash, and an open quote stays in it.
    // zsh and fish escape a candidate themselves and match it against the word without its quote, so they get the raw name.
    let star = if bash { "\\*" } else { "*" };
    let opened = |text: &str| match quote {
        Some(quote) if bash => format!("{quote}{text}"),
        _ => text.to_owned(),
    };
    let mut found = BTreeSet::new();
    for name in known(leftovers) {
        let Some(rest) = name.strip_prefix(current) else {
            continue;
        };
        // Readline closes a quote after a completed word that is not a directory, so inside a quote bash gets full names, and its common prefix goes on in the open quote.
        let in_quote = bash && quote.is_some();
        match rest.find('/').filter(|_| !in_quote) {
            Some(slash) => {
                let folder = format!("{current}{}", &rest[..=slash]);
                if patterns {
                    found.insert(format!("{folder}{star}"));
                }
                found.insert(opened(&folder));
            }
            None => {
                found.insert(opened(&name));
            }
        }
    }
    if patterns && current.ends_with('/') && !found.is_empty() {
        found.insert(format!("{current}{star}"));
    }
    found.into_iter().map(CompletionCandidate::new).collect()
}

/// The names that the saved evaluation or a file on disk gives, or with `leftovers` the names of the files that the saved evaluation does not declare.
///
/// With `leftovers` it follows `sauce remove`: a file counts as declared by its path as well as by its name, because a secret that a machine declares keeps its file when a rename leaves another name in it.
/// The names of the other commands need no path, so they join the saved evaluation for its names alone.
fn known(leftovers: bool) -> BTreeSet<String> {
    let Ok(flake) = fs::canonicalize(".") else {
        return BTreeSet::new();
    };
    let root = source_root(&flake);
    let saved = manifest_cache::saved(&flake);
    let secrets = saved
        .as_ref()
        .map_or_else(BTreeMap::new, manifest_cache::Saved::secrets);
    // The walk gets three quarters of the time, so that the files that it found are read when the tree is large.
    let started = Instant::now();
    let until = started + SEARCH_BUDGET;
    let mut files = sauce_files(root, Some(started + SEARCH_BUDGET * 3 / 4), &mut Vec::new());
    if leftovers {
        let declared = declared_files(&secrets, root);
        files.retain(|path| !declared.contains(path));
    }
    let mut names: BTreeSet<String> = names_in(files, until)
        .into_iter()
        .filter(|name| !leftovers || !secrets.contains_key(name))
        .map(|name| name.to_string())
        .collect();
    if !leftovers {
        names.extend(secrets.keys().map(ToString::to_string));
    }
    names
}

/// The name in each of `files`, read as `sauce remove` reads it, until `until`.
fn names_in(files: Vec<PathBuf>, until: Instant) -> Vec<Name> {
    let mut names = Vec::new();
    for path in files {
        if Instant::now() >= until {
            break;
        }
        if let Ok(Ok((name, _))) = format::load(&path).map(|text| format::look(&text)) {
            names.push(name);
        }
    }
    names
}
