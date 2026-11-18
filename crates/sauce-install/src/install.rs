use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, fchown, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use age::x25519;
use sauce::format::{self, Name, NameError, ReadError};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::ids::Ids;

/// The bytes that `holds` reads at a time, so the old file never needs more memory than this.
const CHUNK: usize = 8192;
const RENDERED: &str = "rendered";

/// The JSON file that the NixOS module writes for one run.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    identity_file: PathBuf,
    /// Points at the newest generation, a numbered directory in `mount_point`.
    link: PathBuf,
    /// A tmpfs that the NixOS module mounts before the run.
    mount_point: PathBuf,
    secrets: Vec<Secret>,
    templates: Vec<Template>,
}

/// Where a file goes on the machine and what changes when it changes.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Delivery {
    group: String,
    mode: String,
    name: String,
    owner: String,
    reload_units: Vec<String>,
    restart_units: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot parse {path}: {source}")]
    Config {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("{action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error(
        "{0} is full, so the new files do not fit and the current files stay, and a file that a service made larger can be the cause"
    )]
    Full(PathBuf),
    #[error("{0} holds no age X25519 identity")]
    Identity(PathBuf),
    #[error("{name} has the mode {mode}, which is not an octal number up to 7777")]
    Mode { mode: String, name: String },
    #[error("{name} is not a valid name: {source}")]
    Name { name: String, source: NameError },
    #[error(
        "{0} is in the way, because it is not a link that sauce-install made, so remove it by hand"
    )]
    Occupied(PathBuf),
    #[error("sauce.secrets.\"{0}\" has no .sauce file, so run `sauce generate` first")]
    NoFile(String),
    #[error("cannot open the .sauce file of sauce.secrets.\"{name}\": {source}")]
    Open { name: String, source: ReadError },
    #[error("cannot run systemctl {verb}: {source}")]
    Systemctl {
        source: io::Error,
        verb: &'static str,
    },
    #[error("systemctl {verb} failed for {units}")]
    SystemctlFailed { units: String, verb: &'static str },
    #[error("{name} has the {kind} {id}, which {file} does not list")]
    UnknownId {
        file: &'static str,
        id: String,
        kind: &'static str,
        name: String,
    },
}

/// One file to write, relative to the generation directory.
struct Output<'a> {
    delivery: &'a Delivery,
    gid: u32,
    mode: u32,
    relative: PathBuf,
    uid: u32,
    value: Zeroizing<Vec<u8>>,
}

#[derive(Deserialize)]
struct Secret {
    #[serde(flatten)]
    delivery: Delivery,
    /// The `.sauce` file in the Nix store, or nothing when the declared file does not exist.
    file: Option<PathBuf>,
    placeholder: String,
}

#[derive(Deserialize)]
struct Template {
    content: String,
    #[serde(flatten)]
    delivery: Delivery,
}

/// The units to restart and to reload after a switch.
#[derive(Default)]
struct Units {
    reload: Vec<String>,
    restart: Vec<String>,
}

impl Units {
    /// One line for each unit, `restart <unit>` or `reload <unit>`.
    fn load(path: &Path) -> io::Result<Self> {
        let mut units = Self::default();
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(units),
            Err(error) => return Err(error),
        };
        for line in text.lines() {
            match line.split_once(' ') {
                Some(("restart", unit)) => units.restart.push(unit.to_owned()),
                Some(("reload", unit)) => units.reload.push(unit.to_owned()),
                _ => {}
            }
        }
        Ok(units)
    }

    fn save(&self, path: &Path) -> io::Result<()> {
        let lines: String = [("restart", &self.restart), ("reload", &self.reload)]
            .into_iter()
            .flat_map(|(verb, units)| units.iter().map(move |unit| format!("{verb} {unit}\n")))
            .collect();
        fs::write(path, lines)
    }
}

/// Opens every secret and renders every template before it writes anything, so a failure leaves the current generation as it is.
pub fn run(config_path: &Path) -> Result<(), Error> {
    let text = fs::read(config_path).map_err(io_error("cannot read", config_path))?;
    let config: Config = serde_json::from_slice(&text).map_err(|source| Error::Config {
        path: config_path.to_owned(),
        source,
    })?;
    let identity = identity(&config.identity_file)?;
    let values = config
        .secrets
        .iter()
        .map(|secret| open(secret, &identity))
        .collect::<Result<Vec<_>, _>>()?;
    let rendered: Vec<_> = config
        .templates
        .iter()
        .map(|template| render(&template.content, &config.secrets, &values))
        .collect();

    let users =
        Ids::load(Path::new("/etc/passwd")).map_err(io_error("cannot read", "/etc/passwd"))?;
    let groups =
        Ids::load(Path::new("/etc/group")).map_err(io_error("cannot read", "/etc/group"))?;
    let secrets = config.secrets.iter().zip(values).map(|(secret, value)| {
        output(
            &secret.delivery,
            PathBuf::from(&secret.delivery.name),
            value,
            &users,
            &groups,
        )
    });
    let templates = config
        .templates
        .iter()
        .zip(rendered)
        .map(|(template, value)| {
            let relative = Path::new(RENDERED).join(&template.delivery.name);
            output(&template.delivery, relative, value, &users, &groups)
        });
    let outputs = secrets.chain(templates).collect::<Result<Vec<_>, _>>()?;

    let full = |error| match error {
        Error::Io {
            ref path,
            ref source,
            ..
        } if source.kind() == io::ErrorKind::StorageFull
            && path.starts_with(&config.mount_point) =>
        {
            Error::Full(config.mount_point.clone())
        }
        error => error,
    };
    let generation = new_generation(&config.link, &config.mount_point).map_err(full)?;
    let units = match switch(&config, &generation, &outputs) {
        Ok(units) => units,
        Err(error) => {
            // The link still points at the current generation, so the staged one is only a copy of values that nothing uses.
            drop(fs::remove_dir_all(&generation));
            return Err(full(error));
        }
    };
    // A former owner of a removed or changed file can open it through its old generation until the prune, so the prune comes before anything that can fail.
    prune(&config.mount_point, &generation)?;
    let pending = config.mount_point.join("pending");
    systemctl("try-restart", &units.restart)?;
    systemctl("try-reload-or-restart", &units.reload)?;
    match fs::remove_file(&pending) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            Err(io_error("cannot remove", &pending)(error))
        }
        _ => Ok(()),
    }
}

/// The units of the files that are new or differ from the current generation, and the units that an earlier run left pending.
/// A pending unit that no file declares any more is dropped, so a removed unit does not fail every later run.
fn changes(link: &Path, outputs: &[Output], pending: &Path) -> Result<Units, Error> {
    let mut units = Units::load(pending).map_err(io_error("cannot read", pending))?;
    units.restart.retain(|unit| {
        outputs
            .iter()
            .any(|output| output.delivery.restart_units.contains(unit))
    });
    units.reload.retain(|unit| {
        outputs
            .iter()
            .any(|output| output.delivery.reload_units.contains(unit))
    });
    let mut added = Vec::new();
    let mut modified = Vec::new();
    for output in outputs {
        let same =
            File::open(link.join(&output.relative)).and_then(|old| holds(old, &output.value));
        match same {
            Ok(true) => continue,
            Ok(false) => modified.push(output.delivery.name.as_str()),
            Err(_) => added.push(output.delivery.name.as_str()),
        }
        units
            .restart
            .extend_from_slice(&output.delivery.restart_units);
        units
            .reload
            .extend_from_slice(&output.delivery.reload_units);
    }
    for (verb, names) in [("adding", added), ("modifying", modified)] {
        if !names.is_empty() {
            eprintln!("sauce-install: {verb} {}", names.join(", "));
        }
    }
    for list in [&mut units.restart, &mut units.reload] {
        list.sort();
        list.dedup();
    }
    Ok(units)
}

/// Whether `old` holds exactly `value`.
/// It reads at most one byte past the length of `value`, because a service that owns the old file can make it longer than memory without filling the tmpfs, as a sparse file.
fn holds(old: impl Read, value: &[u8]) -> io::Result<bool> {
    let mut old = old.take(value.len() as u64 + 1);
    let mut chunk = Zeroizing::new([0; CHUNK]);
    let mut rest = value;
    loop {
        let read = match old.read(chunk.as_mut_slice()) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if read == 0 {
            return Ok(rest.is_empty());
        }
        match rest.split_at_checked(read) {
            Some((head, tail)) if head == &chunk[..read] => rest = tail,
            _ => return Ok(false),
        }
    }
}

/// The first line that is not empty and not a comment, as `age-keygen` writes it.
fn identity(path: &Path) -> Result<x25519::Identity, Error> {
    let text = Zeroizing::new(fs::read_to_string(path).map_err(io_error("cannot read", path))?);
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .and_then(|line| line.parse().ok())
        .ok_or_else(|| Error::Identity(path.to_owned()))
}

fn io_error(action: &'static str, path: impl AsRef<Path>) -> impl FnOnce(io::Error) -> Error {
    let path = path.as_ref().to_owned();
    move |source| Error::Io {
        action,
        path,
        source,
    }
}

fn new_generation(link: &Path, mount_point: &Path) -> Result<PathBuf, Error> {
    // Only a link into `mount_point` is one that sauce-install made, and anything else at `link` stays as it is.
    let current = match fs::symlink_metadata(link) {
        Ok(meta) if meta.is_symlink() => fs::read_link(link)
            .map_err(io_error("cannot read", link))?
            .strip_prefix(mount_point)
            .ok()
            .and_then(|name| name.to_str()?.parse::<u64>().ok())
            .ok_or_else(|| Error::Occupied(link.to_owned()))?,
        Ok(_) => return Err(Error::Occupied(link.to_owned())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(io_error("cannot read", link)(error)),
    };
    let generation = mount_point.join((current + 1).to_string());
    if generation.exists() {
        fs::remove_dir_all(&generation).map_err(io_error("cannot remove", &generation))?;
    }
    DirBuilder::new()
        .mode(0o751)
        .create(&generation)
        .map_err(io_error("cannot create", &generation))?;
    Ok(generation)
}

fn open(secret: &Secret, identity: &x25519::Identity) -> Result<Zeroizing<Vec<u8>>, Error> {
    let name = &secret.delivery.name;
    let expected: Name = name.parse().map_err(|source| Error::Name {
        name: name.clone(),
        source,
    })?;
    let file = secret
        .file
        .as_ref()
        .ok_or_else(|| Error::NoFile(name.clone()))?;
    let text = format::load(file).map_err(io_error("cannot read", file))?;
    let (value, _facts) =
        format::read(&text, &expected, identity).map_err(|source| Error::Open {
            name: name.clone(),
            source,
        })?;
    Ok(Zeroizing::new(value.expose().to_vec()))
}

fn output<'a>(
    delivery: &'a Delivery,
    relative: PathBuf,
    value: Zeroizing<Vec<u8>>,
    users: &Ids,
    groups: &Ids,
) -> Result<Output<'a>, Error> {
    let _: Name = delivery.name.parse().map_err(|source| Error::Name {
        name: delivery.name.clone(),
        source,
    })?;
    let unknown = |kind, file, id: &String| Error::UnknownId {
        file,
        id: id.clone(),
        kind,
        name: delivery.name.clone(),
    };
    let uid = users
        .get(&delivery.owner)
        .ok_or_else(|| unknown("owner", "/etc/passwd", &delivery.owner))?;
    let gid = groups
        .get(&delivery.group)
        .ok_or_else(|| unknown("group", "/etc/group", &delivery.group))?;
    let mode = u32::from_str_radix(&delivery.mode, 8)
        .ok()
        .filter(|mode| *mode <= 0o7777)
        .ok_or_else(|| Error::Mode {
            mode: delivery.mode.clone(),
            name: delivery.name.clone(),
        })?;
    Ok(Output {
        delivery,
        gid,
        mode,
        relative,
        uid,
        value,
    })
}

/// Removes every generation but the new one.
fn prune(mount_point: &Path, generation: &Path) -> Result<(), Error> {
    let entries = fs::read_dir(mount_point).map_err(io_error("cannot read", mount_point))?;
    for entry in entries {
        let path = entry.map_err(io_error("cannot read", mount_point))?.path();
        let numbered = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.parse::<u64>().is_ok());
        if numbered && path != generation {
            fs::remove_dir_all(&path).map_err(io_error("cannot remove", &path))?;
        }
    }
    Ok(())
}

/// Puts each value in place of its placeholder, in one pass over `content`.
/// A value goes in as it is and is never searched again, so a value that holds a placeholder cannot pull in another secret.
fn render(content: &str, secrets: &[Secret], values: &[Zeroizing<Vec<u8>>]) -> Zeroizing<Vec<u8>> {
    let content = content.as_bytes();
    let mut rendered = Zeroizing::new(Vec::with_capacity(content.len()));
    let mut at = 0;
    while at < content.len() {
        let rest = &content[at..];
        let found = secrets.iter().zip(values).find(|(secret, _)| {
            !secret.placeholder.is_empty() && rest.starts_with(secret.placeholder.as_bytes())
        });
        if let Some((secret, value)) = found {
            rendered.extend_from_slice(value);
            at += secret.placeholder.len();
        } else {
            rendered.push(content[at]);
            at += 1;
        }
    }
    rendered
}

/// Replaces `link` in one step, so a reader never sees it missing.
fn replace_symlink(target: &Path, link: &Path) -> io::Result<()> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos());
    let mut temporary = link.as_os_str().to_owned();
    temporary.push(format!(".new-{}-{nanos}", std::process::id()));
    let temporary = PathBuf::from(temporary);
    symlink(target, &temporary)?;
    let renamed = fs::rename(&temporary, link);
    if renamed.is_err() {
        drop(fs::remove_file(&temporary));
    }
    renamed
}

/// Writes the new generation, records its units in `pending`, and points `link` at it.
/// An error leaves `link` on the current generation.
fn switch(config: &Config, generation: &Path, outputs: &[Output]) -> Result<Units, Error> {
    write_all(generation, outputs)?;
    // Before systemd runs, at boot, no unit has started yet, so there is nothing to restart.
    let booted = Path::new("/run/systemd/system").exists();
    let pending = config.mount_point.join("pending");
    let units = if booted {
        changes(&config.link, outputs, &pending)?
    } else {
        Units::default()
    };
    // A run that fails after the switch leaves the units in `pending`, so the next run restarts them.
    units
        .save(&pending)
        .map_err(io_error("cannot write", &pending))?;
    replace_symlink(generation, &config.link).map_err(io_error("cannot point", &config.link))?;
    Ok(units)
}

fn systemctl(verb: &'static str, units: &[String]) -> Result<(), Error> {
    if units.is_empty() {
        return Ok(());
    }
    let status = Command::new("systemctl")
        .args(["--no-block", verb])
        .args(units)
        .status()
        .map_err(|source| Error::Systemctl { source, verb })?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::SystemctlFailed {
            units: units.join(" "),
            verb,
        })
    }
}

fn write_all(generation: &Path, outputs: &[Output]) -> Result<(), Error> {
    for output in outputs {
        let path = generation.join(&output.relative);
        if let Some(parent) = path.parent() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o751)
                .create(parent)
                .map_err(io_error("cannot create", parent))?;
        }
        write_file(&path, output).map_err(io_error("cannot write", &path))?;
    }
    Ok(())
}

/// The file starts with mode 0600 and the owner of this process, so no other user can read it before its owner and mode are set.
fn write_file(path: &Path, output: &Output) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&output.value)?;
    fchown(&file, Some(output.uid), Some(output.gid))?;
    file.set_permissions(Permissions::from_mode(output.mode))
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{CHUNK, holds};

    #[test]
    fn an_endless_old_file_differs_and_is_read_only_past_the_value() {
        assert!(!holds(io::repeat(0), &vec![0; CHUNK * 3]).unwrap());
    }

    #[test]
    fn only_the_same_bytes_hold_the_value() {
        let value: Vec<u8> = (0..=u8::MAX).cycle().take(CHUNK * 2 + 7).collect();
        let longer = [value.as_slice(), &[0]].concat();
        let mut changed = value.clone();
        changed[CHUNK + 1] ^= 1;

        assert!(holds(value.as_slice(), &value).unwrap());
        assert!(!holds(longer.as_slice(), &value).unwrap());
        assert!(!holds(&value[..value.len() - 1], &value).unwrap());
        assert!(!holds(changed.as_slice(), &value).unwrap());
        assert!(holds(&b""[..], b"").unwrap());
    }
}
