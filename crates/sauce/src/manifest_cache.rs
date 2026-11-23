use std::{
    collections::BTreeMap,
    env,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, BufReader, BufWriter, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use sauce::format::Name;

use crate::{
    manifest::{Machines, ReadError, ReadManifests, Secret},
    spinner::Step,
};

// Bump when the stored declarations or evaluator arguments change.
const CACHE_SCHEMA: u32 = 3;

#[derive(Deserialize, Serialize)]
struct Cached {
    key: String,
    machines: Machines,
}

/// The machines of a saved evaluation.
pub struct Saved(Machines);

#[derive(Deserialize)]
struct Metadata {
    fingerprint: Option<String>,
    path: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct NixConfig {
    abort_on_warn: Setting<bool>,
    accept_flake_config: Setting<bool>,
    allow_unsafe_native_code_during_evaluation: Setting<bool>,
    allowed_uris: Setting<Vec<String>>,
    experimental_features: Setting<Vec<String>>,
    plugin_files: Setting<Vec<PathBuf>>,
    pure_eval: Setting<bool>,
    restrict_eval: Setting<bool>,
    store: Setting<String>,
}

#[derive(Deserialize)]
struct Setting<T> {
    value: T,
}

impl Saved {
    /// The secrets that the machines declare, joined once, or none when the saved manifests break a rule.
    pub fn secrets(&self) -> BTreeMap<Name, Secret<'_>> {
        self.0.secrets().unwrap_or_default()
    }
}

fn cache_key(flake: &Path) -> Option<String> {
    // A saved flake setting can override the evaluator settings reported by `nix config show`.
    let nix_data = env_path("NIX_DATA_HOME")
        .or_else(|| data_home("XDG_DATA_HOME", ".local/share").map(|dir| dir.join("nix")))?;
    if !matches!(fs::symlink_metadata(nix_data.join("trusted-settings.json")), Err(error) if error.kind() == io::ErrorKind::NotFound)
    {
        return None;
    }
    let _step = Step::show("Checking the flake…");
    let probes: [&[&str]; 3] = [
        &[
            "flake",
            "metadata",
            "--json",
            "--no-update-lock-file",
            "--no-write-lock-file",
            ".",
        ],
        &["config", "show", "--json"],
        &["--version"],
    ];
    let [metadata, config, version] = probes
        .map(|args| {
            let mut command = Command::new("nix");
            crate::identity::without_key(&mut command);
            command
                .current_dir(flake)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
        })
        .map(|child| {
            let output = child.ok()?.wait_with_output().ok()?;
            output.status.success().then_some(output.stdout)
        });
    let metadata: Metadata = serde_json::from_slice(&metadata?).ok()?;
    let fingerprint = metadata.fingerprint.filter(|value| !value.is_empty())?;
    let config: NixConfig = serde_json::from_slice(&config?).ok()?;
    if !config.pure_eval.value
        || config.accept_flake_config.value
        || config.allow_unsafe_native_code_during_evaluation.value
        || !config.plugin_files.value.is_empty()
        || config.restrict_eval.value
        || config.abort_on_warn.value
    {
        return None;
    }
    let key = serde_json::to_vec(&(
        CACHE_SCHEMA,
        fingerprint,
        metadata.path,
        version?,
        config.experimental_features.value,
        config.allowed_uris.value,
        config.store.value,
    ))
    .ok()?;
    Some(format!("{:x}", Sha256::digest(key)))
}

fn cache_path(flake: &Path) -> Option<PathBuf> {
    let dir = data_home("XDG_CACHE_HOME", ".cache")?.join("sauce");
    let name = Sha256::digest(flake.as_os_str().as_encoded_bytes());
    Some(dir.join(format!("{name:x}.json")))
}

fn data_home(variable: &str, fallback: &str) -> Option<PathBuf> {
    env_path(variable).or_else(|| env_path("HOME").map(|home| home.join(fallback)))
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

pub fn load(flake: &Path) -> Result<ReadManifests, ReadError> {
    let Some((path, key)) = cache_path(flake).and_then(|path| Some((path, cache_key(flake)?)))
    else {
        return ReadManifests::eval(flake);
    };
    if let Some(cached) = read_cache(&path)
        && cached.key == key
    {
        return Ok(cached.machines.into());
    }
    let machines = match ReadManifests::eval(flake)? {
        ReadManifests::Complete(machines) => machines,
        partial @ ReadManifests::Partial(_) => return Ok(partial),
    };
    // Do not save an evaluation under the fingerprint of a worktree it did not read.
    if cache_key(flake).as_ref() != Some(&key) {
        return Ok(machines.into());
    }
    let cached = Cached { key, machines };
    let _ = save_cache(&path, &cached);
    Ok(cached.machines.into())
}

/// The saved evaluation of `flake`, if there is one.
///
/// It does not compare the key of the save, because the key comes from `nix`, and a name that has gone stale only costs a wrong suggestion.
pub fn saved(flake: &Path) -> Option<Saved> {
    cache_path(flake)
        .and_then(|path| read_cache(&path))
        .map(|cached| Saved(cached.machines))
}

fn read_cache(path: &Path) -> Option<Cached> {
    if !writable_cache_dir(path.parent()?).ok()? {
        return None;
    }
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.permissions().mode() & 0o777 != 0o600 {
        return None;
    }
    serde_json::from_reader(BufReader::new(File::open(path).ok()?)).ok()
}

fn save_cache(path: &Path, cached: &Cached) -> io::Result<()> {
    let dir = path
        .parent()
        .expect("cache file is inside the sauce cache folder");
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    if !writable_cache_dir(dir)? {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    let mut suffix = [0; 8];
    OsRng
        .try_fill_bytes(&mut suffix)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let temp = dir.join(format!(".manifest-{:016x}.tmp", u64::from_ne_bytes(suffix)));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, cached)?;
        writer.flush()?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn writable_cache_dir(dir: &Path) -> io::Result<bool> {
    let meta = fs::symlink_metadata(dir)?;
    Ok(meta.is_dir() && meta.permissions().mode() & 0o022 == 0)
}
