//! Runs `sauce-install` as the user of the test, with the throwaway keys of `example/snakeoil`.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use age::x25519::Identity;
use sauce::format::{Facts, Reader, Value, write};

const NAME: &str = "app/password";

/// The name of the line in `/etc/passwd` or `/etc/group` that has this id.
fn name_of(file: &str, id: u32) -> String {
    fs::read_to_string(file)
        .expect("a readable file of users or groups")
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.get(2)? == &id.to_string()).then(|| fields[0].to_owned())
        })
        .expect("a line with the id of the test")
}

fn key(machine: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../example/snakeoil/{machine}.key"))
}

fn placeholder(name: &str) -> String {
    format!("<SAUCE:{name}>")
}

fn seal(dir: &Path, machine: &str, name: &str, value: &str) -> PathBuf {
    let text = fs::read_to_string(key(machine)).expect("a throwaway key");
    let identity: Identity = text
        .lines()
        .find(|line| !line.starts_with('#'))
        .and_then(|line| line.parse().ok())
        .expect("an age identity");
    let facts = Facts {
        version: 1,
        set: "2026-11-18".parse().expect("a valid date"),
        issued: None,
        expires: None,
        generator: None,
        formerly: Vec::new(),
        revoke: false,
    };
    let reader = Reader {
        r#for: machine.to_owned(),
        age: identity.to_public().to_string(),
    };
    let text = write(
        &name.parse().expect("a valid name"),
        &Value::from(value.as_bytes().to_vec()),
        &facts,
        252,
        &[reader],
    )
    .expect("a valid write");
    let file = dir.join(format!("{machine}-{}.sauce.yaml", name.replace('/', "-")));
    fs::write(&file, text).expect("a writable test folder");
    file
}

/// Installs the secrets, each as `(name, file)`, and one template `app-env` with `content`.
fn install(dir: &Path, secrets: &[(&str, &Path)], content: &str) -> Output {
    let me = fs::metadata(dir).expect("the test folder");
    let delivery = |name: &str| {
        serde_json::json!({
            "name": name,
            "owner": name_of("/etc/passwd", me.uid()),
            "group": name_of("/etc/group", me.gid()),
            "mode": "0440",
            "restartUnits": [],
            "reloadUnits": [],
        })
    };
    let secrets: Vec<_> = secrets
        .iter()
        .map(|(name, file)| {
            let mut secret = delivery(name);
            secret["file"] = file.to_str().into();
            secret["placeholder"] = placeholder(name).into();
            secret
        })
        .collect();
    let mut template = delivery("app-env");
    template["content"] = content.into();
    let config = serde_json::json!({
        "identityFile": key("notes"),
        "link": dir.join("sauce"),
        "mountPoint": dir.join("sauce.d"),
        "secrets": secrets,
        "templates": [template],
    });
    let path = dir.join("config.json");
    fs::write(&path, config.to_string()).expect("a writable test folder");
    Command::new(env!("CARGO_BIN_EXE_sauce-install"))
        .arg(&path)
        .output()
        .expect("sauce-install runs")
}

fn test_folder(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    drop(fs::remove_dir_all(&dir));
    fs::create_dir_all(dir.join("sauce.d")).expect("a writable test folder");
    dir
}

#[test]
fn installs_a_secret_and_a_template_and_keeps_them_when_a_file_does_not_open() {
    let dir = test_folder("install");
    let content = format!("PASSWORD={}\n", placeholder(NAME));

    let file = seal(&dir, "notes", NAME, "first value");
    let installed = install(&dir, &[(NAME, &file)], &content);
    assert!(installed.status.success(), "{installed:?}");
    let secret = dir.join("sauce").join(NAME);
    assert_eq!(fs::read_to_string(&secret).unwrap(), "first value");
    assert_eq!(fs::metadata(&secret).unwrap().mode() & 0o7777, 0o440);
    assert_eq!(
        fs::read_to_string(dir.join("sauce/rendered/app-env")).unwrap(),
        "PASSWORD=first value\n"
    );

    let file = seal(&dir, "backup", NAME, "value for another key");
    let refused = install(&dir, &[(NAME, &file)], &content);
    assert!(!refused.status.success());
    let error = String::from_utf8(refused.stderr).unwrap();
    assert!(
        error.contains(&format!("sauce.secrets.\"{NAME}\"")),
        "{error}"
    );
    assert!(!error.contains("value for another key"), "{error}");
    assert_eq!(fs::read_to_string(&secret).unwrap(), "first value");
}

#[test]
fn a_value_that_holds_another_placeholder_stays_as_it_is_in_a_template() {
    let dir = test_folder("placeholder-in-value");
    let other = "app/other";
    let first = seal(&dir, "notes", NAME, &placeholder(other));
    let second = seal(&dir, "notes", other, "second value");
    let content = format!(
        "FIRST={}\nSECOND={}\n",
        placeholder(NAME),
        placeholder(other)
    );

    let installed = install(&dir, &[(NAME, &first), (other, &second)], &content);

    assert!(installed.status.success(), "{installed:?}");
    assert_eq!(
        fs::read_to_string(dir.join("sauce/rendered/app-env")).unwrap(),
        format!("FIRST={}\nSECOND=second value\n", placeholder(other))
    );
}

#[test]
fn a_directory_at_the_link_stays_and_stops_the_install() {
    let dir = test_folder("occupied");
    fs::create_dir_all(dir.join("sauce")).expect("a writable test folder");
    fs::write(dir.join("sauce/keep"), "not made by sauce-install").expect("a writable test folder");
    let file = seal(&dir, "notes", NAME, "first value");

    let refused = install(&dir, &[(NAME, &file)], &format!("{}\n", placeholder(NAME)));

    assert!(!refused.status.success());
    let error = String::from_utf8(refused.stderr).unwrap();
    assert!(error.contains("is in the way"), "{error}");
    assert_eq!(
        fs::read_to_string(dir.join("sauce/keep")).unwrap(),
        "not made by sauce-install"
    );
}
