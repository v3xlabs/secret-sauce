//! Runs `sauce-install` as the user of the test, with the throwaway keys of `example/snakeoil`.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use age::x25519::Identity;
use sauce::format::{Facts, Key, Reader, Value, write};

const NAME: &str = "app/password";
/// A run takes well under a second, so a run past this is stuck, as on the open of a FIFO, and fails the test.
const DEADLINE: Duration = Duration::from_secs(30);

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

/// A copy of the key of `notes` in `dir` with `mode`, because sauce-install reads only a key that no other user can read.
fn identity(dir: &Path, mode: u32) -> PathBuf {
    let path = dir.join("identity.key");
    fs::copy(key("notes"), &path).expect("a writable test folder");
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("a writable test folder");
    path
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
        key: Key::Age(identity.to_public().to_string()),
    };
    // A GPG reader as an admin has, so that every test proves a machine skips its entry without gpg.
    let admin = Reader {
        r#for: "admin".to_owned(),
        key: Key::Pgp("0123456789ABCDEF0123456789ABCDEF01234567".to_owned()),
    };
    let text = write(
        &name.parse().expect("a valid name"),
        &Value::from(value.as_bytes().to_vec()),
        &facts,
        252,
        &[reader, admin],
        |_, _| Ok(vec![0xc1, 1, 0, 0xd2, 1, 0]),
    )
    .expect("a valid write");
    let file = dir.join(format!("{machine}-{}.sauce.yaml", name.replace('/', "-")));
    fs::write(&file, text).expect("a writable test folder");
    file
}

fn install(dir: &Path, identity: &Path, secrets: &[(&str, &Path)], content: &str) -> Output {
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
        "identityFile": identity,
        "link": dir.join("sauce"),
        "mountPoint": dir.join("sauce.d"),
        "secrets": secrets,
        "sshKeyPaths": [],
        "templates": [template],
    });
    let path = dir.join("config.json");
    fs::write(&path, config.to_string()).expect("a writable test folder");
    let mut child = Command::new(env!("CARGO_BIN_EXE_sauce-install"))
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sauce-install runs");
    let start = Instant::now();
    let ended = |child: &mut Child| {
        child
            .try_wait()
            .expect("sauce-install can be waited for")
            .is_some()
    };
    while !ended(&mut child) && start.elapsed() < DEADLINE {
        thread::sleep(Duration::from_millis(20));
    }
    let stuck = !ended(&mut child);
    if stuck {
        child.kill().expect("sauce-install can be killed");
    }
    let output = child.wait_with_output().expect("sauce-install ends");
    assert!(!stuck, "sauce-install ran past {DEADLINE:?}");
    output
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
    let installed = install(&dir, &identity(&dir, 0o600), &[(NAME, &file)], &content);
    assert!(installed.status.success(), "{installed:?}");
    let secret = dir.join("sauce").join(NAME);
    assert_eq!(fs::read_to_string(&secret).unwrap(), "first value");
    assert_eq!(fs::metadata(&secret).unwrap().mode() & 0o7777, 0o440);
    assert_eq!(
        fs::read_to_string(dir.join("sauce/rendered/app-env")).unwrap(),
        "PASSWORD=first value\n"
    );

    let file = seal(&dir, "backup", NAME, "value for another key");
    let refused = install(&dir, &identity(&dir, 0o600), &[(NAME, &file)], &content);
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
fn a_key_that_another_user_can_read_is_refused_by_its_path() {
    let dir = test_folder("readable-key");
    let file = seal(&dir, "notes", NAME, "first value");
    let key = identity(&dir, 0o640);

    let refused = install(
        &dir,
        &key,
        &[(NAME, &file)],
        &format!("{}\n", placeholder(NAME)),
    );

    assert!(!refused.status.success());
    let error = String::from_utf8(refused.stderr).unwrap();
    assert!(error.contains(&key.display().to_string()), "{error}");
    assert!(!error.contains("AGE-SECRET-KEY"), "{error}");
    assert!(!dir.join("sauce").exists());

    // A FIFO with no writer would block an open, and it is refused before one.
    let fifo = dir.join("fifo.key");
    let made = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo runs");
    assert!(made.success());
    let refused = install(
        &dir,
        &fifo,
        &[(NAME, &file)],
        &format!("{}\n", placeholder(NAME)),
    );
    assert!(!refused.status.success());
    let error = String::from_utf8(refused.stderr).unwrap();
    assert!(error.contains(&fifo.display().to_string()), "{error}");
}

#[test]
fn a_key_behind_a_folder_that_another_user_can_change_is_refused() {
    let dir = test_folder("open-folder");
    let file = seal(&dir, "notes", NAME, "first value");
    let content = format!("{}\n", placeholder(NAME));
    let key = identity(&dir, 0o600);

    // A link in a folder of the test user, which nobody else can change, leads to the key.
    let link = dir.join("link.key");
    std::os::unix::fs::symlink(&key, &link).expect("a writable test folder");
    let installed = install(&dir, &link, &[(NAME, &file)], &content);
    assert!(installed.status.success(), "{installed:?}");

    // A link whose target ends in `/` is a folder on the way to the key, which is fine.
    let keys = dir.join("keys");
    fs::create_dir(&keys).expect("a writable test folder");
    fs::copy(&key, keys.join("identity.key")).expect("a writable test folder");
    let mut target = keys.into_os_string();
    target.push("/");
    std::os::unix::fs::symlink(&target, dir.join("keys-link")).expect("a writable test folder");
    let through_folder_link = dir.join("keys-link/identity.key");
    let installed = install(&dir, &through_folder_link, &[(NAME, &file)], &content);
    assert!(installed.status.success(), "{installed:?}");

    // A folder that every user can write could hold the key, or a link to any other key.
    let open = dir.join("open");
    fs::create_dir(&open).expect("a writable test folder");
    fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).expect("a writable test folder");
    let copied = open.join("identity.key");
    fs::copy(&key, &copied).expect("a writable test folder");
    let linked = open.join("link.key");
    std::os::unix::fs::symlink(&key, &linked).expect("a writable test folder");
    // A link in the folder of the test user whose target goes through that open folder.
    let through = dir.join("through-open.key");
    std::os::unix::fs::symlink(&copied, &through).expect("a writable test folder");
    // A path that ends in `/` or `/.` names a folder, which Linux refuses for a file.
    let mut folder = key.clone().into_os_string();
    folder.push("/");
    let mut current = folder.clone();
    current.push(".");
    for path in [copied, linked, through, folder.into(), current.into()] {
        let refused = install(&dir, &path, &[(NAME, &file)], &content);
        assert!(!refused.status.success(), "{}", path.display());
        let error = String::from_utf8(refused.stderr).unwrap();
        assert!(error.contains(&path.display().to_string()), "{error}");
    }
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

    let installed = install(
        &dir,
        &identity(&dir, 0o600),
        &[(NAME, &first), (other, &second)],
        &content,
    );

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

    let refused = install(
        &dir,
        &identity(&dir, 0o600),
        &[(NAME, &file)],
        &format!("{}\n", placeholder(NAME)),
    );

    assert!(!refused.status.success());
    let error = String::from_utf8(refused.stderr).unwrap();
    assert!(error.contains("is in the way"), "{error}");
    assert_eq!(
        fs::read_to_string(dir.join("sauce/keep")).unwrap(),
        "not made by sauce-install"
    );
}
