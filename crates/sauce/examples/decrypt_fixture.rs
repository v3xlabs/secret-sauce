use std::{env, fs};

use age::x25519::Identity;
use sauce::format::{Facts, Key, Reader, Value, write};

fn main() {
    let key = fs::read_to_string(env::args().nth(1).expect("a key file path"))
        .expect("the key file is readable");
    let identity: Identity = key
        .lines()
        .find(|line| line.starts_with("AGE-SECRET-KEY-1"))
        .expect("the key file has an identity")
        .parse()
        .expect("a valid identity");
    let facts = Facts {
        version: 4,
        set: "2026-11-10".parse().expect("a valid date"),
        issued: Some("2026-11-01".parse().expect("a valid date")),
        expires: Some("2027-02-10".parse().expect("a valid date")),
        generator: Some([7; 32]),
        formerly: vec!["old/name".parse().expect("a valid name")],
        revoke: true,
    };
    let text = write(
        &"test/secret".parse().expect("a valid name"),
        &Value::from(b"correct horse".to_vec()),
        &facts,
        252,
        &[
            Reader {
                r#for: "admin".to_owned(),
                key: Key::Age(identity.to_public().to_string()),
            },
            // The second decrypt program skips a GPG reader, but binds its fingerprint as `sauce` does.
            Reader {
                r#for: "admin".to_owned(),
                key: Key::Pgp("0123456789ABCDEF0123456789ABCDEF01234567".to_owned()),
            },
            Reader {
                r#for: "backup".to_owned(),
                key: Key::Age(identity.to_public().to_string()),
            },
        ],
        |_, _| Ok(vec![0xc1, 1, 0, 0xd2, 1, 0]),
    )
    .expect("a valid file");
    print!("{text}");
}
