use std::{env, fs};

use age::x25519::Identity;
use sauce::format::{Facts, Reader, Value, write};

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
                age: identity.to_public().to_string(),
            },
            Reader {
                r#for: "backup".to_owned(),
                age: identity.to_public().to_string(),
            },
        ],
    )
    .expect("a valid file");
    print!("{text}");
}
