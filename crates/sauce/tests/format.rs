use std::cell::Cell;

use age::{secrecy::ExposeSecret as _, x25519::Identity};
use age_core::format::FileKey;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as BASE64};
use sauce::format::{
    Facts, Key, Name, Opener, ReadError, Reader, Value, WriteError, look, read, read_facts, write,
};

const NAME: &str = "kanidm/oauth2/freshrss";

const FINGERPRINT: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

fn name(text: &str) -> Name {
    text.parse().expect("a valid name")
}

fn facts(expires: Option<&str>) -> Facts {
    Facts {
        version: 4,
        set: "2026-11-10".parse().expect("a valid date"),
        issued: None,
        expires: expires.map(|date| date.parse().expect("a valid date")),
        generator: Some([7; 32]),
        formerly: vec![name("freshrss/oauth2")],
        revoke: false,
    }
}

fn reader(host: &str, identity: &Identity) -> Reader {
    Reader {
        r#for: host.to_owned(),
        key: Key::Age(identity.to_public().to_string()),
    }
}

fn write_for(value: &[u8], bound: usize, facts: &Facts, readers: &[Reader]) -> String {
    write(
        &name(NAME),
        &Value::from(value.to_vec()),
        facts,
        bound,
        readers,
        |_, _| unreachable!("these files have no GPG reader"),
    )
    .expect("a valid write")
}

fn line<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find(|line| line.starts_with(key))
        .expect("the file has the line")
}

#[test]
fn every_reader_opens_the_same_value_and_facts() {
    let (admin, web) = (Identity::generate(), Identity::generate());
    let facts = facts(Some("2027-02-10"));
    let readers = [reader("admin", &admin), reader("web", &web)];
    let text = write_for(b"correct horse", 252, &facts, &readers);
    for identity in [&admin, &web] {
        let (value, opened) = read(&text, &name(NAME), Opener::Age(identity)).unwrap();
        assert_eq!(value.expose(), b"correct horse");
        assert_eq!(opened, facts);
    }
}

#[test]
fn a_key_that_is_not_a_reader_gets_an_error() {
    let admin = Identity::generate();
    let text = write_for(
        b"correct horse",
        252,
        &facts(None),
        &[reader("admin", &admin)],
    );
    let opened = read(&text, &name(NAME), Opener::Age(&Identity::generate()));
    assert!(matches!(opened, Err(ReadError::NotAReader)));
}

#[test]
fn a_changed_file_fails_to_open() {
    let (admin, web) = (Identity::generate(), Identity::generate());
    let readers = [reader("admin", &admin), reader("web", &web)];
    let text = write_for(b"correct horse", 252, &facts(None), &readers);
    let open = |text: &str, expected: &str| read(text, &name(expected), Opener::Age(&admin));

    let renamed = text.replace(&format!("name: {NAME}\n"), "name: kanidm/other\n");
    assert!(matches!(
        open(&renamed, "kanidm/other"),
        Err(ReadError::Decrypt)
    ));

    let stranger = reader("stranger", &Identity::generate());
    let stanza = line(&text, "      - ");
    let one_more = format!(
        "{text}  - for: {}\n    age: {}\n    wrap:\n{stanza}\n",
        stranger.r#for, stranger.key
    );
    assert!(matches!(open(&one_more, NAME), Err(ReadError::Decrypt)));

    let sealed_facts = &line(&text, "facts: ")["facts: ".len()..];
    let sealed_value = &line(&text, "value: ")["value: ".len()..];
    let swapped = text
        .replace(sealed_facts, "\0")
        .replace(sealed_value, sealed_facts)
        .replace('\0', sealed_value);
    assert!(matches!(open(&swapped, NAME), Err(ReadError::Decrypt)));

    let other = write_for(b"correct horse", 252, &facts(None), &readers);
    let recommitted = text.replace(line(&text, "commitment: "), line(&other, "commitment: "));
    assert!(matches!(
        open(&recommitted, NAME),
        Err(ReadError::Commitment)
    ));
}

#[test]
fn small_values_have_values_of_the_same_length() {
    let readers = [reader("admin", &Identity::generate())];
    let boolean = write_for(b"true", 5, &facts(None), &readers);
    let port = write_for(b"8080", 5, &facts(None), &readers);
    let password = write_for(&[b'x'; 40], 40, &facts(None), &readers);
    let length = |text: &str| line(text, "value: ").len();
    assert_eq!(length(&boolean), length(&port));
    assert_eq!(length(&boolean), length(&password));
}

#[test]
fn an_expiry_date_does_not_change_the_length_of_facts() {
    let readers = [reader("admin", &Identity::generate())];
    let with = write_for(b"token", 252, &facts(Some("2027-02-10")), &readers);
    let without = write_for(b"token", 252, &facts(None), &readers);
    assert_eq!(
        line(&with, "facts: ").len(),
        line(&without, "facts: ").len()
    );
}

#[test]
fn a_value_longer_than_its_bound_is_refused() {
    let readers = [reader("admin", &Identity::generate())];
    let written = write(
        &name(NAME),
        &Value::from(b"123456".to_vec()),
        &facts(None),
        5,
        &readers,
        |_, _| unreachable!("the value is refused first"),
    );
    assert!(matches!(written, Err(WriteError::TooLong(5))));
}

#[test]
fn a_sealed_field_opens_at_each_step_and_fails_at_its_line_off_a_step() {
    let admin = Identity::generate();
    let readers = [reader("admin", &admin)];
    for bound in [252, 1020, 4092, 8188, 16380, 32764, 65532] {
        let text = write_for(b"token", bound, &facts(None), &readers);
        assert_eq!(
            read(&text, &name(NAME), Opener::Age(&admin))
                .unwrap()
                .0
                .expose(),
            b"token"
        );
    }

    let text = write_for(b"token", 252, &facts(None), &readers);
    let off_step = BASE64.encode([0; 256 + 16 + 3]);
    for (key, number) in [("facts: ", 4), ("value: ", 5)] {
        let changed = text.replace(&line(&text, key)[key.len()..], &off_step);
        assert_eq!(look(&changed).err().map(|error| error.line), Some(number));
    }
}

#[test]
fn facts_open_when_the_value_does_not() {
    let admin = Identity::generate();
    let facts = facts(Some("2027-02-10"));
    let text = write_for(b"correct horse", 252, &facts, &[reader("admin", &admin)]);
    let sealed_facts = &line(&text, "facts: ")["facts: ".len()..];
    let sealed_value = &line(&text, "value: ")["value: ".len()..];
    let damaged = text.replace(sealed_value, sealed_facts);

    assert!(matches!(
        read(&damaged, &name(NAME), Opener::Age(&admin)),
        Err(ReadError::Decrypt)
    ));
    assert_eq!(
        read_facts(&damaged, &name(NAME), Opener::Age(&admin)).unwrap(),
        facts
    );
}

#[test]
fn facts_stay_as_checked_as_the_whole_file() {
    let (admin, web) = (Identity::generate(), Identity::generate());
    let readers = [reader("admin", &admin), reader("web", &web)];
    let text = write_for(b"correct horse", 252, &facts(None), &readers);
    let open = |text: &str, expected: &str| read_facts(text, &name(expected), Opener::Age(&admin));

    assert!(matches!(
        read_facts(&text, &name(NAME), Opener::Age(&Identity::generate())),
        Err(ReadError::NotAReader)
    ));
    assert!(matches!(open(&text, "kanidm/other"), Err(ReadError::Name)));

    let sealed_facts = &line(&text, "facts: ")["facts: ".len()..];
    let sealed_value = &line(&text, "value: ")["value: ".len()..];
    let swapped = text
        .replace(sealed_facts, "\0")
        .replace(sealed_value, sealed_facts)
        .replace('\0', sealed_value);
    assert!(matches!(open(&swapped, NAME), Err(ReadError::Decrypt)));

    let renamed = text.replace(&format!("name: {NAME}\n"), "name: kanidm/other\n");
    assert!(matches!(
        open(&renamed, "kanidm/other"),
        Err(ReadError::Decrypt)
    ));

    let other = write_for(b"correct horse", 252, &facts(None), &readers);
    let recommitted = text.replace(line(&text, "commitment: "), line(&other, "commitment: "));
    assert!(matches!(
        open(&recommitted, NAME),
        Err(ReadError::Commitment)
    ));
}

#[test]
fn a_gpg_reader_opens_with_the_file_key_that_its_wrap_holds() {
    let web = Identity::generate();
    let gpg = Reader {
        r#for: "admin".to_owned(),
        key: Key::Pgp(FINGERPRINT.to_owned()),
    };
    let wrapped = Cell::new(None);
    let text = write(
        &name(NAME),
        &Value::from(b"correct horse".to_vec()),
        &facts(None),
        252,
        &[reader("web", &web), gpg.clone()],
        |fingerprint, file_key| {
            assert_eq!(fingerprint, FINGERPRINT);
            wrapped.set(Some(*file_key.expose_secret()));
            Ok(b"wrap".to_vec())
        },
    )
    .unwrap();
    let entry = format!("  - for: admin\n    pgp: {FINGERPRINT}\n    wrap: d3JhcA\n");
    assert!(text.contains(&entry));
    let twice = format!("{text}{entry}");
    assert!(matches!(
        read(&twice, &name(NAME), Opener::Age(&web)),
        Err(ReadError::Parse(_))
    ));
    let file_key = wrapped.get().expect("the GPG reader got a wrap");

    let unwrap = |fingerprint: &str, wrap: &[u8]| {
        (fingerprint == FINGERPRINT && wrap == b"wrap")
            .then(|| Ok(FileKey::init_with_mut(|key| *key = file_key)))
    };
    let (value, _) = read(&text, &name(NAME), Opener::Pgp(&unwrap)).unwrap();
    assert_eq!(value.expose(), b"correct horse");
    let (value, _) = read(&text, &name(NAME), Opener::Age(&web)).unwrap();
    assert_eq!(value.expose(), b"correct horse");

    let wrong = |_: &str, _: &[u8]| Some(Ok(FileKey::init_with_mut(|key| *key = [0; 16])));
    assert!(matches!(
        read(&text, &name(NAME), Opener::Pgp(&wrong)),
        Err(ReadError::Commitment)
    ));

    let host = Reader {
        r#for: "web".to_owned(),
        ..gpg
    };
    let written = write(
        &name(NAME),
        &Value::from(b"correct horse".to_vec()),
        &facts(None),
        252,
        &[host],
        |_, _| unreachable!("a GPG key of a machine is refused first"),
    );
    assert!(matches!(written, Err(WriteError::Reader(0))));
}
