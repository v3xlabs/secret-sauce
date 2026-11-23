//! The readers that secrets gain and lose, and how `generate` and `set` show them before they ask to write.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    io::{self, Write as _},
};

use sauce::format::{Key, Name, Reader};

use crate::color::{Color, Folders, Palette};

/// The readers that a secret gains and loses, from the readers of its file to the declared ones.
pub struct ReaderChange<'a> {
    gained: Vec<&'a Reader>,
    lost: Vec<Reader>,
}

/// One key and one kind of change; a key that is both an admin and a machine has one group for both roles.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Group<'a> {
    key: &'a str,
    pgp: bool,
    loses: bool,
}

impl<'a> ReaderChange<'a> {
    pub fn new(found: &[Reader], declared: &'a [Reader]) -> Self {
        Self {
            gained: declared
                .iter()
                .filter(|reader| !found.contains(reader))
                .collect(),
            lost: found
                .iter()
                .filter(|reader| !declared.contains(reader))
                .cloned()
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.gained.is_empty() && self.lost.is_empty()
    }

    /// Whether a reader of the file is not declared, so that it knows the value that the file holds.
    pub fn loses(&self) -> bool {
        !self.lost.is_empty()
    }
}

impl<'a> Group<'a> {
    fn new(reader: &'a Reader, loses: bool) -> Self {
        let (key, pgp) = match &reader.key {
            Key::Age(key) => (key.as_str(), false),
            Key::Pgp(fingerprint) => (fingerprint.as_str(), true),
        };
        Self { key, pgp, loses }
    }
}

/// Prints every reader that changes, each key once with the tree of the secrets that it gets or loses.
///
/// `declared` are all declared secrets in name order, the rows of `sauce list`, so each folder has the color that `list` gives it.
pub fn print<'a, 'b: 'a>(
    changes: impl IntoIterator<Item = (&'a Name, &'a ReaderChange<'b>)>,
    declared: impl IntoIterator<Item = &'a Name>,
) -> io::Result<()> {
    let palette = Palette::stderr();
    let folders = palette.folders(declared.into_iter().map(Name::as_str));
    io::stderr()
        .lock()
        .write_all(render(changes, palette, &folders).as_bytes())
}

/// The text of [`print`]: a header for each key and kind of change, with the key in full, and the names of its secrets below it.
fn render<'a, 'b: 'a>(
    changes: impl IntoIterator<Item = (&'a Name, &'a ReaderChange<'b>)>,
    palette: Palette,
    folders: &Folders,
) -> String {
    let mut groups: BTreeMap<Group<'_>, (BTreeSet<&str>, Vec<&Name>)> = BTreeMap::new();
    for (name, change) in changes {
        let gained = change.gained.iter().map(|reader| (*reader, false));
        let lost = change.lost.iter().map(|reader| (reader, true));
        for (reader, loses) in gained.chain(lost) {
            let (roles, names) = groups.entry(Group::new(reader, loses)).or_default();
            roles.insert(reader.r#for.as_str());
            names.push(name);
        }
    }
    // The order of the display: admins first, then machines by name, then keys, and gets before loses.
    let mut groups: Vec<_> = groups
        .into_iter()
        .map(|(group, (roles, mut names))| {
            let admin = roles.contains("admin");
            let roles: Vec<&str> = admin
                .then_some("admin")
                .into_iter()
                .chain(roles.into_iter().filter(|role| *role != "admin"))
                .collect();
            // A file can list one age key twice, which is still one secret for that key.
            names.sort_unstable();
            names.dedup();
            (!admin, roles, group, names)
        })
        .collect();
    groups.sort_unstable_by(|a, b| (a.0, &a.1, &a.2).cmp(&(b.0, &b.1, &b.2)));

    let mut text =
        String::from("These readers change. A key that gets access learns a value that exists:\n");
    for (_, roles, group, names) in &groups {
        let (kind, key) = if group.pgp {
            ("gpg", spaced(group.key))
        } else {
            ("age", group.key.to_owned())
        };
        let (verb, color) = if group.loses {
            ("loses", Color::Red)
        } else {
            ("gets", Color::Yellow)
        };
        let change = palette.paint(color, format!("{verb} {}", names.len()));
        writeln!(text, "  {} ({kind}) {key}  {change}", roles.join(", "))
            .expect("a string takes any text");
        for (index, name) in names.iter().enumerate() {
            let branch = if index + 1 == names.len() {
                "└─"
            } else {
                "├─"
            };
            writeln!(text, "    {branch} {}", folders.name(name.as_str()))
                .expect("a string takes any text");
        }
    }
    text
}

/// A GPG fingerprint in the ten groups of four that `gpg` prints, with a wider gap in the middle, so that it reads against a known fingerprint.
fn spaced(fingerprint: &str) -> String {
    let mut text = String::with_capacity(fingerprint.len() + fingerprint.len() / 4 + 1);
    for (index, character) in fingerprint.chars().enumerate() {
        if index > 0 && index % 4 == 0 {
            text.push_str(if index == 20 { "  " } else { " " });
        }
        text.push(character);
    }
    text
}

#[cfg(test)]
mod tests {
    use sauce::format::{Key, Name, Reader};

    use super::{ReaderChange, render};
    use crate::color::Palette;

    fn reader(role: &str, key: Key) -> Reader {
        Reader {
            r#for: role.to_owned(),
            key,
        }
    }

    #[test]
    fn changes_group_by_key_with_admins_first_and_gets_before_loses() {
        let admin = reader(
            "admin",
            Key::Pgp("716C1889C8EBE5C434C106C4C3575672485E2CEC".to_owned()),
        );
        // A machine whose name sorts before `admin`, so only the rule puts admins first.
        let alpha = reader("alpha", Key::Age("age1alpha".to_owned()));
        // A file can list one age key twice.
        let lost_twice = [alpha.clone(), alpha.clone(), admin.clone()];
        let only_admin = [admin.clone()];
        let only_alpha = [alpha.clone()];
        let both = [alpha, admin];
        let names: Vec<Name> = ["db/c", "app/b", "app/a", "app/d"]
            .iter()
            .map(|name| name.parse().unwrap())
            .collect();
        // The loss of `alpha` comes before its gain in the input.
        let changes = [
            ReaderChange::new(&lost_twice, &only_admin),
            ReaderChange::new(&only_alpha, &both),
            ReaderChange::new(&only_alpha, &both),
            ReaderChange::new(&only_admin, &both),
        ];
        let palette = Palette::default();

        let text = render(names.iter().zip(&changes), palette, &palette.folders([]));

        assert_eq!(
            text,
            "These readers change. A key that gets access learns a value that exists:\n\
             \x20 admin (gpg) 716C 1889 C8EB E5C4 34C1  06C4 C357 5672 485E 2CEC  gets 2\n\
             \x20   ├─ app/a\n\
             \x20   └─ app/b\n\
             \x20 alpha (age) age1alpha  gets 1\n\
             \x20   └─ app/d\n\
             \x20 alpha (age) age1alpha  loses 1\n\
             \x20   └─ db/c\n"
        );
    }

    #[test]
    fn a_key_with_two_roles_has_one_header_that_names_both() {
        let key = Key::Age("age1shared".to_owned());
        let declared = [reader("v3x-teapot", key.clone()), reader("admin", key)];
        let name: Name = "app/a".parse().unwrap();
        let change = ReaderChange::new(&[], &declared);
        let palette = Palette::default();

        let text = render([(&name, &change)], palette, &palette.folders([]));

        assert_eq!(
            text,
            "These readers change. A key that gets access learns a value that exists:\n\
             \x20 admin, v3x-teapot (age) age1shared  gets 1\n\
             \x20   └─ app/a\n"
        );
    }
}
