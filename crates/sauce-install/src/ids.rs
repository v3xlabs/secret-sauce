use std::collections::HashMap;
use std::io;
use std::path::Path;

/// The numeric ids of the users in `/etc/passwd` or the groups in `/etc/group`, by name.
pub struct Ids(HashMap<String, u32>);

impl Ids {
    /// A missing file gives no names, because `/etc/passwd` does not exist yet before the first activation that makes users.
    pub fn load(path: &Path) -> io::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error),
        };
        let ids = text
            .lines()
            .filter_map(|line| {
                let mut fields = line.split(':');
                let name = fields.next()?;
                let id = fields.nth(1)?.parse().ok()?;
                Some((name.to_owned(), id))
            })
            .collect();
        Ok(Self(ids))
    }

    /// `root` is 0 on every system, so it resolves before `/etc/passwd` and `/etc/group` exist.
    pub fn get(&self, name: &str) -> Option<u32> {
        if name == "root" {
            return Some(0);
        }
        self.0.get(name).copied()
    }
}
