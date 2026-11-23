use std::{
    env, fmt,
    io::{self, IsTerminal as _},
};

#[derive(Clone, Copy)]
pub enum Color {
    Green,
    Yellow,
    Red,
    Cyan,
    Blue,
    Magenta,
}

#[derive(Clone, Copy)]
pub struct Palette(bool);

struct Painted<T> {
    color: Option<Color>,
    text: T,
}

impl Palette {
    pub fn stdout() -> Self {
        Self(
            io::stdout().is_terminal()
                && env::var_os("NO_COLOR").is_none()
                && env::var_os("TERM").is_none_or(|term| term != "dumb"),
        )
    }

    pub fn paint(self, color: Color, text: impl fmt::Display) -> impl fmt::Display {
        Painted {
            color: self.0.then_some(color),
            text,
        }
    }

    pub fn name(self, name: &str) -> impl fmt::Display {
        let (folder, file) = name.split_at(name.rfind('/').map_or(0, |slash| slash + 1));
        let color = (self.0 && !folder.is_empty()).then(|| Color::for_folder(folder));
        fmt::from_fn(move |f| {
            write!(
                f,
                "{}{file}",
                Painted {
                    color,
                    text: folder
                }
            )
        })
    }
}

impl Color {
    // A folder must keep its color on every build, so the hash is fixed and not `DefaultHasher`.
    // The palette has no green, yellow or red, because a folder in a state color would read as a state.
    fn for_folder(folder: &str) -> Self {
        let hash = folder
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
            });
        match hash % 3 {
            0 => Self::Blue,
            1 => Self::Magenta,
            _ => Self::Cyan,
        }
    }
}

impl<T: fmt::Display> fmt::Display for Painted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self.color {
            Some(Color::Green) => 32,
            Some(Color::Yellow) => 33,
            Some(Color::Red) => 31,
            Some(Color::Cyan) => 36,
            Some(Color::Blue) => 34,
            Some(Color::Magenta) => 35,
            None => return self.text.fmt(f),
        };
        write!(f, "\x1b[{code}m{}\x1b[0m", self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::Palette;

    #[test]
    fn a_folder_has_one_fixed_color() {
        let palette = Palette(true);
        assert_eq!(
            palette.name("backup/ssh-key").to_string(),
            "\x1b[36mbackup/\x1b[0mssh-key"
        );
        assert_eq!(
            palette.name("ddclient/api-token").to_string(),
            "\x1b[35mddclient/\x1b[0mapi-token"
        );
        assert_eq!(
            palette.name("hedgedoc/db-password").to_string(),
            "\x1b[34mhedgedoc/\x1b[0mdb-password"
        );
        assert_eq!(
            palette.name("hedgedoc/session-secret").to_string(),
            "\x1b[34mhedgedoc/\x1b[0msession-secret"
        );
    }

    #[test]
    fn the_folder_ends_at_the_last_slash() {
        let painted = Palette(true).name("a/b/c").to_string();
        assert!(painted.ends_with("a/b/\x1b[0mc"), "{painted:?}");
    }

    #[test]
    fn no_folder_or_no_palette_is_plain() {
        assert_eq!(Palette(true).name("password").to_string(), "password");
        assert_eq!(
            Palette(false).name("backup/ssh-key").to_string(),
            "backup/ssh-key"
        );
    }
}
