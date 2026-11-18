use std::{
    env, fmt,
    io::{self, IsTerminal as _},
};

pub enum Color {
    Green,
    Yellow,
    Red,
    Cyan,
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
}

impl<T: fmt::Display> fmt::Display for Painted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self.color {
            Some(Color::Green) => 32,
            Some(Color::Yellow) => 33,
            Some(Color::Red) => 31,
            Some(Color::Cyan) => 36,
            None => return self.text.fmt(f),
        };
        write!(f, "\x1b[{code}m{}\x1b[0m", self.text)
    }
}
