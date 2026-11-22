//! A one-line spinner on stderr that names the step that sauce waits for.
//!
//! It draws only when stdout and stderr are terminals and `TERM` is not `dumb`, and only after [`DELAY`], so a fast command shows nothing.
//! A pipe on stdout, such as `sauce list | less`, never gets a frame over its screen.
//! A [`Step`] shows its text until it is dropped, so the line is gone before the code after the step prints a result, an error or a prompt.

use std::{
    env,
    io::{self, IsTerminal as _, Write as _},
    mem,
    sync::{Mutex, MutexGuard, Once, PoisonError},
    thread,
    time::{Duration, Instant},
};

/// How long a command runs before the first frame, so that a command that ends at once leaves the terminal as it was.
/// The animation thread wakes this often, so a step that starts between two frames shows after about this long.
const DELAY: Duration = Duration::from_millis(20);

const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// How long one frame stays, which makes the spinner turn about twelve times in a second.
const INTERVAL: Duration = Duration::from_millis(80);

/// Moves the cursor to the start of the line and erases the line.
const ERASE: &str = "\r\x1b[2K";

/// Turns autowrap off around a frame, because a frame wider than the terminal would wrap, and [`ERASE`] clears only the last row.
const NO_WRAP: &str = "\x1b[?7l";
const WRAP: &str = "\x1b[?7h";

static ANIMATION: Once = Once::new();

static LINE: Mutex<Line> = Mutex::new(Line {
    text: None,
    started: None,
    drawn: None,
    frame: 0,
});

struct Line {
    text: Option<String>,
    /// When the first step started, which is about when the command started.
    started: Option<Instant>,
    /// When the frame on the terminal was drawn, and `None` while the terminal shows no frame.
    drawn: Option<Instant>,
    frame: usize,
}

/// The text on the line while the value lives, and the text from before it when the value drops.
#[must_use = "the step ends when the value drops"]
pub struct Step {
    previous: Option<String>,
}

impl Step {
    /// Shows `text` on the line.
    pub fn show(text: impl Into<String>) -> Self {
        Self::replace(Some(text.into()))
    }

    /// Erases the line until the value drops, for a prompt or a program that writes to the terminal.
    pub fn hide() -> Self {
        Self::replace(None)
    }

    /// Shows `{verb} {count} secrets…`, such as `Reading 8 secrets…`.
    pub fn secrets(verb: &str, count: usize) -> Self {
        let noun = if count == 1 { "secret" } else { "secrets" };
        Self::show(format!("{verb} {count} {noun}…"))
    }

    fn replace(text: Option<String>) -> Self {
        ANIMATION.call_once(|| {
            if enabled() {
                thread::spawn(animate);
            }
        });
        Self {
            previous: lock().replace(text),
        }
    }
}

impl Line {
    fn draw(&mut self) {
        let Some(text) = &self.text else { return };
        let frame = FRAMES[self.frame % FRAMES.len()];
        // A terminal that cannot take a frame has nothing to show and nothing to clean.
        let _ = io::stderr().write_all(format!("{ERASE}{NO_WRAP}{frame} {text}{WRAP}").as_bytes());
        self.drawn = Some(Instant::now());
    }

    fn replace(&mut self, text: Option<String>) -> Option<String> {
        let previous = mem::replace(&mut self.text, text);
        self.started.get_or_insert_with(Instant::now);
        match (&self.text, self.drawn) {
            (Some(_), Some(_)) => self.draw(),
            (None, Some(_)) => {
                self.drawn = None;
                let _ = io::stderr().write_all(ERASE.as_bytes());
            }
            _ => {}
        }
        previous
    }

    fn tick(&mut self) {
        let Some(started) = self.started else { return };
        if started.elapsed() < DELAY || self.drawn.is_some_and(|at| at.elapsed() < INTERVAL) {
            return;
        }
        self.frame += 1;
        self.draw();
    }
}

impl Drop for Step {
    fn drop(&mut self) {
        lock().replace(self.previous.take());
    }
}

fn animate() {
    loop {
        thread::sleep(DELAY);
        lock().tick();
    }
}

fn enabled() -> bool {
    io::stdout().is_terminal()
        && io::stderr().is_terminal()
        && env::var_os("TERM").is_none_or(|term| term != "dumb")
}

fn lock() -> MutexGuard<'static, Line> {
    // The line holds no invariant that a panic in the animation could break.
    LINE.lock().unwrap_or_else(PoisonError::into_inner)
}
