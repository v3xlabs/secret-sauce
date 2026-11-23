use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    io::{self, IsTerminal as _},
    ops::RangeInclusive,
};

/// The hues of the folder colors, in degrees, from teal to pink.
/// The range leaves out the hues around green at 120, yellow at 60 and red at 0 and 360, because a folder in a state color would read as a state.
const HUE_FROM: u32 = 170;
const HUE_TO: u32 = 320;

/// The most colors that a 24-bit terminal gets, one every 4 degrees of hue.
/// A smaller step is too small to tell apart, so more folders than this share colors, and never neighbours.
const TRUE_COLORS: u32 = 36;

/// The least spread between the strongest and the weakest channel of a cube color for a folder, so that it is a color and not a grey.
const CUBE_MIN_CHROMA: i32 = 80;

/// The brightness, in the weights of the Y' of video, that a folder color of 24-bit color has.
/// Teal and green look brighter than blue at one lightness, so each color is scaled to this brightness, which reads on a dark and on a light background alike.
const LUMA: u32 = 130;

/// The relative luminance of WCAG of a cube color for a folder, which gives it a contrast of at least 3 to 1 on a white and on a black background.
const CUBE_LUMINANCE: RangeInclusive<f32> = 0.1..=0.3;

/// The strongest channel of a color before it is scaled, with a saturation of 65% and a lightness of 60%.
const CHROMA: u32 = 133;

/// The weakest channel of a color before it is scaled.
const FLOOR: u32 = 87;

/// The levels of one channel in the 6 by 6 by 6 color cube of a 256-color terminal.
const CUBE_LEVELS: [i32; 6] = [0, 95, 135, 175, 215, 255];

/// The 16 basic colors that leave out green, yellow and red, in the order that a folder takes them.
const BASIC: [Color; 6] = [
    Color::Blue,
    Color::Magenta,
    Color::Cyan,
    Color::BrightBlue,
    Color::BrightMagenta,
    Color::BrightCyan,
];

#[derive(Clone, Copy)]
pub enum Color {
    Green,
    Yellow,
    Red,
    Cyan,
    Blue,
    Magenta,
    BrightCyan,
    BrightBlue,
    BrightMagenta,
    Indexed(u8),
    Rgb([u8; 3]),
}

/// The colors that a terminal shows, or none when the output is not a terminal, which is also the default.
#[derive(Clone, Copy, Default)]
pub struct Palette(Option<Depth>);

/// The color of each folder in one listing.
pub struct Folders {
    colors: BTreeMap<String, Color>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Depth {
    Basic,
    Indexed,
    TrueColor,
}

struct Painted<T> {
    color: Option<Color>,
    text: T,
}

impl Palette {
    pub fn stdout() -> Self {
        Self::terminal(io::stdout().is_terminal())
    }

    /// For the questions that `sauce` asks on stderr, so `sauce generate 2>&1 | cat` has no escape codes.
    pub fn stderr() -> Self {
        Self::terminal(io::stderr().is_terminal())
    }

    fn terminal(is_terminal: bool) -> Self {
        let enabled = is_terminal
            && env::var_os("NO_COLOR").is_none()
            && env::var_os("TERM").is_none_or(|term| term != "dumb");
        Self(enabled.then(|| {
            Depth::detect(
                env::var("COLORTERM").ok().as_deref(),
                env::var("TERM").ok().as_deref(),
            )
        }))
    }

    pub fn paint(self, color: Color, text: impl fmt::Display) -> impl fmt::Display {
        Painted {
            color: self.0.map(|_| color),
            text,
        }
    }

    /// Gives each folder of `names` its own color, so that the same names in the same order get the same colors on every run.
    ///
    /// `names` are the rows in the order that they show.
    /// The folders are in sorted order, and each starts at the slot of its fixed hash and takes the next free slot.
    /// With more folders than colors, a folder takes the next slot that no folder next to it in the rows has.
    pub fn folders<'a>(self, names: impl IntoIterator<Item = &'a str>) -> Folders {
        let Some(depth) = self.0 else {
            return Folders {
                colors: BTreeMap::new(),
            };
        };
        let rows: Vec<&str> = names.into_iter().map(|name| split(name).0).collect();
        let folders: BTreeSet<&str> = rows
            .iter()
            .copied()
            .filter(|folder| !folder.is_empty())
            .collect();
        let mut neighbours: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for pair in rows.windows(2) {
            if pair[0] != pair[1] && !pair[0].is_empty() && !pair[1].is_empty() {
                neighbours.entry(pair[0]).or_default().insert(pair[1]);
                neighbours.entry(pair[1]).or_default().insert(pair[0]);
            }
        }
        let slots = depth.slots(folders.len());
        let mut taken = vec![false; slots.len()];
        let mut slot_of: BTreeMap<&str, usize> = BTreeMap::new();
        for folder in folders {
            let start = hash(folder) % slots.len();
            let order = (0..slots.len()).map(|step| (start + step) % slots.len());
            let next_to = |slot: &usize| {
                neighbours
                    .get(folder)
                    .is_some_and(|next| next.iter().any(|other| slot_of.get(other) == Some(slot)))
            };
            // A folder with more neighbours than the colors left repeats one, which only a folder next to many others can do.
            let slot = order
                .clone()
                .find(|slot| !taken[*slot])
                .or_else(|| order.into_iter().find(|slot| !next_to(slot)))
                .unwrap_or(start);
            taken[slot] = true;
            slot_of.insert(folder, slot);
        }
        let colors = slot_of
            .into_iter()
            .map(|(folder, slot)| (folder.to_owned(), slots[slot]))
            .collect();
        Folders { colors }
    }
}

impl Folders {
    pub fn name(&self, name: &str) -> impl fmt::Display {
        let (folder, file) = split(name);
        let color = self.colors.get(folder).copied();
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

impl Depth {
    /// `COLORTERM` of `truecolor` or `24bit` is 24-bit color, a `TERM` with `256color` is 256 colors, and any other terminal has the 16 basic colors.
    fn detect(colorterm: Option<&str>, term: Option<&str>) -> Self {
        if matches!(colorterm, Some("truecolor" | "24bit")) {
            Self::TrueColor
        } else if term.is_some_and(|term| term.contains("256color")) {
            Self::Indexed
        } else {
            Self::Basic
        }
    }

    /// At most `wanted` different colors of this depth, spread evenly over the hues, and fewer when the depth has fewer.
    fn slots(self, wanted: usize) -> Vec<Color> {
        let wanted = u32::try_from(wanted).unwrap_or(u32::MAX);
        match self {
            Self::Basic => BASIC
                .into_iter()
                .take(usize::try_from(wanted.max(1)).expect("a count of colors fits in usize"))
                .collect(),
            Self::Indexed => {
                let mut candidates = cube_colors();
                let count = wanted.clamp(
                    1,
                    u32::try_from(candidates.len()).expect("the cube has 216 colors"),
                );
                // Each pick takes the cube color that is nearest to its hue, and one with a hue that no pick has before one that repeats a hue.
                let mut hues = Vec::new();
                (0..count)
                    .map(|pick| {
                        let target = hue(pick, count);
                        let nearest = (0..candidates.len())
                            .min_by_key(|at| {
                                let hue = candidates[*at].0;
                                (hues.contains(&hue), hue.abs_diff(target))
                            })
                            .expect("a cube color is left for each pick");
                        let (hue, index) = candidates.remove(nearest);
                        hues.push(hue);
                        Color::Indexed(index)
                    })
                    .collect()
            }
            Self::TrueColor => {
                let count = wanted.clamp(1, TRUE_COLORS);
                (0..count)
                    .map(|pick| Color::Rgb(rgb(hue(pick, count))))
                    .collect()
            }
        }
    }
}

impl fmt::Display for Color {
    /// The parameters of the escape sequence that sets the color.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Green => f.write_str("32"),
            Self::Yellow => f.write_str("33"),
            Self::Red => f.write_str("31"),
            Self::Cyan => f.write_str("36"),
            Self::Blue => f.write_str("34"),
            Self::Magenta => f.write_str("35"),
            Self::BrightCyan => f.write_str("96"),
            Self::BrightBlue => f.write_str("94"),
            Self::BrightMagenta => f.write_str("95"),
            Self::Indexed(index) => write!(f, "38;5;{index}"),
            Self::Rgb([red, green, blue]) => write!(f, "38;2;{red};{green};{blue}"),
        }
    }
}

impl<T: fmt::Display> fmt::Display for Painted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.color {
            Some(color) => write!(f, "\x1b[{color}m{}\x1b[0m", self.text),
            None => self.text.fmt(f),
        }
    }
}

/// The folder of a name, up to its last slash, and the rest.
fn split(name: &str) -> (&str, &str) {
    name.split_at(name.rfind('/').map_or(0, |slash| slash + 1))
}

/// A folder must keep its color on every build, so the hash is fixed and not `DefaultHasher`.
fn hash(folder: &str) -> usize {
    let hash = folder
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        });
    usize::try_from(hash >> 1).expect("63 bits fit in usize on 64-bit targets")
}

/// The hue in degrees of step `step` of `steps` over [`HUE_FROM`] to [`HUE_TO`].
fn hue(step: u32, steps: u32) -> u32 {
    HUE_FROM + (HUE_TO - HUE_FROM) * step / (steps - 1).max(1)
}

/// The Y' brightness of a color, from 0 to 255.
fn luma([red, green, blue]: [u32; 3]) -> u32 {
    (299 * red + 587 * green + 114 * blue) / 1000
}

/// The color of `hue` at the fixed saturation and lightness, scaled to the brightness [`LUMA`].
fn rgb(hue: u32) -> [u8; 3] {
    let offset = hue % 60;
    let rising = FLOOR + CHROMA * offset / 60;
    let falling = FLOOR + CHROMA * (60 - offset) / 60;
    let top = FLOOR + CHROMA;
    let base = match hue / 60 {
        0 => [top, rising, FLOOR],
        1 => [falling, top, FLOOR],
        2 => [FLOOR, top, rising],
        3 => [FLOOR, falling, top],
        4 => [rising, FLOOR, top],
        _ => [top, FLOOR, falling],
    };
    let brightness = luma(base);
    base.map(|channel| u8::try_from((channel * LUMA / brightness).min(255)).expect("capped at 255"))
}

/// The cube colors that suit a folder, as their hue and their index in the 256 colors.
fn cube_colors() -> Vec<(u32, u8)> {
    let mut colors = Vec::new();
    let cube = (0..6)
        .flat_map(|red| (0..6).flat_map(move |green| (0..6).map(move |blue| (red, green, blue))));
    for (red, green, blue) in cube {
        let [r, g, b] = [red, green, blue].map(|level| CUBE_LEVELS[level]);
        let (strongest, weakest) = (r.max(g).max(b), r.min(g).min(b));
        let chroma = strongest - weakest;
        let channels = [r, g, b].map(|level| u8::try_from(level).expect("a level is at most 255"));
        if chroma < CUBE_MIN_CHROMA || !CUBE_LUMINANCE.contains(&luminance(channels)) {
            continue;
        }
        let hue = if strongest == r {
            60 * (g - b) / chroma
        } else if strongest == g {
            120 + 60 * (b - r) / chroma
        } else {
            240 + 60 * (r - g) / chroma
        };
        let hue = u32::try_from(hue.rem_euclid(360)).expect("a hue is not negative");
        if (HUE_FROM..=HUE_TO).contains(&hue) {
            let index = u8::try_from(16 + 36 * red + 6 * green + blue)
                .expect("a cube index is at most 231");
            colors.push((hue, index));
        }
    }
    colors.sort_unstable();
    colors
}

/// The relative luminance of WCAG of a color, from 0 for black to 1 for white.
fn luminance(color: [u8; 3]) -> f32 {
    let [red, green, blue] = color.map(|channel| {
        let channel = f32::from(channel) / 255.0;
        if channel <= 0.039_28 {
            channel / 12.92
        } else {
            ((channel + 0.055) / 1.055).powf(2.4)
        }
    });
    0.2126 * red + 0.7152 * green + 0.0722 * blue
}

#[cfg(test)]
mod tests {
    use super::{BASIC, CUBE_LEVELS, Color, Depth, Palette, cube_colors};

    const DEPTHS: [Depth; 3] = [Depth::Basic, Depth::Indexed, Depth::TrueColor];

    /// The name of a secret in each of `folders`, under `parent`.
    fn names(parent: &str, folders: &[&str]) -> Vec<String> {
        folders
            .iter()
            .map(|folder| format!("{parent}{folder}/secret"))
            .collect()
    }

    /// The color of each folder in sorted order, as the escape sequence parameters.
    fn colors(depth: Depth, names: &[String]) -> Vec<String> {
        let folders = Palette(Some(depth)).folders(names.iter().map(String::as_str));
        folders.colors.values().map(ToString::to_string).collect()
    }

    /// Whether every two rows next to each other that have different folders have different colors, with the rows in sorted order as `sauce list` shows them.
    fn neighbours_differ(depth: Depth, names: &[String]) -> bool {
        let mut rows: Vec<&str> = names.iter().map(String::as_str).collect();
        rows.sort_unstable();
        let folders = Palette(Some(depth)).folders(rows.iter().copied());
        rows.windows(2).all(|pair| {
            let [(first, _), (second, _)] = [super::split(pair[0]), super::split(pair[1])];
            first == second
                || first.is_empty()
                || second.is_empty()
                || folders.colors[first].to_string() != folders.colors[second].to_string()
        })
    }

    #[test]
    fn four_folders_get_four_colors_at_each_depth_and_nesting() {
        for depth in DEPTHS {
            for parent in ["", "apps/", "apps/web/"] {
                let names = names(parent, &["freshrss", "kanidm", "sso", "voice-channel"]);
                let mut colors = colors(depth, &names);
                colors.sort();
                colors.dedup();
                assert_eq!(colors.len(), 4, "{depth:?} {parent:?}");
            }
        }
    }

    #[test]
    fn folders_up_to_the_colors_of_a_depth_all_differ() {
        for depth in DEPTHS {
            let available = depth.slots(usize::MAX).len();
            let names: Vec<String> = (0..available)
                .map(|n| format!("folder{n}/secret"))
                .collect();
            let mut colors = colors(depth, &names);
            colors.sort();
            colors.dedup();
            assert_eq!(colors.len(), available, "{depth:?}");
        }
    }

    #[test]
    fn folders_past_the_colors_of_a_depth_never_repeat_next_to_each_other() {
        let flat: Vec<String> = (0..300).map(|n| format!("folder{n:03}/secret")).collect();
        // The rows of `p/` come between the rows of its subfolders, so a folder is next to many others.
        let alternating: Vec<String> = (0..40)
            .flat_map(|n| [format!("p/k{n:02}"), format!("p/k{n:02}/secret")])
            .collect();
        // `a/` sorts after `a/t/`, so the order of the rows is not the order of the folders.
        let nested: Vec<String> = ["a", "b", "c", "d", "e", "t"]
            .iter()
            .map(|folder| format!("a/{folder}/secret"))
            .chain([String::from("a/z"), String::from("root")])
            .collect();
        for depth in DEPTHS {
            assert!(colors(depth, &flat).len() > depth.slots(usize::MAX).len());
            for names in [&flat, &alternating, &nested] {
                assert!(neighbours_differ(depth, names), "{depth:?}");
            }
        }
    }

    #[test]
    fn colors_of_256_colors_have_different_hues_while_the_cube_has_them() {
        let hues = cube_colors();
        let mut distinct: Vec<u32> = hues.iter().map(|(hue, _)| *hue).collect();
        distinct.dedup();
        for wanted in [4, 8, distinct.len()] {
            let picked = Depth::Indexed.slots(wanted);
            let mut seen: Vec<u32> = picked
                .iter()
                .map(|color| {
                    let Color::Indexed(index) = color else {
                        panic!("256 colors give indexed colors");
                    };
                    hues.iter()
                        .find(|(_, known)| known == index)
                        .expect("a pick is a candidate")
                        .0
                })
                .collect();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), wanted);
        }
    }

    /// The contrast of WCAG between a color and a background, from 1 to 21.
    fn contrast(color: [u8; 3], background: [u8; 3]) -> f64 {
        let luminance = |rgb: [u8; 3]| {
            let [red, green, blue] = rgb.map(|channel| {
                let channel = f64::from(channel) / 255.0;
                if channel <= 0.039_28 {
                    channel / 12.92
                } else {
                    ((channel + 0.055) / 1.055).powf(2.4)
                }
            });
            0.2126 * red + 0.7152 * green + 0.0722 * blue
        };
        let (a, b) = (luminance(color), luminance(background));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    #[test]
    fn colors_of_256_colors_are_every_cube_color_that_suits_a_folder() {
        let mut expected: Vec<u8> = Vec::new();
        for (red, green, blue) in
            (0..6).flat_map(|r| (0..6).flat_map(move |g| (0..6).map(move |b| (r, g, b))))
        {
            let rgb = [red, green, blue]
                .map(|level| u8::try_from(CUBE_LEVELS[level]).expect("a level fits"));
            let [r, g, b] = rgb.map(f64::from);
            let chroma = r.max(g).max(b) - r.min(g).min(b);
            let hue = (3.0_f64.sqrt() * (g - b))
                .atan2(2.0 * r - g - b)
                .to_degrees()
                .rem_euclid(360.0);
            let readable = contrast(rgb, [255; 3]) >= 3.0 && contrast(rgb, [0; 3]) >= 3.0;
            if chroma >= 80.0 && (170.0..=320.0).contains(&hue) && readable {
                expected.push(
                    u8::try_from(16 + 36 * red + 6 * green + blue).expect("a cube index fits"),
                );
            }
        }
        let mut palette: Vec<u8> = Depth::Indexed
            .slots(usize::MAX)
            .into_iter()
            .map(|color| match color {
                Color::Indexed(index) => index,
                _ => unreachable!("256 colors give indexed colors"),
            })
            .collect();
        palette.sort_unstable();
        assert_eq!(palette, expected);
    }

    #[test]
    fn folder_colors_read_on_a_white_and_on_a_black_background() {
        for depth in [Depth::Indexed, Depth::TrueColor] {
            for color in depth.slots(usize::MAX) {
                let rgb = match color {
                    Color::Rgb(rgb) => rgb,
                    Color::Indexed(index) => {
                        let at = usize::from(index - 16);
                        [at / 36, at / 6 % 6, at % 6]
                            .map(|level| u8::try_from(CUBE_LEVELS[level]).expect("a level fits"))
                    }
                    _ => unreachable!("only these two are for a folder at these depths"),
                };
                assert!(contrast(rgb, [255; 3]) >= 3.0, "{rgb:?} on white");
                assert!(contrast(rgb, [0; 3]) >= 3.0, "{rgb:?} on black");
            }
        }
    }

    #[test]
    fn the_same_folders_get_the_same_colors() {
        let names = names("", &["freshrss", "kanidm", "sso", "voice-channel"]);
        let mut reversed = names.clone();
        reversed.reverse();
        for depth in DEPTHS {
            assert_eq!(colors(depth, &names), colors(depth, &reversed));
        }
    }

    #[test]
    fn a_name_is_painted_up_to_its_last_slash() {
        let names = ["a/b/c".to_owned()];
        let folders = Palette(Some(Depth::Basic)).folders(names.iter().map(String::as_str));
        let painted = folders.name("a/b/c").to_string();
        assert_eq!(painted, format!("\x1b[{}ma/b/\x1b[0mc", BASIC[0]));

        let folders = Palette(Some(Depth::TrueColor)).folders(names.iter().map(String::as_str));
        let painted = folders.name("a/b/c").to_string();
        assert!(painted.starts_with("\x1b[38;2;"), "{painted:?}");
        assert!(painted.ends_with("a/b/\x1b[0mc"), "{painted:?}");
    }

    #[test]
    fn no_folder_or_no_palette_is_plain() {
        let names = ["password".to_owned(), "backup/ssh-key".to_owned()];
        let folders = Palette(Some(Depth::Basic)).folders(names.iter().map(String::as_str));
        assert_eq!(folders.name("password").to_string(), "password");

        let folders = Palette(None).folders(names.iter().map(String::as_str));
        assert_eq!(folders.name("backup/ssh-key").to_string(), "backup/ssh-key");
        assert_eq!(Palette(None).paint(Color::Green, "✓").to_string(), "✓");
    }

    #[test]
    fn terminal_depth_follows_colorterm_and_term() {
        assert_eq!(
            Depth::detect(Some("truecolor"), Some("xterm")),
            Depth::TrueColor
        );
        assert_eq!(Depth::detect(Some("24bit"), None), Depth::TrueColor);
        assert_eq!(Depth::detect(None, Some("xterm-256color")), Depth::Indexed);
        assert_eq!(Depth::detect(Some("yes"), Some("xterm")), Depth::Basic);
        assert_eq!(Depth::detect(None, None), Depth::Basic);
    }
}
