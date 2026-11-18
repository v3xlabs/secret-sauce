use std::{
    fmt, iter,
    iter::Peekable,
    str::{FromStr, Lines},
    time::{SystemTime, UNIX_EPOCH},
};

use super::Name;

/// A day of the Gregorian calendar, written `YYYY-MM-DD`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

#[derive(Debug, thiserror::Error)]
#[error("a date is a real day, written `YYYY-MM-DD`")]
pub struct DateError;

/// The facts of a secret, which a file holds encrypted in `facts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    /// The number of writes of a value.
    pub version: u32,
    /// The date of the last write of a value.
    pub set: Date,
    /// The date a provider issued the secret.
    pub issued: Option<Date>,
    /// The date the secret stops working.
    pub expires: Option<Date>,
    /// The SHA-256 digest of the declared generator.
    pub generator: Option<[u8; 32]>,
    /// The former names of the secret, oldest first.
    pub formerly: Vec<Name>,
    /// A former reader still knows the value.
    pub revoke: bool,
}

impl Date {
    /// The number of days from `self` to `later`, which is negative when `later` is earlier.
    #[must_use]
    pub fn days_until(self, later: Self) -> i64 {
        later.days() - self.days()
    }

    /// The days since 1970-01-01, with `days_from_civil` of Howard Hinnant.
    fn days(self) -> i64 {
        let month = i64::from(self.month);
        let year = i64::from(self.year) - i64::from(month <= 2);
        let (era, year_of_era) = (year.div_euclid(400), year.rem_euclid(400));
        let month_from_march = (month + 9) % 12;
        let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(self.day) - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }

    /// The current day in UTC.
    ///
    /// # Panics
    ///
    /// When the clock of the system is before 1970.
    #[must_use]
    pub fn today() -> Self {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is after 1970")
            .as_secs();
        // `civil_from_days` of Howard Hinnant, for the days since 1970-01-01.
        let days = seconds / 86_400 + 719_468;
        let (era, day_of_era) = (days / 146_097, days % 146_097);
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_from_march = (5 * day_of_year + 2) / 153;
        let month = if month_from_march < 10 {
            month_from_march + 3
        } else {
            month_from_march - 9
        };
        Self {
            year: u16::try_from(era * 400 + year_of_era + u64::from(month <= 2))
                .expect("the year fits in 16 bits"),
            month: u8::try_from(month).expect("a month is at most 12"),
            day: u8::try_from(day_of_year - (153 * month_from_march + 2) / 5 + 1)
                .expect("a day is at most 31"),
        }
    }

    fn parse(text: &str) -> Option<Self> {
        let (year, rest) = text.split_once('-')?;
        let (month, day) = rest.split_once('-')?;
        let date = Self {
            year: year.parse().ok()?,
            month: month.parse().ok()?,
            day: day.parse().ok()?,
        };
        let leap = date.year.is_multiple_of(4)
            && (!date.year.is_multiple_of(100) || date.year.is_multiple_of(400));
        let days = match date.month {
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            1..=12 => 31,
            _ => 0,
        };
        (text.len() == 10 && (1..=days).contains(&date.day) && date.to_string() == text)
            .then_some(date)
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl FromStr for Date {
    type Err = DateError;

    fn from_str(text: &str) -> Result<Self, DateError> {
        Self::parse(text).ok_or(DateError)
    }
}

/// Parses the text that `print` makes, and nothing else.
pub fn parse(text: &str) -> Option<Facts> {
    let mut lines = text.lines().peekable();
    let lines = &mut lines;
    // An optional fact that does not parse becomes `None`, and then the printed text differs.
    let facts = Facts {
        version: field(lines, "version: ")?.parse().ok()?,
        set: Date::parse(field(lines, "set: ")?)?,
        issued: field(lines, "issued: ").and_then(Date::parse),
        expires: field(lines, "expires: ").and_then(Date::parse),
        generator: field(lines, "generator: ").and_then(digest),
        formerly: iter::from_fn(|| field(lines, "formerly: "))
            .map(|name| name.parse().ok())
            .collect::<Option<_>>()?,
        revoke: field(lines, "revoke: true").is_some(),
    };
    (print(&facts) == text).then_some(facts)
}

pub fn print(facts: &Facts) -> String {
    let mut lines = vec![
        format!("version: {}", facts.version),
        format!("set: {}", facts.set),
    ];
    lines.extend(facts.issued.map(|date| format!("issued: {date}")));
    lines.extend(facts.expires.map(|date| format!("expires: {date}")));
    lines.extend(facts.generator.map(|digest| {
        let hex: String = digest
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0xf])
            .map(|nibble| char::from_digit(u32::from(nibble), 16).expect("a nibble is a hex digit"))
            .collect();
        format!("generator: {hex}")
    }));
    lines.extend(
        facts
            .formerly
            .iter()
            .map(|name| format!("formerly: {name}")),
    );
    lines.extend(facts.revoke.then(|| "revoke: true".to_owned()));
    lines.into_iter().map(|line| line + "\n").collect()
}

/// The length of the text of these facts when every fact is set and at its longest.
///
/// The step of `facts` follows this length, so it stays the same when an optional fact comes or goes.
pub fn longest(facts: &Facts) -> usize {
    print(&Facts {
        version: u32::MAX,
        set: facts.set,
        issued: Some(facts.set),
        expires: Some(facts.set),
        generator: Some([0; 32]),
        formerly: facts.formerly.clone(),
        revoke: true,
    })
    .len()
}

fn field<'a>(lines: &mut Peekable<Lines<'a>>, key: &str) -> Option<&'a str> {
    lines
        .next_if(|line| line.starts_with(key))
        .map(|line| &line[key.len()..])
}

fn digest(hex: &str) -> Option<[u8; 32]> {
    let mut digest = [0; 32];
    if hex.len() != 64 {
        return None;
    }
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(digest)
}
