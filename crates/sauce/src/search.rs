use std::io::{self, IsTerminal as _};

use dialoguer::{FuzzySelect, theme::ColorfulTheme};

use crate::manifest::{Machines, RuleError};

/// The rows of the picker on screen at one time, so that a long list scrolls and leaves the command line in view.
const ROWS: usize = 15;

#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error("the picker failed: {0}")]
    Picker(#[from] dialoguer::Error),
    #[error("no secret was picked")]
    Cancelled,
    #[error("no secret matches {0}")]
    NoMatch(String),
}

/// Picks a secret on the terminal and prints its name, or prints every name that holds `text` with no terminal.
///
/// The picker draws on stderr, so `sauce get "$(sauce search)"` works.
pub fn search(machines: &Machines, text: Option<&str>) -> Result<(), SearchError> {
    let secrets = machines.secrets()?;
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
        let text = text.unwrap_or_default();
        let lower = text.to_lowercase();
        let mut found = false;
        for name in secrets.keys().filter(|name| name.as_str().contains(&lower)) {
            println!("{name}");
            found = true;
        }
        return if found {
            Ok(())
        } else {
            Err(SearchError::NoMatch(text.to_owned()))
        };
    }

    let rows: Vec<_> = secrets
        .values()
        .map(|secret| {
            [
                secret.machines.join(","),
                secret
                    .definition
                    .declaration()
                    .unwrap_or_else(|| String::from("sauce set")),
            ]
        })
        .collect();
    let name_width = secrets
        .keys()
        .map(|name| name.as_str().len())
        .max()
        .unwrap_or(0);
    let machines_width = rows
        .iter()
        .map(|[machines, _]| machines.len())
        .max()
        .unwrap_or(0);
    let items: Vec<_> = secrets
        .keys()
        .zip(&rows)
        .map(|(name, [machines, made_by])| {
            format!(
                "{:name_width$}  {machines:machines_width$}  {made_by}",
                name.as_str()
            )
        })
        .collect();
    if items.is_empty() {
        return Err(SearchError::NoMatch(text.unwrap_or_default().to_owned()));
    }
    let picked = FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Secret")
        .with_initial_text(text.unwrap_or_default())
        .items(&items)
        .default(0)
        .max_length(ROWS)
        .report(false)
        .interact_opt()?
        .ok_or(SearchError::Cancelled)?;
    let name = secrets
        .keys()
        .nth(picked)
        .expect("the picker returns an index of the items");
    println!("{name}");
    Ok(())
}
