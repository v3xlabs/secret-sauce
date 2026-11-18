mod clipboard;
mod color;
mod edit;
mod generate;
mod get;
mod identity;
mod make;
mod manifest;
mod manifest_cache;
mod rotate;
mod search;
mod set;
mod status;

use std::{
    error::Error,
    fmt::Write as _,
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand};
use sauce::format::{self, Date};

use crate::{
    color::{Color, Palette},
    get::Out,
    identity::Admin,
    manifest::{Machines, ReadError, ReadManifests},
    set::Dates,
    status::{Evaluator, StatusError},
};

const HEADER: [&str; 4] = ["SECRET", "MACHINES", "MADE BY", "STATE"];

/// Keeps the secrets of NixOS machines in git.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List every secret that a machine of the flake declares, one row for each secret, and with the private key of an admin mark a secret that needs attention.
    List {
        #[command(flatten)]
        source: Source,
        #[command(flatten)]
        identity: Identity,
    },
    /// Create every secret that sauce can make and that has no file, and re-encrypt every file whose readers changed.
    Generate {
        /// Show what would change without writing files or using a private key.
        #[arg(long)]
        dry_run: bool,
        #[command(flatten)]
        source: Source,
        #[command(flatten)]
        identity: Identity,
    },
    /// Give a secret a value from stdin, or from a hidden prompt on a terminal.
    Set {
        name: String,
        /// The date the secret stops working, as YYYY-MM-DD.
        #[arg(long)]
        expires: Option<Date>,
        /// The date a provider issued the secret, as YYYY-MM-DD.
        #[arg(long)]
        issued: Option<Date>,
        #[command(flatten)]
        source: Source,
        #[command(flatten)]
        identity: Identity,
    },
    /// Make new values for the secrets that match a name or a pattern with `*`, and ask first for a pattern.
    Rotate {
        /// A name, or a pattern where `*` stands for any text, such as 'sso/*'.
        pattern: String,
        #[command(flatten)]
        source: Source,
        #[command(flatten)]
        identity: Identity,
    },
    /// List what needs attention, one row for each problem, and with the private key of an admin also expiry and revoke.
    Status {
        #[command(flatten)]
        source: Source,
        #[command(flatten)]
        identity: Identity,
    },
    /// Open a secret in $EDITOR. Confirm each secret when using a pattern.
    Edit {
        /// A name, or a quoted pattern where `*` stands for any text, such as 'sso/*'.
        pattern: String,
        #[command(flatten)]
        source: Source,
        #[command(flatten)]
        identity: Identity,
    },
    /// Pick a secret from a fuzzy list on the terminal and print its name, or print the names that hold TEXT with no terminal.
    Search {
        /// The text to start the search with.
        text: Option<String>,
        #[command(flatten)]
        source: Source,
    },
    /// Show facts about one secret. Use --copy or --print to request the value.
    Get {
        /// The exact name of the secret.
        name: String,
        /// Write the value to stdout, and nothing else.
        #[arg(long, conflicts_with = "copy")]
        print: bool,
        /// Put the value on the clipboard, and take it off again after 30 seconds.
        #[arg(long)]
        copy: bool,
        #[command(flatten)]
        source: Source,
        #[command(flatten)]
        identity: Identity,
    },
}

#[derive(Args)]
struct Identity {
    /// The age identity file of an admin.
    /// Without it, sauce reads `SOPS_AGE_KEY_FILE` and then `~/.config/sops/age/keys.txt`.
    #[arg(long = "identity", env = "SAUCE_IDENTITY")]
    file: Option<PathBuf>,
}

#[derive(Args)]
struct Source {
    /// The folder of the flake.
    #[arg(long, default_value = ".")]
    flake: PathBuf,
    /// Read the manifests from this JSON file in place of `nix eval`.
    #[arg(long)]
    manifest: Option<PathBuf>,
}

impl Source {
    /// The manifests, and the folder that the files of the secrets are relative to.
    fn load<T: From<Machines>>(
        &self,
        evaluate: fn(&Path) -> Result<T, ReadError>,
    ) -> Result<(T, PathBuf), ReadError> {
        let flake = fs::canonicalize(&self.flake).map_err(|source| ReadError::File {
            path: self.flake.clone(),
            source,
        })?;
        let machines = match &self.manifest {
            Some(file) => Machines::read(file)?.into(),
            None => evaluate(&flake)?,
        };
        Ok((machines, manifest::source_root(&flake).to_owned()))
    }

    fn load_read(&self) -> Result<(ReadManifests, PathBuf), ReadError> {
        let (manifests, root) = self.load(manifest_cache::load)?;
        if let Some(failures) = manifests.failures() {
            eprintln!("warning: incomplete manifest\n{failures}");
        }
        Ok((manifests, root))
    }
}

enum Mark {
    Present,
    Missing,
    Warning,
    NoReader,
}

fn list(
    machines: &ReadManifests,
    root: &Path,
    identity: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let secrets = machines.secrets()?;
    let admin = Admin::find_if_set(identity)?;
    let mut evaluator = Evaluator::new(admin.as_ref(), machines.failures().is_some());
    let mut rows = Vec::new();
    for (name, secret) in &secrets {
        let path = root.join(&secret.definition.file);
        let mark = match &admin {
            None if path.exists() => Mark::Present,
            None => Mark::Missing,
            Some(_) => match format::load(&path) {
                Ok(text) => {
                    let findings = evaluator.check(name, &text, secret);
                    if !findings.problems.is_empty() {
                        Mark::Warning
                    } else if findings.no_reader {
                        Mark::NoReader
                    } else {
                        Mark::Present
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => Mark::Missing,
                Err(source) => return Err(StatusError::Read { path, source }.into()),
            },
        };
        rows.push((
            [
                name.to_string(),
                secret.machines.join(","),
                secret.definition.made_by(),
            ],
            mark,
        ));
    }

    let mut widths = [0; 3];
    for (width, cell) in widths.iter_mut().zip(HEADER) {
        *width = cell.len();
    }
    for (cells, _) in &rows {
        for (width, cell) in widths.iter_mut().zip(cells) {
            *width = (*width).max(cell.len());
        }
    }
    let palette = Palette::stdout();
    let mut text = String::new();
    let [name_width, machines_width, made_by_width] = widths;
    let [name, machines, made_by, state] = HEADER;
    writeln!(
        text,
        "{name:name_width$}  {machines:machines_width$}  {made_by:made_by_width$}  {state}"
    )?;
    for ([name, machines, made_by], mark) in &rows {
        let (sign, color) = match mark {
            Mark::Present => ("✓", Color::Green),
            Mark::NoReader if evaluator.all_inaccessible() => ("✓", Color::Green),
            Mark::Warning | Mark::NoReader => ("⚠", Color::Yellow),
            Mark::Missing => ("✗", Color::Red),
        };
        writeln!(
            text,
            "{name:name_width$}  {machines:machines_width$}  {made_by:made_by_width$}  {}",
            palette.paint(color, sign)
        )?;
    }
    io::stdout().write_all(text.as_bytes())?;
    evaluator.finish();
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(exit) => exit,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn manifest_exit(machines: &ReadManifests) -> ExitCode {
    if machines.failures().is_some() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn run(command: Command) -> Result<ExitCode, Box<dyn Error>> {
    match command {
        Command::List { source, identity } => {
            let (machines, root) = source.load_read()?;
            list(&machines, &root, identity.file.as_deref())?;
            return Ok(manifest_exit(&machines));
        }
        Command::Generate {
            source,
            identity,
            dry_run,
        } => {
            let evaluate = if dry_run {
                Machines::eval_read_only
            } else {
                Machines::eval
            };
            let (machines, root) = source.load(evaluate)?;
            Ok(generate::generate(
                &machines,
                &root,
                identity.file.as_deref(),
                dry_run,
            )?)
        }
        Command::Set {
            name,
            expires,
            issued,
            source,
            identity,
        } => {
            let (machines, root) = source.load(Machines::eval)?;
            let dates = Dates { issued, expires };
            Ok(set::set(
                &machines,
                &root,
                &name,
                dates,
                identity.file.as_deref(),
            )?)
        }
        Command::Rotate {
            pattern,
            source,
            identity,
        } => {
            let (machines, root) = source.load(Machines::eval)?;
            Ok(rotate::rotate(
                &machines,
                &root,
                &pattern,
                identity.file.as_deref(),
            )?)
        }
        Command::Status { source, identity } => {
            let (machines, root) = source.load_read()?;
            status::status(&machines, &root, identity.file.as_deref())?;
            return Ok(manifest_exit(&machines));
        }
        Command::Edit {
            pattern,
            source,
            identity,
        } => {
            let (machines, root) = source.load(Machines::eval)?;
            Ok(edit::edit(
                &machines,
                &root,
                &pattern,
                identity.file.as_deref(),
            )?)
        }
        Command::Search { text, source } => {
            let (machines, _) = source.load_read()?;
            Ok(search::search(&machines, text.as_deref())?)
        }
        Command::Get {
            name,
            print,
            copy,
            source,
            identity,
        } => {
            let (machines, root) = source.load_read()?;
            let out = match (print, copy) {
                (true, _) => Out::Print,
                (false, true) => Out::Copy,
                (false, false) => Out::Facts,
            };
            Ok(get::get(
                &machines,
                &root,
                &name,
                out,
                identity.file.as_deref(),
            )?)
        }
    }
    .map(|()| ExitCode::SUCCESS)
}
