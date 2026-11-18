mod clipboard;
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
    get::Out,
    identity::Admin,
    manifest::{Machines, ReadError},
    set::Dates,
    status::StatusError,
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
    /// Open the value of one secret in $EDITOR, and write it back when it changed.
    Edit {
        name: String,
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
    /// Show the readers of a secret, and its facts with the private key of an admin.
    Get {
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
    fn load(
        &self,
        evaluate: fn(&Path) -> Result<Machines, ReadError>,
    ) -> Result<(Machines, PathBuf), ReadError> {
        let flake = fs::canonicalize(&self.flake).map_err(|source| ReadError::File {
            path: self.flake.clone(),
            source,
        })?;
        let machines = match &self.manifest {
            Some(file) => Machines::read(file)?,
            None => evaluate(&flake)?,
        };
        Ok((machines, manifest::source_root(&flake).to_owned()))
    }
}

fn list(machines: &Machines, root: &Path, identity: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let secrets = machines.secrets()?;
    let admin = Admin::find_if_set(identity)?;
    let today = Date::today();
    let mut rows = vec![HEADER.map(String::from)];
    for (name, secret) in &secrets {
        let path = root.join(&secret.definition.file);
        let sign = match &admin {
            None if path.exists() => "✓",
            None => "✗",
            Some(admin) => match format::load(&path) {
                Ok(text)
                    if status::problems(name, &text, secret, Some(admin), today).is_empty() =>
                {
                    "✓"
                }
                Ok(_) => "⚠",
                Err(error) if error.kind() == io::ErrorKind::NotFound => "✗",
                Err(source) => return Err(StatusError::Read { path, source }.into()),
            },
        };
        rows.push([
            name.to_string(),
            secret.machines.join(","),
            secret.definition.made_by(),
            sign.to_owned(),
        ]);
    }

    let mut widths = [0; 3];
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }
    let mut text = String::new();
    for [name, machines, made_by, file] in &rows {
        let [name_width, machines_width, made_by_width] = widths;
        writeln!(
            text,
            "{name:name_width$}  {machines:machines_width$}  {made_by:made_by_width$}  {file}"
        )?;
    }
    io::stdout().write_all(text.as_bytes())?;
    if admin.is_none() {
        status::warn_unchecked();
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<(), Box<dyn Error>> {
    match command {
        Command::List { source, identity } => {
            let (machines, root) = source.load(manifest_cache::load)?;
            list(&machines, &root, identity.file.as_deref())
        }
        Command::Generate { source, identity } => {
            let (machines, root) = source.load(Machines::eval)?;
            Ok(generate::generate(
                &machines,
                &root,
                identity.file.as_deref(),
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
            let (machines, root) = source.load(manifest_cache::load)?;
            Ok(status::status(&machines, &root, identity.file.as_deref())?)
        }
        Command::Edit {
            name,
            source,
            identity,
        } => {
            let (machines, root) = source.load(Machines::eval)?;
            Ok(edit::edit(
                &machines,
                &root,
                &name,
                identity.file.as_deref(),
            )?)
        }
        Command::Search { text, source } => {
            let (machines, _) = source.load(manifest_cache::load)?;
            Ok(search::search(&machines, text.as_deref())?)
        }
        Command::Get {
            name,
            print,
            copy,
            source,
            identity,
        } => {
            let (machines, root) = source.load(manifest_cache::load)?;
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
}
