use std::ffi::OsStr;
use std::process::ExitCode;

const USAGE: &str = "usage: sauce --version";

enum Command {
    Version,
}

impl Command {
    fn parse<S: AsRef<OsStr>>(args: impl IntoIterator<Item = S>) -> Option<Self> {
        let mut args = args.into_iter();
        match (args.next(), args.next()) {
            (Some(arg), None) if arg.as_ref() == "--version" => Some(Self::Version),
            _ => None,
        }
    }
}

fn main() -> ExitCode {
    match Command::parse(std::env::args_os().skip(1)) {
        Some(Command::Version) => {
            println!("sauce {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Command;

    #[test]
    fn version_flag_alone_is_the_version_command() {
        assert!(matches!(
            Command::parse(["--version"]),
            Some(Command::Version)
        ));
    }

    #[test]
    fn anything_else_is_rejected() {
        assert!(Command::parse(Vec::<&str>::new()).is_none());
        assert!(Command::parse(["nonsense"]).is_none());
        assert!(Command::parse(["--version", "extra"]).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn argument_that_is_not_unicode_is_rejected() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let bad = OsStr::from_bytes(b"\xff\xfe");
        assert!(Command::parse([bad]).is_none());
        assert!(Command::parse([OsStr::new("--version"), bad]).is_none());
    }
}
