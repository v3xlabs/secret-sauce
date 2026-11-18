mod ids;
mod install;

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (Some(config), None) = (args.next(), args.next()) else {
        eprintln!("usage: sauce-install <config.json>");
        return ExitCode::FAILURE;
    };
    match install::run(&PathBuf::from(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sauce-install: {error}");
            ExitCode::FAILURE
        }
    }
}
