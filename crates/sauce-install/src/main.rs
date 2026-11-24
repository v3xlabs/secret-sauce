mod generations;
mod ids;
mod install;
mod key;

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    if let Err(error) = forbid_core_dumps() {
        eprintln!("sauce-install: cannot turn off core dumps: {error}");
        return ExitCode::FAILURE;
    }
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

/// Keeps the values out of a core dump, before the run reads any file.
///
/// The kernel checks the dumpable flag before it writes a core file or starts a core handler, so a process that is not dumpable gets no dump, whatever `fs.suid_dumpable` says.
/// The core size limit of zero is a second guard, which also makes systemd-coredump keep nothing.
fn forbid_core_dumps() -> io::Result<()> {
    // SAFETY: PR_SET_DUMPABLE takes integers only and touches no memory of this process.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads `none`, which lives through the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const none) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
