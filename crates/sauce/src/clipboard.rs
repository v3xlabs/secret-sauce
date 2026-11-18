use std::{
    env,
    io::{self, Write as _},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::Duration,
};

use sauce::format::Value;

/// How long sauce offers a copied value: long enough to paste it, short enough that it is gone before the next screen share.
pub const CLEAR_SECONDS: &str = "30";

/// How long the copy program has to fail, such as for a display that does not answer, before sauce takes its silence as success.
const START: Duration = Duration::from_millis(500);

#[derive(Debug, thiserror::Error)]
pub enum CopyError {
    #[error("no clipboard is here, because WAYLAND_DISPLAY and DISPLAY are not set")]
    NoDisplay,
    #[error("XDG_RUNTIME_DIR is not set, and wl-copy keeps the value there, in memory")]
    NoRuntimeDir,
    #[error("{0} is not installed, and sauce copies with it on this display")]
    Missing(&'static str),
    #[error("{program} stopped with {status}, so the clipboard does not hold the value")]
    Failed {
        program: &'static str,
        status: ExitStatus,
    },
    #[error("cannot start {program}: {source}")]
    Start {
        program: &'static str,
        #[source]
        source: io::Error,
    },
}

/// Offers a value on the clipboard of the desktop for 30 seconds.
///
/// `wl-copy` and `xclip` run in the foreground under `timeout`, so the clipboard is theirs until `timeout` stops them.
/// The value goes through a pipe, never through an argument, and `wl-copy` keeps its copy of stdin in `$XDG_RUNTIME_DIR`, which is in memory.
/// A clipboard history of the desktop keeps a copy of its own, which this cannot clear.
pub fn copy(value: &Value) -> Result<(), CopyError> {
    let set = |name| env::var_os(name).filter(|value| !value.is_empty());
    let mut command = Command::new("timeout");
    let program = if set("WAYLAND_DISPLAY").is_some() {
        let runtime = set("XDG_RUNTIME_DIR").ok_or(CopyError::NoRuntimeDir)?;
        command
            .env("TMPDIR", runtime)
            .args([CLEAR_SECONDS, "wl-copy", "--foreground"]);
        "wl-copy"
    } else if set("DISPLAY").is_some() {
        command.args([CLEAR_SECONDS, "xclip", "-selection", "clipboard", "-quiet"]);
        "xclip"
    } else {
        return Err(CopyError::NoDisplay);
    };
    if !installed(program) {
        return Err(CopyError::Missing(program));
    }
    let start = |source| CopyError::Start { program, source };
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(start)?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(value.expose())
        .map_err(start)?;
    thread::sleep(START);
    match child.try_wait().map_err(start)? {
        Some(status) => Err(CopyError::Failed { program, status }),
        None => Ok(()),
    }
}

fn installed(program: &str) -> bool {
    env::var_os("PATH")
        .is_some_and(|path| env::split_paths(&path).any(|folder| folder.join(program).is_file()))
}
