//! The GPG keys of an admin, through the `gpg` program on PATH.
//!
//! A GPG reader is named by the fingerprint of a primary key or of a subkey, as in sops.
//! A primary fingerprint names its certificate, so any encryption key of that certificate opens the file.
//! A subkey fingerprint names that one key, so gpg encrypts to it alone and only it opens the file.

use std::{
    io::{self, Read as _, Write as _},
    mem,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use age::secrecy::ExposeSecret as _;
use age_core::format::FileKey;
use sauce::format::LARGEST_PGP_WRAP;
use zeroize::Zeroizing;

use crate::spinner::Step;

/// The bytes of a file key, which is all that the wrap of a GPG reader holds.
const FILE_KEY_BYTES: usize = 16;

/// The most bytes of stderr that sauce keeps from one run of gpg, for the text of an error.
/// gpg writes a few lines, and the rest is read and dropped so that gpg never waits on a full pipe.
const STDERR_BYTES: u64 = 64 * 1024;

/// The most bytes of the key listing of gpg that sauce reads.
/// A key takes a few hundred bytes in the listing, so a keyring with thousands of secret keys stays far below it.
const LISTING_BYTES: usize = 16 * 1024 * 1024;

/// How long one run of gpg may take, with a pinentry for the PIN of a card and a touch of the card in it.
/// A run that takes longer is stopped, so a stalled gpg, or a helper that holds a pipe open, cannot hang sauce.
const DEADLINE: Duration = Duration::from_secs(120);

/// How often sauce looks whether gpg has ended, while it waits for the pipes of gpg.
const POLL: Duration = Duration::from_millis(20);

/// The options of every run of gpg.
///
/// `--no-options` keeps the `gpg.conf` of the admin from changing a wrap, for example with `armor`, `encrypt-to`, `throw-keyids` or a `group` that adds a reader the header does not show.
/// gpg-agent keeps its own configuration, so pinentry and a card work as before.
const OPTIONS: [&str; 3] = ["--no-options", "--batch", "--quiet"];

/// The options of a run of gpg on a wrap: status lines alone on stderr, and the log, which can quote text from the wrap, nowhere.
const STATUS_ONLY: [&str; 4] = ["--log-file", "/dev/null", "--status-fd", "2"];

/// The variables that name or hold an age private key, for `sauce` or for sops, which gpg never needs.
///
/// gpg keeps the rest of the environment, such as `GNUPGHOME`, `HOME`, `PATH` and the variables of gpg-agent and pinentry.
const AGE_KEY_VARIABLES: [&str; 3] = ["SAUCE_IDENTITY", "SOPS_AGE_KEY", "SOPS_AGE_KEY_FILE"];

/// The key ID in an `ENC_TO` status line for a recipient that the wrap hides.
const HIDDEN_RECIPIENT: &str = "0000000000000000";

/// The status line that gpg writes when it has no public key for a key that it lists.
/// The text of the message beside it follows the locale, and this line does not.
const NO_PUBLIC_KEY: &str = "ERROR keylist.getkey 9";

/// The tag of a public-key encrypted session key packet.
const SESSION_KEY: u8 = 1;

/// The tag of a symmetrically encrypted and integrity protected data packet.
const ENCRYPTED: u8 = 18;

/// The tag of an OCB encrypted data packet, which gpg 2.4 writes for a key that announces OCB.
const ENCRYPTED_OCB: u8 = 20;

#[derive(Debug, thiserror::Error)]
pub enum GpgError {
    #[error("cannot run gpg: {0}")]
    Run(#[source] io::Error),
    #[error("gpg failed: {0}")]
    Failed(String),
    #[error("gpg wrote more than {0} bytes")]
    TooLong(usize),
    #[error(
        "the wrap is not one public-key encrypted session key packet and then one encrypted data packet, in at most {LARGEST_PGP_WRAP} bytes"
    )]
    Packets,
    #[error("gpg did not give a file key of {FILE_KEY_BYTES} bytes")]
    FileKey,
    #[error(
        "the wrap is not for one encryption key of {0}, with a key ID that no other secret key has; a subkey fingerprint names that subkey alone"
    )]
    Recipient(String),
    #[error(
        "gpg decrypted the wrap with a key other than {0}; a subkey fingerprint names that subkey alone, and a primary fingerprint names its certificate"
    )]
    DecryptionKey(String),
    #[error("gpg did not end within {} seconds", DEADLINE.as_secs())]
    Deadline,
    #[error("gpg has no public key for the key that it was asked for")]
    NoPublicKey,
    #[error("{0} is not in the keyring of gpg; import the public key with `gpg --import`")]
    NotInKeyring(String),
    #[error(
        "{fingerprint} is a subkey, so gpg encrypts to that subkey alone, and it refuses: {reason}; replace it with a subkey that gpg accepts, or, if its whole certificate may read, check that {primary} is its primary key and use that fingerprint"
    )]
    Subkey {
        fingerprint: String,
        primary: String,
        reason: String,
    },
    #[error(
        "gpg wrote a message for more than the one key of {0}, for example because its certificate names an additional decryption subkey, which sauce does not take"
    )]
    MoreRecipients(String),
}

/// The certificates of gpg that have a secret key, or the stub of a card.
pub struct SecretKeys(Vec<Cert>);

/// One certificate of a key listing of gpg.
struct Cert {
    /// The primary key, then each subkey.
    keys: Vec<CertKey>,
}

/// One key of a certificate.
struct CertKey {
    /// The long key ID, which an `ENC_TO` status line names.
    id: String,
    fingerprint: String,
    encrypts: bool,
}

impl Cert {
    /// The fingerprint of the primary key.
    fn primary(&self) -> &str {
        &self
            .keys
            .first()
            .expect("a certificate starts with its primary key")
            .fingerprint
    }

    fn holds(&self, fingerprint: &str) -> bool {
        self.keys.iter().any(|key| key.fingerprint == fingerprint)
    }
}

impl SecretKeys {
    /// Lists the secret keys of gpg, and none when gpg is not installed.
    pub fn find() -> Result<Self, GpgError> {
        let (listing, _) = match run(&["--with-colons", "--list-secret-keys"], &[], LISTING_BYTES) {
            Err(GpgError::Run(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Self(Vec::new()));
            }
            listing => listing?,
        };
        Ok(Self(certs(&String::from_utf8_lossy(&listing))))
    }

    /// Unwraps the file key with gpg when the fingerprint is of a key of one of these certificates, and gives `None` for any other key.
    pub fn unwrap(&self, fingerprint: &str, wrap: &[u8]) -> Option<Result<FileKey, GpgError>> {
        self.0
            .iter()
            .any(|cert| cert.holds(fingerprint))
            .then(|| self.decrypt(fingerprint, wrap))
    }

    /// Takes the file key out of a wrap whose one recipient is the encryption key of `fingerprint`, or an encryption key of its certificate when it is a primary key, and refuses it before any use of a private key otherwise.
    ///
    /// gpg decrypts with whichever secret key the wrap names, so a wrap that names another local key would make gpg use that key, or ask for its PIN.
    /// `--unwrap` takes off the encryption layer and parses nothing inside it, so packets in the encrypted data, such as a message for a passphrase, never reach gpg.
    fn decrypt(&self, fingerprint: &str, wrap: &[u8]) -> Result<FileKey, GpgError> {
        if !is_wrap(wrap) {
            return Err(GpgError::Packets);
        }
        let listed = [&STATUS_ONLY[..], &["--list-only", "--unwrap"]].concat();
        let (_, status) = run(&listed, wrap, 0)?;
        let recipient =
            recipient(&status).ok_or_else(|| GpgError::Recipient(fingerprint.to_owned()))?;
        let keys: Vec<_> = self
            .0
            .iter()
            .flat_map(|cert| cert.keys.iter().map(move |key| (cert, key)))
            .filter(|(_, key)| key.id == recipient)
            .collect();
        // gpg lists one key under each certificate that has it, for example as an additional decryption subkey, and that is one key.
        let one_key = keys
            .iter()
            .all(|(_, key)| key.fingerprint == keys[0].1.fingerprint);
        let named = keys.iter().any(|(cert, key)| {
            key.encrypts && (key.fingerprint == fingerprint || cert.primary() == fingerprint)
        });
        if !named || !one_key {
            return Err(GpgError::Recipient(fingerprint.to_owned()));
        }

        let unwrapped = [&STATUS_ONLY[..], &["--unwrap", "--output", "-"]].concat();
        let (output, status) = match run(&unwrapped, wrap, FILE_KEY_BYTES) {
            Err(GpgError::TooLong(_)) => return Err(GpgError::FileKey),
            run => run?,
        };
        if !status_lines(&status).any(|line| line == "DECRYPTION_OKAY") {
            return Err(GpgError::Failed(message(&status)));
        }
        // `DECRYPTION_KEY` names the fingerprint of the key that gpg used, then the fingerprint of its primary key.
        let used = status_lines(&status)
            .find_map(|line| line.strip_prefix("DECRYPTION_KEY "))
            .map(|rest| rest.split(' ').take(2).collect::<Vec<_>>())
            .unwrap_or_default();
        let vetted = keys[0].1.fingerprint.as_str();
        if used.first() != Some(&vetted) || !used.contains(&fingerprint) {
            return Err(GpgError::DecryptionKey(fingerprint.to_owned()));
        }
        if output.len() != FILE_KEY_BYTES {
            return Err(GpgError::FileKey);
        }
        Ok(FileKey::init_with_mut(|key| key.copy_from_slice(&output)))
    }
}

/// A run of gpg, which is killed and reaped when it is dropped before it ends.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        // gpg has ended or is stopped either way, so the errors are moot.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What the reader of a pipe of gpg sends back.
enum Pipe {
    Stdout(io::Result<Zeroizing<Vec<u8>>>),
    Stderr(io::Result<Vec<u8>>),
}

/// Wraps the file key for the GPG key of `fingerprint`, with the public key in the keyring of gpg.
///
/// The fingerprint in the Nix config is the trust anchor, so the web of trust of gpg has no say.
/// A primary key lets gpg choose an encryption key of its certificate.
/// A subkey is exact: `!` makes gpg encrypt to that key and to no other key of the certificate, and refuse it when it cannot encrypt.
/// `--no-literal` puts the 16 bytes of the file key in the encrypted data with no literal data packet around them, for `--unwrap` on a read.
pub fn wrap(fingerprint: &str, file_key: &FileKey) -> io::Result<Vec<u8>> {
    let listed = [
        "--status-fd",
        "2",
        "--with-colons",
        "--list-keys",
        fingerprint,
    ];
    let (listing, _) = run(&listed, &[], LISTING_BYTES).map_err(|error| match error {
        GpgError::NoPublicKey => io::Error::other(GpgError::NotInKeyring(fingerprint.to_owned())),
        error => io::Error::other(error),
    })?;
    let certs = certs(&String::from_utf8_lossy(&listing));
    let mut holders = certs.iter().filter(|cert| cert.holds(fingerprint));
    let Some(holder) = holders.next() else {
        return Err(io::Error::other(GpgError::NotInKeyring(
            fingerprint.to_owned(),
        )));
    };
    let subkey = certs.iter().all(|cert| cert.primary() != fingerprint);
    let primary = (subkey && holders.next().is_none()).then(|| holder.primary().to_owned());
    let recipient = if subkey {
        format!("{fingerprint}!")
    } else {
        fingerprint.to_owned()
    };
    let args = [
        "--trust-model",
        "always",
        "--compress-algo",
        "none",
        "--recipient",
        &recipient,
        "--no-literal",
        "--encrypt",
    ];
    let (message, _) = run(&args, file_key.expose_secret(), LARGEST_PGP_WRAP).map_err(|error| {
        io::Error::other(match (error, primary) {
            (GpgError::Failed(reason), Some(primary)) => GpgError::Subkey {
                fingerprint: fingerprint.to_owned(),
                primary,
                reason,
            },
            (error, _) => error,
        })
    })?;
    if !is_wrap(&message) {
        return Err(io::Error::other(if session_keys(&message) > 1 {
            GpgError::MoreRecipients(fingerprint.to_owned())
        } else {
            GpgError::Packets
        }));
    }
    Ok(message.to_vec())
}

/// Reads the certificates of a listing of `--with-colons`, where a `fpr` record follows the `pub`, `sec`, `sub` or `ssb` record of each key.
fn certs(listing: &str) -> Vec<Cert> {
    let mut certs: Vec<Cert> = Vec::new();
    let mut after_key = false;
    for line in listing.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let field = |index: usize| fields.get(index).copied().unwrap_or_default();
        let primary = matches!(field(0), "pub" | "sec");
        let key = primary || matches!(field(0), "sub" | "ssb");
        match field(0) {
            "pub" | "sec" | "sub" | "ssb" => {
                let key = CertKey {
                    id: field(4).to_owned(),
                    fingerprint: String::new(),
                    encrypts: field(11).contains('e'),
                };
                if primary {
                    certs.push(Cert { keys: vec![key] });
                } else if let Some(cert) = certs.last_mut() {
                    cert.keys.push(key);
                }
            }
            "fpr" if after_key => {
                if let Some(key) = certs.last_mut().and_then(|cert| cert.keys.last_mut()) {
                    field(9).clone_into(&mut key.fingerprint);
                }
            }
            _ => {}
        }
        after_key = key;
    }
    certs
}

/// The lines of a status channel of gpg, each without its prefix.
fn status_lines(status: &str) -> impl Iterator<Item = &str> {
    status
        .lines()
        .filter_map(|line| line.strip_prefix("[GNUPG:] "))
}

/// The key ID of the one recipient that the `ENC_TO` lines name, and `None` for none, more than one, or a hidden one.
fn recipient(status: &str) -> Option<&str> {
    let mut ids = status_lines(status)
        .filter_map(|line| line.strip_prefix("ENC_TO "))
        .map(|rest| rest.split(' ').next().unwrap_or_default());
    let id = ids.next()?;
    (ids.next().is_none() && !id.is_empty() && id != HIDDEN_RECIPIENT).then_some(id)
}

/// Runs gpg with `input` on stdin, and gives its stdout and its stderr.
///
/// sauce reads at most one byte more than `limit` from stdout, and stops gpg when it writes more or runs past [`DEADLINE`].
fn run(
    args: &[&str],
    input: &[u8],
    limit: usize,
) -> Result<(Zeroizing<Vec<u8>>, String), GpgError> {
    // A pinentry for the PIN of a card asks on the terminal, where the spinner would draw over it.
    let _hidden = Step::hide();
    let mut command = Command::new("gpg");
    for name in AGE_KEY_VARIABLES {
        command.env_remove(name);
    }
    let child = command
        .args(OPTIONS)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(GpgError::Run)?;
    let deadline = Instant::now() + DEADLINE;
    let mut running = Running(child);
    let child = &mut running.0;

    // Each pipe has a reader of its own, so that the deadline holds while a read waits.
    // A reader that still waits when sauce gives up is left behind, and its pipe closes when its writer ends or sauce exits.
    let (sender, receiver) = mpsc::channel();
    let mut stdout = child.stdout.take().expect("stdout of gpg is piped");
    let read_limit = u64::try_from(limit + 1).expect("a limit fits in u64");
    let stdout_sender = sender.clone();
    thread::spawn(move || {
        let mut output = Zeroizing::new(Vec::new());
        let read = (&mut stdout)
            .take(read_limit)
            .read_to_end(&mut output)
            .map(|_| output);
        // A send fails only when sauce gave up on gpg, which leaves nothing to tell.
        let _ = stdout_sender.send(Pipe::Stdout(read));
    });
    let mut stderr = child.stderr.take().expect("stderr of gpg is piped");
    thread::spawn(move || {
        let mut text = Vec::new();
        let read = (&mut stderr)
            .take(STDERR_BYTES)
            .read_to_end(&mut text)
            .and_then(|_| io::copy(&mut stderr, &mut io::sink()))
            .map(|_| text);
        let _ = sender.send(Pipe::Stderr(read));
    });
    // The input is a file key or a wrap, which fits in the buffer of a pipe, so this write cannot wait on gpg.
    let written = child
        .stdin
        .take()
        .expect("stdin of gpg is piped")
        .write_all(input);

    let (mut output, mut errors, mut status) = (None, None, None);
    let (output, stderr, status) = loop {
        if let (Some(output), Some(errors), Some(status)) = (&mut output, &mut errors, status) {
            break (mem::take(output), mem::take(errors), status);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(GpgError::Deadline);
        }
        match receiver.recv_timeout(left.min(POLL)) {
            Ok(Pipe::Stdout(read)) => {
                let read = read.map_err(GpgError::Run)?;
                if read.len() > limit {
                    return Err(GpgError::TooLong(limit));
                }
                output = Some(read);
            }
            Ok(Pipe::Stderr(read)) => errors = Some(read.map_err(GpgError::Run)?),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => thread::sleep(left.min(POLL)),
        }
        if status.is_none() {
            status = child.try_wait().map_err(GpgError::Run)?;
        }
    };
    let stderr = String::from_utf8_lossy(&stderr).into_owned();
    if !status.success() {
        return Err(if status_lines(&stderr).any(|line| line == NO_PUBLIC_KEY) {
            GpgError::NoPublicKey
        } else {
            GpgError::Failed(message(&stderr))
        });
    }
    written.map_err(GpgError::Run)?;
    Ok((output, stderr))
}

/// The lines of stderr that are not status lines, for a person, or the status lines when gpg wrote its log elsewhere.
fn message(stderr: &str) -> String {
    let lines = |status: bool| {
        stderr
            .lines()
            .filter(|line| line.starts_with("[GNUPG:] ") == status && !line.trim().is_empty())
            .collect::<Vec<_>>()
            .join("; ")
    };
    let text = lines(false);
    let text = if text.is_empty() { lines(true) } else { text };
    if text.is_empty() {
        String::from("no reason given")
    } else {
        text
    }
}

/// Whether a wrap is one public-key encrypted session key packet and then one encrypted data packet.
///
/// It reads the tags and the lengths of the packets only, and no packet body, so nothing else reaches gpg.
/// It refuses a message for a passphrase, which gpg would open after a prompt, and anything after the encrypted data.
fn is_wrap(message: &[u8]) -> bool {
    if message.len() > LARGEST_PGP_WRAP {
        return false;
    }
    let mut tags = [0; 2];
    let mut count = 0;
    let mut rest = message;
    while !rest.is_empty() {
        let Some((tag, length)) = packet(rest) else {
            return false;
        };
        let (Some(next), Some(slot)) = (rest.get(length..), tags.get_mut(count)) else {
            return false;
        };
        *slot = tag;
        count += 1;
        rest = next;
    }
    count == 2 && tags[0] == SESSION_KEY && matches!(tags[1], ENCRYPTED | ENCRYPTED_OCB)
}

/// How many public-key encrypted session key packets start the message, which is one packet for each recipient.
fn session_keys(message: &[u8]) -> usize {
    let mut count = 0;
    let mut rest = message;
    while let Some((SESSION_KEY, length)) = packet(rest) {
        let Some(next) = rest.get(length..) else {
            break;
        };
        count += 1;
        rest = next;
    }
    count
}

/// The tag of the first packet and its length with its header.
///
/// It takes a header in the new or the old format with a definite length, and refuses a partial or an indeterminate length.
fn packet(bytes: &[u8]) -> Option<(u8, usize)> {
    let (&first, rest) = bytes.split_first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let (tag, header, body) = if first & 0x40 == 0 {
        let size = match first & 0x03 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => return None,
        };
        let body = rest
            .get(..size)?
            .iter()
            .fold(0, |length, byte| (length << 8) | usize::from(*byte));
        ((first >> 2) & 0x0f, 1 + size, body)
    } else {
        let tag = first & 0x3f;
        match *rest.first()? {
            length @ 0..=191 => (tag, 2, usize::from(length)),
            length @ 192..=223 => (
                tag,
                3,
                (usize::from(length - 192) << 8) + usize::from(*rest.get(1)?) + 192,
            ),
            255 => {
                let length = u32::from_be_bytes(rest.get(1..5)?.try_into().ok()?);
                (tag, 6, usize::try_from(length).ok()?)
            }
            _ => return None,
        }
    };
    Some((tag, header.checked_add(body)?))
}

#[cfg(test)]
mod tests {
    use super::{certs, is_wrap, recipient, session_keys};

    /// A public-key encrypted session key packet and an encrypted data packet, both with a header of the new format.
    fn wrap() -> Vec<u8> {
        let mut message = vec![0xc1, 3, 0, 0, 0];
        message.extend([0xd2, 4, 0, 0, 0, 0]);
        message
    }

    #[test]
    fn wrap_for_a_public_key_passes() {
        assert!(is_wrap(&wrap()));
        // A session key packet with a header of the old format, as gpg writes it.
        assert!(is_wrap(&[0x84, 2, 0, 0, 0xd2, 1, 0]));
        // OCB encrypted data.
        assert!(is_wrap(&[0xc1, 1, 0, 0xd4, 1, 0]));
    }

    #[test]
    fn wrap_for_a_passphrase_is_refused() {
        // A symmetric-key encrypted session key packet, tag 3, then encrypted data.
        assert!(!is_wrap(&[0xc3, 1, 0, 0xd2, 1, 0]));
    }

    #[test]
    fn extra_recipients_are_counted_by_their_session_key_packets() {
        let mut two_readers = vec![0xc1, 1, 0];
        two_readers.extend(wrap());
        assert_eq!(session_keys(&two_readers), 2);
        assert_eq!(session_keys(&wrap()), 1);
        // One recipient and a packet of another kind is not an extra recipient.
        assert_eq!(session_keys(&[0xc1, 1, 0, 0xcb, 1, 0]), 1);
    }

    #[test]
    fn wrap_with_other_packets_is_refused() {
        let mut trailing = wrap();
        trailing.extend([0xcb, 1, 0]);
        assert!(!is_wrap(&trailing));

        let mut two_readers = vec![0xc1, 1, 0];
        two_readers.extend(wrap());
        assert!(!is_wrap(&two_readers));

        assert!(!is_wrap(&[0xc1, 1, 0]));
        assert!(!is_wrap(&[]));
    }

    #[test]
    fn wrap_with_a_length_past_its_end_is_refused() {
        let mut truncated = wrap();
        truncated.pop();
        assert!(!is_wrap(&truncated));
    }

    #[test]
    fn wrap_with_a_partial_or_indeterminate_length_is_refused() {
        assert!(!is_wrap(&[0xc1, 1, 0, 0xd2, 0xe0, 0]));
        assert!(!is_wrap(&[0x87, 0, 0xd2, 1, 0]));
    }

    #[test]
    fn wrap_larger_than_the_largest_is_refused() {
        let mut large = vec![0xc1, 255, 0, 0, 0x10, 0];
        large.resize(6 + 0x1000, 0);
        large.extend([0xd2, 1, 0]);
        assert!(!is_wrap(&large));
    }

    #[test]
    fn listing_gives_each_certificate_with_its_keys() {
        let listing = "\
sec:u:255:22:0BE836D1B324C6CE:1763485200:::u:::scESC:::+:::23::0:
fpr:::::::::2071113AFE99E29E0C390A980BE836D1B324C6CE:
grp:::::::::4A5D19D71F60103EC1749136F4D7EACF61CF83CC:
uid:u::::1763485200::0::throwaway <t@example.invalid>::::::::::0:
ssb:u:255:18:2377AADEF945377F:1763485200::::::e:::+:::23:
fpr:::::::::C776E9499E788192A91F6A8F0AA589284B30DBAB:
";
        let certs = certs(listing);

        assert_eq!(certs.len(), 1);
        assert_eq!(
            certs[0].primary(),
            "2071113AFE99E29E0C390A980BE836D1B324C6CE"
        );
        assert!(certs[0].holds("C776E9499E788192A91F6A8F0AA589284B30DBAB"));
        assert!(!certs[0].holds("0BE836D1B324C6CE"));
        let keys: Vec<_> = certs[0]
            .keys
            .iter()
            .map(|key| (key.id.as_str(), key.encrypts))
            .collect();
        assert_eq!(
            keys,
            [("0BE836D1B324C6CE", false), ("2377AADEF945377F", true)]
        );
    }

    #[test]
    fn recipient_is_one_named_key() {
        let one = "[GNUPG:] ENC_TO 2377AADEF945377F 18 0\n[GNUPG:] BEGIN_DECRYPTION\n";
        assert_eq!(recipient(one), Some("2377AADEF945377F"));

        let two = format!("{one}[GNUPG:] ENC_TO 3D219C9B3557D228 1 0\n");
        assert_eq!(recipient(&two), None);
        assert_eq!(recipient("[GNUPG:] ENC_TO 0000000000000000 18 0\n"), None);
        assert_eq!(recipient("[GNUPG:] BEGIN_DECRYPTION\n"), None);
    }
}
