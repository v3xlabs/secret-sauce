use base64::{Engine as _, engine::general_purpose::STANDARD};
use sauce::format::Date;
use x509_cert::{Certificate as Der, der::Decode, time::Time};

const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const END: &[u8] = b"-----END CERTIFICATE-----";

const SEQUENCE: u8 = 0x30;

/// A certificate that was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Certificate {
    /// The day of its `notAfter`.
    Ends(Date),
    /// A `notAfter` of `9999-12-31 23:59:59` as a `GeneralizedTime`, which RFC 5280 says is a certificate with no end.
    Never,
}

impl Certificate {
    /// The expiry date, and `None` for a certificate that never ends.
    pub fn date(self) -> Option<Date> {
        match self {
            Self::Ends(date) => Some(date),
            Self::Never => None,
        }
    }
}

/// What a value says about when it stops working, when it holds a certificate.
///
/// `None` is a value with no certificate in it, and so is a value that `x509-cert` cannot decode, also when bytes follow the certificate.
/// The first `CERTIFICATE` block counts, and the lines before it, such as another block, are skipped.
/// The block goes to `x509-cert` as DER from a slice, not as PEM from a reader, so a short input ends in an error and never waits for more.
pub fn expires(value: &[u8], bound: usize) -> Option<Certificate> {
    if value.len() > bound {
        return None;
    }
    let mut lines = value
        .split(|&byte| matches!(byte, b'\r' | b'\n'))
        .map(<[u8]>::trim_ascii);
    lines.find(|&line| line == BEGIN)?;
    let mut body = Vec::new();
    loop {
        let line = lines.next()?;
        if line == END {
            break;
        }
        body.extend_from_slice(line);
    }
    let der = STANDARD.decode(body).ok()?;
    if !outer_length_fits(&der) {
        return None;
    }
    let certificate = Der::from_der(&der).ok()?;
    let not_after = certificate.tbs_certificate.validity.not_after;
    let when = not_after.to_date_time();
    let never = matches!(not_after, Time::GeneralTime(_))
        && (when.year(), when.month(), when.day()) == (9999, 12, 31)
        && (when.hour(), when.minutes(), when.seconds()) == (23, 59, 59);
    if never {
        return Some(Certificate::Never);
    }
    format!("{:04}-{:02}-{:02}", when.year(), when.month(), when.day())
        .parse()
        .ok()
        .map(Certificate::Ends)
}

/// Whether the outer element of `der` ends exactly at its last byte.
/// The lengths of the elements inside it are left to `x509-cert`, and a nested length that claims more bytes than there are can make `der` 0.7 allocate that much before it fails, which is a known limit.
fn outer_length_fits(der: &[u8]) -> bool {
    let Some((&SEQUENCE, rest)) = der.split_first() else {
        return false;
    };
    let Some((&first, rest)) = rest.split_first() else {
        return false;
    };
    let length = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7F);
        let Some((bytes, _)) = rest
            .split_at_checked(count)
            .filter(|_| (1..=4).contains(&count))
        else {
            return false;
        };
        bytes
            .iter()
            .fold(0_usize, |length, &byte| length << 8 | usize::from(byte))
    };
    let header = if first < 0x80 {
        2
    } else {
        2 + usize::from(first & 0x7F)
    };
    header.checked_add(length) == Some(der.len())
}

#[cfg(test)]
mod tests {
    use super::expires;

    #[test]
    fn element_that_claims_more_bytes_than_it_has_is_no_certificate() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIT/////\n-----END CERTIFICATE-----\n";

        assert_eq!(expires(pem.as_bytes(), 4096), None);
    }

    #[test]
    fn inner_element_that_claims_two_gibibytes_is_no_certificate() {
        // The outer lengths fit the bytes, and an INTEGER inside claims 0x7FFFFFFF bytes.
        let pem = "-----BEGIN CERTIFICATE-----\nMAgwBgKEf////w==\n-----END CERTIFICATE-----\n";

        assert_eq!(expires(pem.as_bytes(), 4096), None);
    }

    #[test]
    fn text_that_is_no_certificate_gives_no_date() {
        for text in [
            &b""[..],
            b"token",
            b"-----BEGIN CERTIFICATE-----\n",
            b"-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----",
            &[0xFF, 0xFE],
        ] {
            assert_eq!(expires(text, 4096), None, "{text:?}");
        }
    }
}
