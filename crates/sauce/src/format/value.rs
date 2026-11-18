use std::fmt;

use zeroize::Zeroizing;

/// The value of a secret.
///
/// `Debug` prints none of its bytes, and its memory is cleared when it is dropped.
pub struct Value(Zeroizing<Vec<u8>>);

impl Value {
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Value(..)")
    }
}

impl From<Vec<u8>> for Value {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}
