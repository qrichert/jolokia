use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Encrypt,
    Decrypt,
    Base64Decode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypt => write!(f, "Could not encrypt input."),
            Self::Decrypt => write!(f, "Could not decrypt input."),
            Self::Base64Decode(reason) => write!(f, "Could not decode base64: {reason}"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait Cipher {
    /// Generate cipher Key.
    #[must_use]
    fn generate_key() -> Vec<u8>;

    /// Encrypt plain bytes with key.
    ///
    /// # Errors
    ///
    /// Errors if decryption fails. Decryption failures are opaque due
    /// to security concerns.
    fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphered bytes with key.
    ///
    /// # Errors
    ///
    /// Errors if decryption fails. Decryption failures are opaque due
    /// to security concerns.
    fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

pub trait ToBase64 {
    /// Encode `self` in base64 string.
    #[must_use]
    fn to_base64(&self) -> String;
}

pub trait FromBase64 {
    /// Decode base64-encoded `self` to bytes.
    ///
    /// # Errors
    ///
    /// Errors if `self` does not contain valid base64.
    #[allow(clippy::wrong_self_convention)]
    fn from_base64(&self) -> Result<Vec<u8>>;
}
