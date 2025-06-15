use std::fmt;
use std::io::{self, Read, Write};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Encrypt,
    Decrypt,
    Algorithm,
    Key,
    Base64Decode(String),
    Read(String),
    Write(String),
    Platform(String),
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypt => write!(f, "Could not encrypt input."),
            Self::Decrypt => write!(
                f,
                "\
Could not decrypt input.
You are likely using the wrong key, or the data is corrupted."
            ),
            Self::Algorithm => write!(f, "Incompatible cipher algorithm."),
            Self::Key => write!(f, "The key is not compatible with the algoritm."),
            Self::Base64Decode(reason) => write!(f, "Could not decode base64: {reason}"),
            Self::Read(reason) => write!(f, "Could not read from input: {reason}"),
            Self::Write(reason) => write!(f, "Could not write to output: {reason}"),
            Self::Platform(reason) | Self::Other(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub enum GeneratedKey {
    Symmetric(Vec<u8>),
    Asymmetric { private: Vec<u8>, public: Vec<u8> },
    None,
}

impl GeneratedKey {
    // TODO: docstring
    /// # Panics
    /// ...
    #[must_use]
    pub fn get_symmetric(&self) -> &Vec<u8> {
        match self {
            Self::Symmetric(key) => key,
            _ => panic!("Key is not symmetric."),
        }
    }

    // TODO: docstring
    /// # Panics
    /// ...
    #[must_use]
    pub fn get_asymmetric_private(&self) -> &Vec<u8> {
        match self {
            Self::Asymmetric { private, .. } => private,
            _ => panic!("Key is not asymmetric."),
        }
    }

    // TODO: docstring
    /// # Panics
    /// ...
    #[must_use]
    pub fn get_asymmetric_public(&self) -> &Vec<u8> {
        match self {
            Self::Asymmetric { public, .. } => public,
            _ => panic!("Key is not asymmetric."),
        }
    }
}

pub trait Cipher {
    fn new() -> Self
    where
        Self: Sized;

    /// Generate cipher Key.
    #[must_use]
    fn generate_key(&self) -> GeneratedKey;

    /// Encrypt plain bytes with key.
    ///
    /// # Errors
    ///
    /// Errors if encryption fails. Encryption failures are opaque due
    /// to security concerns.
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut encrypted = Vec::new();
        self.encrypt_stream(key, &mut io::Cursor::new(plaintext), &mut encrypted)?;
        Ok(encrypted)
    }

    /// Decrypt ciphered bytes with key.
    ///
    /// # Errors
    ///
    /// Errors if decryption fails. Decryption failures are opaque due
    /// to security concerns.
    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut decrypted = Vec::new();
        self.decrypt_stream(key, &mut io::Cursor::new(ciphertext), &mut decrypted)?;
        Ok(decrypted)
    }

    /// Encrypt stream of plain bytes with key.
    ///
    /// # Errors
    ///
    /// Errors if encryption fails, or if read/write fails. Encryption
    /// failures are opaque due to security concerns.
    fn encrypt_stream(
        &self,
        key: &[u8],
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<()>;

    /// Encrypt stream of plain bytes with key.
    ///
    /// # Errors
    ///
    /// Errors if decryption fails, or if read/write fails. Decryption
    /// failures are opaque due to security concerns.
    fn decrypt_stream(
        &self,
        key: &[u8],
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<()>;
}

pub trait Base64Encode {
    /// Encode `self` in base64 string.
    #[must_use]
    fn base64_encode(&self) -> String;
}

pub trait Base64Decode {
    /// Decode base64-encoded `self` to bytes.
    ///
    /// # Errors
    ///
    /// Errors if `self` does not contain valid base64.
    fn base64_decode(&self) -> Result<Vec<u8>>;
}
