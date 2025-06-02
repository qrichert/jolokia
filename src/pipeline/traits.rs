use std::fmt;
use std::io::{self, Read, Write};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Encrypt,
    Decrypt,
    CipherAlgorithm,
    Base64Decode(String),
    Extract(String),
    Read(String),
    Write(String),
    Platform(String),
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
            Self::CipherAlgorithm => write!(f, "Incompatible cipher algorithm."),
            Self::Base64Decode(reason) => write!(f, "Could not decode base64: {reason}"),
            Self::Extract(reason) => write!(f, "Could not extract data: {reason}"),
            Self::Read(reason) => write!(f, "Could not read from input: {reason}"),
            Self::Write(reason) => write!(f, "Could not write to output: {reason}"),
            Self::Platform(reason) => write!(f, "{reason}"),
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
    /// Errors if encryption fails. Encryption failures are opaque due
    /// to security concerns.
    fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut encrypted = Vec::new();
        Self::encrypt_stream(key, &mut io::Cursor::new(plaintext), &mut encrypted)?;
        Ok(encrypted)
    }

    /// Decrypt ciphered bytes with key.
    ///
    /// # Errors
    ///
    /// Errors if decryption fails. Decryption failures are opaque due
    /// to security concerns.
    fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut decrypted = Vec::new();
        Self::decrypt_stream(key, &mut io::Cursor::new(ciphertext), &mut decrypted)?;
        Ok(decrypted)
    }

    /// Encrypt stream of plain bytes with key.
    ///
    /// # Errors
    ///
    /// Errors if encryption fails, or if read/write fails. Encryption
    /// failures are opaque due to security concerns.
    fn encrypt_stream<R: Read, W: Write>(key: &[u8], reader: &mut R, writer: &mut W) -> Result<()>;

    /// Encrypt stream of plain bytes with key.
    ///
    /// # Errors
    ///
    /// Errors if decryption fails, or if read/write fails. Decryption
    /// failures are opaque due to security concerns.
    fn decrypt_stream<R: Read, W: Write>(key: &[u8], reader: &mut R, writer: &mut W) -> Result<()>;
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

pub trait Compress {
    /// Compress `self` into an array of bytes.
    fn compress(&self) -> Vec<u8>;
}

pub trait Extract {
    /// Extract `self` into an array of bytes.
    ///
    /// # Errors
    ///
    /// Errors if `self` does not contain valid compressed data.
    fn extract(&self) -> Result<Vec<u8>>;
}
