use std::fmt;
use std::io::{self, Read, Write};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Encrypt,
    Decrypt,
    Algorithm,
    Base64Decode(String),
    Base64StreamEncode(String),
    Base64StreamDecode(String),
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
            Self::Algorithm => write!(f, "Incompatible algorithm."),
            Self::Base64Decode(reason) => write!(f, "Could not decode base64: {reason}"),
            Self::Base64StreamEncode(reason) => {
                write!(f, "Could not encode base64 stream: {reason}")
            }
            Self::Base64StreamDecode(reason) => {
                write!(f, "Could not decode base64 stream: {reason}")
            }
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

pub trait EncodeBase64 {
    /// Encode `self` in base64 string.
    #[must_use]
    fn encode_base64(&self) -> String;
}

pub trait DecodeBase64 {
    /// Decode base64-encoded `self` to bytes.
    ///
    /// # Errors
    ///
    /// Errors if `self` does not contain valid base64.
    fn decode_base64(&self) -> Result<Vec<u8>>;
}

pub trait EncodeBase64Stream {
    /// Encode `self` in base64 and stream as string to writer.
    ///
    /// # Errors
    ///
    /// Errors if writing fails.
    fn encode_base64_stream<W: Write>(&mut self, writer: &mut W) -> Result<()>;
}

pub trait DecodeBase64Stream {
    /// Decode `self` in base64 and stream as bytes to writer.
    ///
    /// # Errors
    ///
    /// Errors if `self` does not contain valid base64, or if writing
    /// fails.
    fn decode_base64_stream<W: Write>(&mut self, writer: &mut W) -> Result<()>;
}
