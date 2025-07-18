use std::fmt;
use std::io::{self, Read, Write};

use secrecy::SecretSlice;

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
    Symmetric(SecretSlice<u8>),
    Asymmetric {
        public: SecretSlice<u8>,
        private: SecretSlice<u8>,
    },
    None,
}

impl GeneratedKey {
    /// Extract symmetric key.
    ///
    /// # Panics
    ///
    /// Panics if key is not a symmetric key.
    #[must_use]
    pub fn get_symmetric(&self) -> &SecretSlice<u8> {
        match self {
            Self::Symmetric(key) => key,
            _ => panic!("Key is not symmetric."),
        }
    }

    /// Extract asymmetric public key.
    ///
    /// # Panics
    ///
    /// Panics if key is not an asymmetric key.
    #[must_use]
    pub fn get_asymmetric_public(&self) -> &SecretSlice<u8> {
        match self {
            Self::Asymmetric { public, .. } => public,
            _ => panic!("Key is not asymmetric."),
        }
    }

    /// Extract asymmetric private key.
    ///
    /// # Panics
    ///
    /// Panics if key is not an asymmetric key.
    #[must_use]
    pub fn get_asymmetric_private(&self) -> &SecretSlice<u8> {
        match self {
            Self::Asymmetric { private, .. } => private,
            _ => panic!("Key is not asymmetric."),
        }
    }
}

pub trait Cipher {
    /// Generate cipher key.
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

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn generated_key_get_symmetric() {
        let key = GeneratedKey::Symmetric(SecretSlice::from(vec![0, 1, 2, 3]));

        assert_eq!(key.get_symmetric().expose_secret(), [0, 1, 2, 3]);
    }

    #[test]
    #[should_panic(expected = "Key is not symmetric.")]
    fn generated_key_get_symmetric_panics_if_wrong_variant() {
        let key = GeneratedKey::None;

        _ = key.get_symmetric();
    }

    #[test]
    fn generated_key_get_asymmetric_public() {
        let key = GeneratedKey::Asymmetric {
            public: SecretSlice::from(vec![0, 1, 2, 3]),
            private: SecretSlice::from(vec![4, 5, 6, 7]),
        };

        assert_eq!(key.get_asymmetric_public().expose_secret(), [0, 1, 2, 3]);
    }

    #[test]
    #[should_panic(expected = "Key is not asymmetric.")]
    fn generated_key_get_asymmetric_public_panics_if_wrong_variant() {
        let key = GeneratedKey::None;

        _ = key.get_asymmetric_public();
    }

    #[test]
    fn generated_key_get_asymmetric_private() {
        let key = GeneratedKey::Asymmetric {
            public: SecretSlice::from(vec![0, 1, 2, 3]),
            private: SecretSlice::from(vec![4, 5, 6, 7]),
        };

        assert_eq!(key.get_asymmetric_private().expose_secret(), [4, 5, 6, 7]);
    }

    #[test]
    #[should_panic(expected = "Key is not asymmetric.")]
    fn generated_key_get_asymmetric_private_panics_if_wrong_variant() {
        let key = GeneratedKey::None;

        _ = key.get_asymmetric_private();
    }
}
