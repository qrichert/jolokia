pub enum Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub trait Cipher {
    /// Generate Cipher Key.
    fn generate_key() -> Vec<u8>;

    /// Encrypt slice of bytes.
    ///
    /// # Errors
    ///
    /// Errors if decryption fails. Decryption failures are opaque due
    /// to security concerns.
    fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt slice of bytes.
    ///
    /// # Errors
    ///
    /// Errors if decryption fails. Decryption failures are opaque due
    /// to security concerns.
    fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}
