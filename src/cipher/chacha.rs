use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};

use super::traits;

pub struct Chacha20Poly1305;

impl traits::Cipher for Chacha20Poly1305 {
    /// Generate a 32-bytes (256-bit) encryption key.
    fn generate_key() -> Vec<u8> {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        key.to_vec()
    }

    fn encrypt(key: &[u8], plaintext: &[u8]) -> traits::Result<Vec<u8>> {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);
        // 96-bits (12 bytes); unique per message.
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let Ok(ciphertext) = cipher.encrypt(&nonce, plaintext) else {
            return Err(traits::Error::Encrypt);
        };

        // Prepend cipher text with nonce for retrieval during decryption.
        let mut output = nonce.to_vec();
        output.extend(ciphertext);

        Ok(output)
    }

    fn decrypt(key: &[u8], ciphertext: &[u8]) -> traits::Result<Vec<u8>> {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);

        let (nonce, ciphertext) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce);

        let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) else {
            return Err(traits::Error::Decrypt);
        };
        Ok(plaintext)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{Cipher, FromBase64};

    // Note: We can't really test encryption alone, because the result
    // is not deteministic.

    #[test]
    fn chacha_roundtrip() {
        let key = "aZZfFANQlAtS5jxyyzHh0R8BWpHGDR2iqsBqROXzPkQ="
            .from_base64()
            .unwrap();
        let plaintext = b"hello, world!";

        let ciphertext = Chacha20Poly1305::encrypt(&key, plaintext).unwrap();

        let decrypted = Chacha20Poly1305::decrypt(&key, &ciphertext).unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);

        assert_eq!(decrypted, "hello, world!");
    }
}
