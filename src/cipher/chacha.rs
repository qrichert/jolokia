use std::io::{Read, Write};

use aead::generic_array::GenericArray;
use aead::rand_core::{OsRng, RngCore};
use aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use super::traits;

// TODO: Include name and version in ciphertext, this will, in the
//  future let us change version and reroute to the corret impl.

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
        // 12-bytes (96-bits); unique per message.
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

    fn encrypt_stream<R: Read, W: Write>(
        key: &[u8],
        mut reader: R,
        mut writer: W,
    ) -> traits::Result<()> {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);

        // 7-bytes (56-bits); unique per message.
        //
        // As per the StreamBE32 docs:
        //
        //     [StreamBE32] uses a 32-bit big endian counter and 1-byte
        //     "last block" flag stored as the last 5-bytes of the AEAD
        //     nonce.
        //
        // ChaCha20-Poly1305 uses a 12-bytes nonce, so 12 - 5 = 7 bytes.
        let mut nonce_prefix = [0u8; 7];
        OsRng.fill_bytes(&mut nonce_prefix);
        let nonce_prefix = GenericArray::from_slice(&nonce_prefix);

        if let Err(reason) = writer.write_all(nonce_prefix) {
            return Err(traits::Error::Write(reason.to_string()));
        }

        let mut encryptor = EncryptorBE32::from_aead(cipher, nonce_prefix);

        let mut buffer = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buffer) {
            if n == 0 {
                break;
            }
            let chunk = encryptor
                .encrypt_next(&buffer[..n])
                .map_err(|_| traits::Error::Encrypt)?;

            // TODO: Append chunk-length prefix to make it more robust.

            if let Err(reason) = writer.write_all(&chunk) {
                return Err(traits::Error::Write(reason.to_string()));
            }
        }

        Ok(())
    }

    fn decrypt_stream<R: Read, W: Write>(
        key: &[u8],
        mut reader: R,
        mut writer: W,
    ) -> traits::Result<()> {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);

        let mut nonce_prefix = [0u8; 7];
        if let Err(reason) = reader.read_exact(&mut nonce_prefix) {
            return Err(traits::Error::Read(reason.to_string()));
        }
        let nonce_prefix = GenericArray::from_slice(&nonce_prefix);

        let mut decryptor = DecryptorBE32::from_aead(cipher, nonce_prefix);

        // Extra 16-bytes for the AEAD auth tag at the end of each chunk.
        let mut buffer = vec![0u8; 4096 + 16];
        loop {
            let n = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => n,
                Err(reason) => return Err(traits::Error::Read(reason.to_string())),
            };

            let chunk = decryptor
                .decrypt_next(&buffer[..n])
                .map_err(|_| traits::Error::Decrypt)?;

            if let Err(reason) = writer.write_all(&chunk) {
                return Err(traits::Error::Write(reason.to_string()));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::{Cipher, FromBase64};

    // Note: We can't really test encryption alone, because the result
    // is not deteministic (the nonce prevents identical plaintexts from
    // encrypting to the same ciphertext).

    #[test]
    fn chacha_encrypt_decrypt_roundtrip() {
        let key = "aZZfFANQlAtS5jxyyzHh0R8BWpHGDR2iqsBqROXzPkQ="
            .from_base64()
            .unwrap();
        let plaintext = b"hello, world!";

        let encrypted = Chacha20Poly1305::encrypt(&key, plaintext).unwrap();

        let decrypted = Chacha20Poly1305::decrypt(&key, &encrypted).unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);

        assert_eq!(decrypted, "hello, world!");
    }

    #[test]
    fn chacha_encrypt_decrypt_streaming_roundtrip_shorter_than_a_chunk() {
        let key = "aZZfFANQlAtS5jxyyzHh0R8BWpHGDR2iqsBqROXzPkQ="
            .from_base64()
            .unwrap();
        let plaintext = b"hello, world!";

        assert!(
            plaintext.len() < 4096 + 16,
            "{} >= {}",
            plaintext.len(),
            4096 + 16
        );

        let mut encrypted = Vec::new();
        Chacha20Poly1305::encrypt_stream(&key, Cursor::new(plaintext), &mut encrypted).unwrap();
        dbg!(&encrypted);

        assert!(encrypted.len() > 8);

        let mut decrypted = Vec::new();
        Chacha20Poly1305::decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted).unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);
        dbg!(&decrypted);

        assert_eq!(decrypted, "hello, world!");
    }

    #[test]
    fn chacha_encrypt_decrypt_streaming_roundtrip_same_length_as_a_chunk() {
        let key = "aZZfFANQlAtS5jxyyzHh0R8BWpHGDR2iqsBqROXzPkQ="
            .from_base64()
            .unwrap();
        let mut plaintext = b"hello, world!".repeat(316);
        plaintext.extend(b"abcd");

        assert_eq!(plaintext.len(), 4096 + 16);

        let mut encrypted = Vec::new();
        Chacha20Poly1305::encrypt_stream(&key, Cursor::new(plaintext), &mut encrypted).unwrap();
        dbg!(&encrypted);

        assert!(encrypted.len() > 8);

        let mut decrypted = Vec::new();
        Chacha20Poly1305::decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted).unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);
        dbg!(&decrypted);

        assert_eq!(decrypted, "hello, world!".repeat(316) + "abcd");
    }

    #[test]
    fn chacha_encrypt_decrypt_streaming_roundtrip_longer_than_a_chunk() {
        let key = "aZZfFANQlAtS5jxyyzHh0R8BWpHGDR2iqsBqROXzPkQ="
            .from_base64()
            .unwrap();
        let plaintext = b"hello, world!".repeat(320);

        assert!(
            plaintext.len() > 4096 + 16,
            "{} <= {}",
            plaintext.len(),
            4096 + 16
        );

        let mut encrypted = Vec::new();
        Chacha20Poly1305::encrypt_stream(&key, Cursor::new(plaintext), &mut encrypted).unwrap();
        dbg!(&encrypted);

        assert!(encrypted.len() > 8);

        let mut decrypted = Vec::new();
        Chacha20Poly1305::decrypt_stream(&key, Cursor::new(encrypted), &mut decrypted).unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);
        dbg!(&decrypted);

        assert_eq!(decrypted, "hello, world!".repeat(320));
    }
}
