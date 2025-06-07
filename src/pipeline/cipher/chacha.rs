//! ChaCha20-Poly1305 implementation.
//!
//! # Message Format
//!
//! All ciphertexts begin with a **5-byte header**:
//! 1. **Algorithm ID**: 4 ASCII bytes, `b"CH20"`.
//! 2. **Version**: 1 byte, currently `0x01`.
//!
//! After the header comes the **stream framing**:
//!
//! ```text
//! [ header (5) ]
//! [ 7-byte nonce prefix ]
//! [ chunk 1 length (4-byte BE) ][ chunk 1 4096-byte ciphertext + 16-byte tag ]
//! [ chunk 2 length (4-byte BE) ][ chunk 2 4096-byte (or less) ciphertext + 16-byte tag ]
//!   ⋮
//! [ 0x00000000 ]  ← zero-length marker = explicit EOF
//! ```
//!
//! - **Nonce prefix** (7 bytes) is generated once per stream;
//!   it forms the high bits of each AEAD nonce under the `StreamBE32`
//!   scheme.
//!
//! - Each **chunk** encrypts up to 4096 bytes of plaintext, producing
//!   ciphertext + 16 bytes of Poly1305 tag. The receiver reads exactly
//!   the advertised length, passes it to the stream decryptor, and
//!   writes the resulting plaintext.
//!
//! - The final zero-length chunk (`0x00 00 00 00`) signals a clean EOF.
//!   Any other early I/O error or truncated tag will be treated as
//!   corruption.

use std::io::{Read, Write};

use aead::generic_array::GenericArray;
use aead::rand_core::{OsRng, RngCore};
use aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::{ChaCha20Poly1305 as ChaCha20Poly1305_, Key};

use crate::pipeline::traits::{self, Cipher, Error, GeneratedKey};

// Contains algorithm name (4-bytes) and version (1-byte).
const HEADER: &[u8; 5] = b"CH20\x01";

pub struct ChaCha20Poly1305;

impl Cipher for ChaCha20Poly1305 {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self
    }

    /// Generate a 32-byte (256-bit) encryption key.
    fn generate_key(&self) -> GeneratedKey {
        let key = ChaCha20Poly1305_::generate_key(&mut OsRng);
        GeneratedKey::Symmetric(key.to_vec())
    }

    fn encrypt_stream(
        &self,
        key: &[u8],
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> traits::Result<()> {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305_::new(key);

        writer
            .write_all(HEADER)
            .map_err(|e| Error::Write(e.to_string()))?;

        // 7-bytes (56-bits); unique per message.
        //
        // As per the StreamBE32 docs:
        //
        //     [StreamBE32] uses a 32-bit big endian counter and 1-byte
        //     "last block" flag stored as the last 5-bytes of the AEAD
        //     nonce.
        //
        // ChaCha20-Poly1305 uses a 12-byte nonce, so 12 - 5 = 7 bytes.
        let mut nonce_prefix = [0u8; 7];
        OsRng.fill_bytes(&mut nonce_prefix);
        let nonce_prefix = GenericArray::from_slice(&nonce_prefix);

        writer
            .write_all(nonce_prefix)
            .map_err(|e| Error::Write(e.to_string()))?;

        let mut encryptor = EncryptorBE32::from_aead(cipher, nonce_prefix);

        let mut buffer = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buffer) {
            if n == 0 {
                break;
            }
            // Encrypt up to 4096 bytes of plaintext, yielding:
            //     4096-byte ciphertext + 16-byte AEAD auth tag
            let chunk = encryptor
                .encrypt_next(&buffer[..n])
                .map_err(|_| Error::Encrypt)?;

            // 4-bytes (32-bits) big-endian chunk length prefix.
            // Length-framing enables reading _exact_ chunks during
            // decryption, and so detect corruption or truncation.
            let chunk_len = u32::try_from(chunk.len())
                // `chunk.len()` sould be `4096 + 16 = 4112`.
                .map_err(|_| Error::Encrypt)?
                .to_be_bytes();
            writer
                .write_all(&chunk_len)
                .map_err(|e| Error::Write(e.to_string()))?;

            writer
                .write_all(&chunk)
                .map_err(|e| Error::Write(e.to_string()))?;
        }

        // Explicit EOF marker (4-bytes of 0s).
        // This can be interpreted as "next chunk has 0 length => EOF".
        writer
            .write_all(&0u32.to_be_bytes())
            .map_err(|e| Error::Write(e.to_string()))?;

        Ok(())
    }

    fn decrypt_stream(
        &self,
        key: &[u8],
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> traits::Result<()> {
        if usize::BITS < u32::BITS {
            return Err(Error::Platform(
                "< 32-bit platforms are not supported.".to_string(),
            ));
        }

        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305_::new(key);

        let mut header = [0u8; HEADER.len()];
        reader
            .read_exact(&mut header)
            .map_err(|e| Error::Read(e.to_string()))?;
        if &header != HEADER {
            return Err(Error::Algorithm);
        }

        let mut nonce_prefix = [0u8; 7];
        reader
            .read_exact(&mut nonce_prefix)
            .map_err(|e| Error::Read(e.to_string()))?;
        let nonce_prefix = GenericArray::from_slice(&nonce_prefix);

        let mut decryptor = DecryptorBE32::from_aead(cipher, nonce_prefix);

        // Extra 16-bytes for the AEAD auth tag at the end of each chunk.
        let mut chunk_buf: Vec<u8> = Vec::with_capacity(4096 + 16);
        loop {
            // 4-byte (32-bits) big-endian chunk length prefix.
            let mut chunk_len = [0u8; 4];
            reader
                .read_exact(&mut chunk_len)
                // Note that `ErrorKind::UnexpectedEof` _is_ in fact
                // unexpected. Real EOFs are marked by chunk length 0.
                .map_err(|e| Error::Read(e.to_string()))?;
            // Includes 16-byte suffix for the AEAD auth tag.
            let chunk_len = u32::from_be_bytes(chunk_len) as usize;

            // Explicit EOF.
            if chunk_len == 0 {
                break;
            }

            // Read the encrypted chunk.
            chunk_buf.resize(chunk_len, 0);
            reader
                .read_exact(&mut chunk_buf)
                .map_err(|e| Error::Read(e.to_string()))?;

            let chunk = decryptor
                .decrypt_next(&*chunk_buf)
                .map_err(|_| Error::Decrypt)?;

            writer
                .write_all(&chunk)
                .map_err(|e| Error::Write(e.to_string()))?;
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use std::io::Cursor;

    use super::*;

    use crate::pipeline::traits::Base64Decode;

    // Note: We can't really test encryption alone, because the result
    // is not deteministic (the nonce prevents identical plaintexts from
    // encrypting to the same ciphertext).

    #[test]
    fn chacha_encrypt_decrypt_roundtrip() {
        let key = "aZZfFANQlAtS5jxyyzHh0R8BWpHGDR2iqsBqROXzPkQ"
            .base64_decode()
            .unwrap();
        let plaintext = b"hello, world!";

        let encrypted = ChaCha20Poly1305::new().encrypt(&key, plaintext).unwrap();

        let decrypted = ChaCha20Poly1305::new().decrypt(&key, &encrypted).unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);

        assert_eq!(decrypted, "hello, world!");
    }

    #[test]
    fn chacha_encrypt_decrypt_streaming_roundtrip_shorter_than_a_chunk() {
        let key = "aZZfFANQlAtS5jxyyzHh0R8BWpHGDR2iqsBqROXzPkQ"
            .base64_decode()
            .unwrap();
        let plaintext = b"hello, world!";

        // Chunks are `4096 + 16 = 4112` bytes (message + auth).
        assert!(plaintext.len() < 4096, "{} >= 4096", plaintext.len());

        let mut encrypted = Vec::new();
        ChaCha20Poly1305::new()
            .encrypt_stream(&key, &mut Cursor::new(plaintext), &mut encrypted)
            .unwrap();
        dbg!(&encrypted);

        assert!(encrypted.len() > 8);

        let mut decrypted = Vec::new();
        ChaCha20Poly1305::new()
            .decrypt_stream(&key, &mut Cursor::new(encrypted), &mut decrypted)
            .unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);
        dbg!(&decrypted);

        assert_eq!(decrypted, "hello, world!");
    }

    #[test]
    fn chacha_encrypt_decrypt_streaming_roundtrip_same_length_as_a_chunk() {
        let key = "aZZfFANQlAtS5jxyyzHh0R8BWpHGDR2iqsBqROXzPkQ"
            .base64_decode()
            .unwrap();
        let mut plaintext = b"hello, world!".repeat(315);
        plaintext.extend(b"1");

        // Chunks are `4096 + 16 = 4112` bytes (message + auth).
        assert_eq!(plaintext.len(), 4096);

        let mut encrypted = Vec::new();
        ChaCha20Poly1305::new()
            .encrypt_stream(&key, &mut Cursor::new(plaintext), &mut encrypted)
            .unwrap();
        dbg!(&encrypted);

        assert!(encrypted.len() > 8);

        let mut decrypted = Vec::new();
        ChaCha20Poly1305::new()
            .decrypt_stream(&key, &mut Cursor::new(encrypted), &mut decrypted)
            .unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);
        dbg!(&decrypted);

        assert_eq!(decrypted, "hello, world!".repeat(315) + "1");
    }

    #[test]
    fn chacha_encrypt_decrypt_streaming_roundtrip_longer_than_a_chunk() {
        let key = "aZZfFANQlAtS5jxyyzHh0R8BWpHGDR2iqsBqROXzPkQ"
            .base64_decode()
            .unwrap();
        let plaintext = b"hello, world!".repeat(320);

        // Chunks are `4096 + 16 = 4112` bytes (message + auth).
        assert!(plaintext.len() > 4096, "{} <= 4096", plaintext.len());

        let mut encrypted = Vec::new();
        ChaCha20Poly1305::new()
            .encrypt_stream(&key, &mut Cursor::new(plaintext), &mut encrypted)
            .unwrap();
        dbg!(&encrypted);

        assert!(encrypted.len() > 8);

        let mut decrypted = Vec::new();
        ChaCha20Poly1305::new()
            .decrypt_stream(&key, &mut Cursor::new(encrypted), &mut decrypted)
            .unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);
        dbg!(&decrypted);

        assert_eq!(decrypted, "hello, world!".repeat(320));
    }
}
