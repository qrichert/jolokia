//! Hybrid Public Key Encryption (HPKE) implementation.
//!
//! Ciphersuite: HPKE-Base-X25519-HKDF-SHA256-ChaCha20Poly1305.
//!
//! - **X25519**: Key Encapsulation Mechanism (KEM). Performs ephemeral-
//!   static Diffie-Hellman to establish a shared secret between sender
//!   and recipient.
//! - **HKDF-SHA256**: Key Derivation Function (KDF). Expands the shared
//!   secret into cryptographic keys.
//! - **ChaCha20-Poly1305**: Authenticated Encryption with Associated
//!   Data (AEAD). Encrypts the actual message data in authenticated
//!   chunks.
//!
//! # Message Format
//!
//! All ciphertexts begin with a **5-byte header**:
//! 1. **Algorithm ID**: 4 ASCII bytes, `b"HPKE"`.
//! 2. **Version**: 1 byte, currently `0x01`.
//!
//! After the header:
//!
//! ```text
//! [ header (5) ]
//! [ encapsulated public key length (2-byte BE) ]
//! [ encapsulated public key (variable) ]
//! [ chacha encrypted payload ]
//! ```
//!
//! - The **encapsulated public key** is produced during encryption and
//!   required for decryption. Its length is encoded as a 2-byte
//!   big-endian integer.
//!
//! - The actual **payload** is encrypted by the [`ChaCha20-Poly1305`]
//!   stream implementation. See its documentation for details on
//!   chunking, nonce structure, and framing.
//!
//! - The derived symmetric key is unique per encryption via a fresh
//!   ephemeral keypair, providing forward secrecy. Only the
//!   encapsulated key and ciphertext are sent.
//!
//! - Decryption requires the recipient's X25519 private key and the
//!   encapsulated key to derive the shared symmetric key.
//!
//! - Any header or encapsulated key mismatch results in immediate
//!   failure.

use std::io::{Read, Write};

use hpke::aead::ChaCha20Poly1305 as ChaCha20Poly1305_;
use hpke::kdf::HkdfSha256;
use hpke::kem::{Kem, X25519HkdfSha256};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use rand::{SeedableRng, rngs::StdRng};
use secrecy::{SecretSlice, zeroize::Zeroizing};

use crate::cipher::ChaCha20Poly1305;
use crate::traits::{self, Cipher, Error, GeneratedKey};

// Contains algorithm name (4-bytes) and version (1-byte).
const HEADER: &[u8; 5] = b"HPKE\x01";

// Used to bind the derived keys to a specific application context or
// protocol version. It's the same idea as `HEADER` but used by HPKE
// internally.
const INFO: &[u8] = b"jolokia-hpke-stream-v1";
const EXPORT_LABEL: &[u8] = b"stream";

pub struct Hpke;

impl Cipher for Hpke {
    /// Generate an X25519 32-byte (256-bit) keypair.
    fn generate_key(&self) -> GeneratedKey {
        let mut csprng = StdRng::from_os_rng();
        let (sk, pk) = <X25519HkdfSha256 as Kem>::gen_keypair(&mut csprng);
        GeneratedKey::Asymmetric {
            public: SecretSlice::from(pk.to_bytes().to_vec()),
            private: SecretSlice::from(sk.to_bytes().to_vec()),
        }
    }

    fn encrypt_stream(
        &self,
        public_key: &[u8],
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> traits::Result<()> {
        // Recipient's public key.
        let public_key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(public_key)
            .map_err(|_| Error::Encrypt)?;

        // Generate an ephemeral keypair.
        //
        // Note: The private key is internal (`encryption_context`) and
        // will be used to derive a symmetric key on our (the encryptor)
        // side. The public key will be sent along and be used by the
        // recipient (the decryptor) to derive the same symmetric key
        // on his side.
        //
        // Why ephemeral? Forward secrecy. If the recipient's private
        // key ever gets compromised, passed and future messages will
        // still be safe because the derived symmetric key will be
        // _unique_ to that session/message. If not for the ephemeral
        // keypair, we would always use the _same_ symmetric key,
        // breaking forward secrecy.
        let mut csprng = StdRng::from_os_rng();
        let (encapsulated_public_key, encryption_context) =
            hpke::setup_sender::<ChaCha20Poly1305_, HkdfSha256, X25519HkdfSha256, _>(
                &OpModeS::Base,
                &public_key,
                INFO,
                &mut csprng,
            )
            .map_err(|_| Error::Encrypt)?;

        // Derive a 32-byte symmetric key. Will encrypt the _message_.
        //
        // Note: Contrary to "traditional" hybrid encryption, the
        // symmetric key is not encrypted and sent along, instead, it
        // is _derived_. During encryption, it is derived by combining
        // the recipient's public key, and the ephemeral private key
        // (dropped after use). During decryption, it is derived by
        // combining the recipient's private key, and the public key
        // (`encapsulated_public_key`) that we send along.
        let mut symmetric_key = Zeroizing::new([0u8; 32]);
        encryption_context
            .export(EXPORT_LABEL, symmetric_key.as_mut_slice())
            .map_err(|_| Error::Encrypt)?;

        writer
            .write_all(HEADER)
            .map_err(|e| Error::Write(e.to_string()))?;

        // 2-bytes (16-bits) big-endian encapsulated public key length.
        // length prefix for encapsulated_key
        let encapsulated_public_key = encapsulated_public_key.to_bytes();
        let encapsulated_public_key_len = u16::try_from(encapsulated_public_key.len())
            .map_err(|_| Error::Encrypt)?
            .to_be_bytes();
        writer
            .write_all(&encapsulated_public_key_len)
            .map_err(|e| Error::Write(e.to_string()))?;
        writer
            .write_all(&encapsulated_public_key)
            .map_err(|e| Error::Write(e.to_string()))?;

        // We've written the header and the encapsulated public key,
        // the only thing left to do is to append the encrypted payload.
        ChaCha20Poly1305.encrypt_stream(symmetric_key.as_ref(), reader, writer)?;

        Ok(())
    }

    fn decrypt_stream(
        &self,
        private_key: &[u8],
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> traits::Result<()> {
        if usize::BITS < u16::BITS {
            return Err(Error::Platform(
                "< 16-bit platforms are not supported.".to_string(),
            ));
        }

        // Recipient's private key.
        let private_key = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(private_key)
            .map_err(|_| Error::Decrypt)?;

        let mut header = [0u8; HEADER.len()];
        reader
            .read_exact(&mut header)
            .map_err(|e| Error::Read(e.to_string()))?;
        if &header != HEADER {
            return Err(Error::Algorithm);
        }

        // 2-bytes (16-bits) big-endian encapsulated public key length.
        let mut encapsulated_public_key_len = [0u8; 2];
        reader
            .read_exact(&mut encapsulated_public_key_len)
            .map_err(|e| Error::Read(e.to_string()))?;
        let encapsulated_public_key_len = u16::from_be_bytes(encapsulated_public_key_len) as usize;
        if encapsulated_public_key_len != 32 {
            return Err(Error::Decrypt);
        }

        let mut encapsulated_public_key = vec![0u8; encapsulated_public_key_len];
        reader
            .read_exact(&mut encapsulated_public_key)
            .map_err(|e| Error::Read(e.to_string()))?;
        let encapsulated_public_key =
            <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&encapsulated_public_key)
                .map_err(|_| Error::Decrypt)?;

        // Combine the encapsulated public key and the recipient's
        // secret key to derive the shared symmetric key.
        let decryption_context = hpke::setup_receiver::<
            ChaCha20Poly1305_,
            HkdfSha256,
            X25519HkdfSha256,
        >(
            &OpModeR::Base, &private_key, &encapsulated_public_key, INFO
        )
        .map_err(|_| Error::Decrypt)?;

        // Derive the 32-byte shared symmetric key.
        let mut symmetric_key = Zeroizing::new([0u8; 32]);
        decryption_context
            .export(EXPORT_LABEL, symmetric_key.as_mut_slice())
            .map_err(|_| Error::Decrypt)?;

        // We've got the symmetric key, decrypt the payload.
        ChaCha20Poly1305.decrypt_stream(symmetric_key.as_ref(), reader, writer)?;

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use std::io::Cursor;

    use super::*;

    use crate::traits::Base64Decode;

    // Note: We can't really test encryption alone, because the result
    // is not deteministic (the nonce prevents identical plaintexts from
    // encrypting to the same ciphertext).

    #[test]
    fn hpke_encrypt_decrypt_roundtrip() {
        let public_key = "lNLRjAfH2i8QfgEBmkwb9DyigB6mFae94FYCx46qij0"
            .base64_decode()
            .unwrap();
        let private_key = "caEdcM9zySxJCc+HBD7QzzpJwBVWm2BcGyBMoGETi+g"
            .base64_decode()
            .unwrap();
        let plaintext = b"hello, world!";

        let encrypted = Hpke.encrypt(&public_key, plaintext).unwrap();

        let decrypted = Hpke.decrypt(&private_key, &encrypted).unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);

        assert_eq!(decrypted, "hello, world!");
    }

    #[test]
    fn hpke_encrypt_decrypt_streaming_roundtrip_shorter_than_a_chunk() {
        let public_key = "lNLRjAfH2i8QfgEBmkwb9DyigB6mFae94FYCx46qij0"
            .base64_decode()
            .unwrap();
        let private_key = "caEdcM9zySxJCc+HBD7QzzpJwBVWm2BcGyBMoGETi+g"
            .base64_decode()
            .unwrap();
        let plaintext = b"hello, world!";

        // Chunks are `4096 + 16 = 4112` bytes (message + auth).
        assert!(plaintext.len() < 4096, "{} >= 4096", plaintext.len());

        let mut encrypted = Vec::new();
        Hpke.encrypt_stream(&public_key, &mut Cursor::new(plaintext), &mut encrypted)
            .unwrap();
        dbg!(&encrypted);

        assert!(encrypted.len() > 8);

        let mut decrypted = Vec::new();
        Hpke.decrypt_stream(&private_key, &mut Cursor::new(encrypted), &mut decrypted)
            .unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);
        dbg!(&decrypted);

        assert_eq!(decrypted, "hello, world!");
    }

    #[test]
    fn hpke_encrypt_decrypt_streaming_roundtrip_same_length_as_a_chunk() {
        let public_key = "lNLRjAfH2i8QfgEBmkwb9DyigB6mFae94FYCx46qij0"
            .base64_decode()
            .unwrap();
        let private_key = "caEdcM9zySxJCc+HBD7QzzpJwBVWm2BcGyBMoGETi+g"
            .base64_decode()
            .unwrap();
        let mut plaintext = b"hello, world!".repeat(315);
        plaintext.extend(b"1");

        // Chunks are `4096 + 16 = 4112` bytes (message + auth).
        assert_eq!(plaintext.len(), 4096);

        let mut encrypted = Vec::new();
        Hpke.encrypt_stream(&public_key, &mut Cursor::new(plaintext), &mut encrypted)
            .unwrap();
        dbg!(&encrypted);

        assert!(encrypted.len() > 8);

        let mut decrypted = Vec::new();
        Hpke.decrypt_stream(&private_key, &mut Cursor::new(encrypted), &mut decrypted)
            .unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);
        dbg!(&decrypted);

        assert_eq!(decrypted, "hello, world!".repeat(315) + "1");
    }

    #[test]
    fn hpke_encrypt_decrypt_streaming_roundtrip_longer_than_a_chunk() {
        let public_key = "lNLRjAfH2i8QfgEBmkwb9DyigB6mFae94FYCx46qij0"
            .base64_decode()
            .unwrap();
        let private_key = "caEdcM9zySxJCc+HBD7QzzpJwBVWm2BcGyBMoGETi+g"
            .base64_decode()
            .unwrap();
        let plaintext = b"hello, world!".repeat(320);

        // Chunks are `4096 + 16 = 4112` bytes (message + auth).
        assert!(plaintext.len() > 4096, "{} <= 4096", plaintext.len());

        let mut encrypted = Vec::new();
        Hpke.encrypt_stream(&public_key, &mut Cursor::new(plaintext), &mut encrypted)
            .unwrap();
        dbg!(&encrypted);

        assert!(encrypted.len() > 8);

        let mut decrypted = Vec::new();
        Hpke.decrypt_stream(&private_key, &mut Cursor::new(encrypted), &mut decrypted)
            .unwrap();
        let decrypted = String::from_utf8_lossy(&decrypted);
        dbg!(&decrypted);

        assert_eq!(decrypted, "hello, world!".repeat(320));
    }
}
