//! ROT-n implementation.

use std::io::{Read, Write};

use crate::pipeline::traits::{self, Cipher, Error, GeneratedKey};

pub struct RotN;

impl Cipher for RotN {
    fn generate_key(&self) -> GeneratedKey {
        GeneratedKey::None
    }

    fn encrypt_stream(
        &self,
        key: &[u8],
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> traits::Result<()> {
        let key = extract_n_from_key_or_fail(key)?;

        let mut buffer = [0u8; 4096];
        // TODO: Handle errors like in chacha decrypt(), same for chacha encrypt().
        while let Ok(n) = reader.read(&mut buffer) {
            if n == 0 {
                break;
            }
            for c in &mut buffer[..n] {
                *c = rotate(*c, key);
            }
            writer
                .write_all(&buffer[..n])
                .map_err(|e| Error::Write(e.to_string()))?;
        }

        Ok(())
    }

    fn decrypt_stream(
        &self,
        key: &[u8],
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> traits::Result<()> {
        let key = extract_n_from_key_or_fail(key)?;

        let mut buffer = [0u8; 4096];
        // TODO: Handle errors like in chacha decrypt(), same for chacha encrypt().
        while let Ok(n) = reader.read(&mut buffer) {
            if n == 0 {
                break;
            }
            for c in &mut buffer[..n] {
                *c = rotate(*c, -key);
            }
            writer
                .write_all(&buffer[..n])
                .map_err(|e| Error::Write(e.to_string()))?;
        }

        Ok(())
    }
}

/// Extract a single-byte ROT-n key.
///
/// Contrary to robust algorithms, this cipher only expects a one-byte
/// key, which corresponds to the rotation amount `n`. The key must be
/// in the range `0..=255`, and only ASCII bytes are transformed.
///
/// # Errors
///
/// Errors if the key is not exactly 1 byte long.
fn extract_n_from_key_or_fail(key: &[u8]) -> traits::Result<i16> {
    if key.len() == 1 {
        Ok(i16::from(key[0]))
    } else {
        Err(Error::Key)
    }
}

#[inline]
fn rotate(character: u8, rot: i16) -> u8 {
    // `i16` can hold any number from `-u8` to `+u8`.
    const ALPHABET_SIZE: i16 = (b'z' - b'a' + 1) as i16;

    // This is sound because we only tranform ASCII bytes. Multi-byte
    // characters do not contain ASCII bytes in valid UTF-8.
    //
    // In UTF-8:
    // - All continuation bytes in UTF-8 multibyte sequences are in the
    //   range 0x80–0xBF.
    // - Start bytes are always ≥ 0xC2.
    // - So: No valid multibyte UTF-8 character contains an ASCII byte
    //   (0x00–0x7F) inside it.
    match character {
        c @ b'a'..=b'z' => {
            // c = 113 (q)              c = 100 (d)

            // 113 - 97 = 16            100 - 97 = 3
            let offset_from_a = i16::from(c - b'a');

            // 16 + (+13) = 29          3 + (-13) = -10
            let rotated = offset_from_a + rot;

            // 29 % 26 = 3              -10 % 26 = 16
            //
            // /!\ In Rust `%` is the remainder, not the modulus. For
            // the modulo use `rem_euclid()`, which is equivalent to
            // `((a % b) + b) % b`:
            //
            //     -1 % 26 = -1
            //     (-1).rem_euclid(26) = 25
            //     ((-1 % 26) + 26) % 26 = 25
            let wrapped = rotated.rem_euclid(ALPHABET_SIZE);

            // 3 + 97 = 100 (d)         16 + 97 = 113 (q)
            let shifted = wrapped + i16::from(b'a');

            u8::try_from(shifted).expect("bound to a-z")
        }
        c @ b'A'..=b'Z' => {
            let offset_from_a = i16::from(c - b'A');
            let rotated = offset_from_a + rot;
            let wrapped = rotated.rem_euclid(ALPHABET_SIZE);
            let shifted = wrapped + i16::from(b'A');
            u8::try_from(shifted).expect("bound to A-Z")
        }
        c => c,
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn rot_encrypt_with_n_is_correct() {
        let plaintext = b"attack at dawn";
        // Do not use `13` here, or ROT-13 symmetry may hide bugs.
        let encrypted = RotN.encrypt(&[5], plaintext).unwrap();
        assert_eq!(&encrypted, b"fyyfhp fy ifbs");
    }

    #[test]
    fn rot_decrypt_with_n_is_correct() {
        let ciphertext = b"fyyfhp fy ifbs";
        let decrypted = RotN.decrypt(&[5], ciphertext).unwrap();
        assert_eq!(&decrypted, b"attack at dawn");
    }

    #[test]
    fn rot_encrypt_does_not_break_multibyte_chars() {
        let plaintext = "hello ü, ñ, ü, 漢 world".as_bytes();

        let encrypted = RotN.encrypt(&[13], plaintext).unwrap();
        dbg!(&encrypted);

        assert_eq!(&encrypted, "uryyb ü, ñ, ü, 漢 jbeyq".as_bytes());
    }

    #[test]
    fn rot_decrypt_does_not_break_multibyte_chars() {
        let ciphertext = "uryyb ü, ñ, ü, 漢 jbeyq".as_bytes();

        let decrypted = RotN.decrypt(&[13], ciphertext).unwrap();
        dbg!(&decrypted);

        assert_eq!(&decrypted, "hello ü, ñ, ü, 漢 world".as_bytes());
    }

    #[test]
    fn rot_empty_input_is_noop() {
        let plaintext = b"";
        let encrypted = RotN.encrypt(&[13], plaintext).unwrap();
        assert_eq!(&encrypted, b"");
    }

    #[test]
    fn rot_ignores_non_ascii_letters() {
        let plaintext = b"1234!@#$%^&*()_+-=[]{}|;:',.<>?/";
        let encrypted = RotN.encrypt(&[7], plaintext).unwrap();
        assert_eq!(&encrypted, plaintext); // Should remain unchanged.
    }

    #[test]
    fn rot_preserves_mixed_case_and_nonletters() {
        let plaintext = b"Hello, World! 123";
        let encrypted = RotN.encrypt(&[5], plaintext).unwrap();
        assert_eq!(&encrypted, b"Mjqqt, Btwqi! 123");

        let decrypted = RotN.decrypt(&[5], &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn rot_round_trip_with_arbitrary_n() {
        let plaintext = b"Encrypt this message properly.";
        let n = 19;
        let encrypted = RotN.encrypt(&[n], plaintext).unwrap();
        let decrypted = RotN.decrypt(&[n], &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn rot_round_trip_all_possible_keys() {
        let plaintext = b"The quick brown fox jumps over the lazy dog!";

        for key in 0u8..=255 {
            let encrypted = RotN.encrypt(&[key], plaintext).unwrap();
            let decrypted = RotN.decrypt(&[key], &encrypted).unwrap();
            assert_eq!(
                &decrypted, plaintext,
                "Failed for key {key}: round-trip mismatch",
            );
        }
    }
}
