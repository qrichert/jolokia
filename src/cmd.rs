pub mod cli;
pub mod ui;

use std::io::Write;

use jolokia::{Chacha20Poly1305, Cipher, DecodeBase64, EncodeBase64};

/// Generic cipher key used by jolokia (this is _not secure_!).
pub const DEFAULT_KEY: &str = "edLKPT4jYaabmMwuKzgQwklMC9HxTYmhVY7qln4yrJM=";

#[allow(clippy::unnecessary_wraps)] // Keep return type consistent.
pub fn genkey() -> Result<(), String> {
    let key = Chacha20Poly1305::generate_key().encode_base64();
    println!("{key}");
    Ok(())
}

pub fn encrypt(key: &str, plaintext: &str) -> Result<(), String> {
    let key = match key.decode_base64() {
        Ok(key) => key,
        Err(reason) => return Err(reason.to_string()),
    };
    match Chacha20Poly1305::encrypt(&key, plaintext.as_bytes()) {
        Ok(ciphertext) => {
            let base64 = ciphertext.encode_base64();
            _ = writeln!(std::io::stdout(), "{base64}");
            Ok(())
        }
        Err(reason) => Err(reason.to_string()),
    }
}

pub fn decrypt(key: &str, ciphertext: &str) -> Result<(), String> {
    let key = match key.decode_base64() {
        Ok(key) => key,
        Err(reason) => return Err(reason.to_string()),
    };
    let ciphertext = match ciphertext.decode_base64() {
        Ok(ciphertext) => ciphertext,
        Err(reason) => return Err(reason.to_string()),
    };
    match Chacha20Poly1305::decrypt(&key, &ciphertext) {
        Ok(plaintext) => {
            let plaintext = String::from_utf8_lossy(&plaintext);
            _ = writeln!(std::io::stdout(), "{plaintext}");
            Ok(())
        }
        Err(reason) => Err(reason.to_string()),
    }
}
