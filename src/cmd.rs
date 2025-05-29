pub mod cli;
pub mod ui;

use std::io::{Read, Write};

use jolokia::{Base64Decode, Base64Encode, Chacha20Poly1305, Cipher};

/// Generic cipher key used by jolokia (this is _not secure_!).
pub const DEFAULT_KEY: &str = "edLKPT4jYaabmMwuKzgQwklMC9HxTYmhVY7qln4yrJM=";

#[allow(clippy::unnecessary_wraps)] // Keep return type consistent.
pub fn genkey() -> Result<(), String> {
    let key = Chacha20Poly1305::generate_key().base64_encode();
    println!("{key}");
    Ok(())
}

pub fn encrypt(
    key: &str,
    mut plaintext: Box<dyn Read>,
    mut output: Box<dyn Write>,
) -> Result<(), String> {
    // TODO: Implement stream-reading. This is a temporary solution.
    let mut buf = String::new();
    _ = plaintext.read_to_string(&mut buf);
    // TODO: Find a way to trim whitespace for base64 (middleman reader?).
    // This is necessary for `stdin` because it adds a trailing newline.
    let plaintext = buf.trim_end_matches('\n').to_string();

    let key = match key.base64_decode() {
        Ok(key) => key,
        Err(reason) => return Err(reason.to_string()),
    };
    match Chacha20Poly1305::encrypt(&key, plaintext.as_bytes()) {
        Ok(ciphertext) => {
            let base64 = ciphertext.base64_encode();
            // FIXME: Only base64 should `ln`, not `--raw`.
            _ = writeln!(output, "{base64}");
            Ok(())
        }
        Err(reason) => Err(reason.to_string()),
    }
}

pub fn decrypt(
    key: &str,
    mut ciphertext: Box<dyn Read>,
    mut output: Box<dyn Write>,
) -> Result<(), String> {
    // TODO: Implement stream-reading. This is a temporary solution.
    let mut buf = String::new();
    _ = ciphertext.read_to_string(&mut buf);
    // This is necessary for `stdin` because it adds a trailing newline.
    // TODO: Find a way to trim whitespace for base64 (middleman reader?).
    let ciphertext = buf.trim_end_matches('\n').to_string();

    let key = match key.base64_decode() {
        Ok(key) => key,
        Err(reason) => return Err(reason.to_string()),
    };
    let ciphertext = match ciphertext.base64_decode() {
        Ok(ciphertext) => ciphertext,
        Err(reason) => return Err(reason.to_string()),
    };
    match Chacha20Poly1305::decrypt(&key, &ciphertext) {
        Ok(plaintext) => {
            let plaintext = String::from_utf8_lossy(&plaintext);
            _ = writeln!(output, "{plaintext}");
            Ok(())
        }
        Err(reason) => Err(reason.to_string()),
    }
}
