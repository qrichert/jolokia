pub mod cli;
pub mod ui;

use std::io::{Read, Write};

use jolokia::{Base64Decode, Base64Encode, Base64Sink, Base64Source, Chacha20Poly1305, Cipher};

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
    let key = match key.base64_decode() {
        Ok(key) => key,
        Err(reason) => return Err(reason.to_string()),
    };

    let mut base64_sink = Base64Sink::new(&mut output);

    Chacha20Poly1305::encrypt_stream(&key, &mut plaintext, &mut base64_sink)
        .map_err(|e| e.to_string())?;

    base64_sink.flush().map_err(|e| e.to_string())?;

    Ok(())
}

pub fn decrypt(
    key: &str,
    mut ciphertext: Box<dyn Read>,
    mut output: Box<dyn Write>,
) -> Result<(), String> {
    let key = match key.base64_decode() {
        Ok(key) => key,
        Err(reason) => return Err(reason.to_string()),
    };

    let mut base64_source = Base64Source::new(&mut ciphertext);

    Chacha20Poly1305::decrypt_stream(&key, &mut base64_source, &mut output)
        .map_err(|e| e.to_string())?;

    Ok(())
}
