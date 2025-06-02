pub mod cli;
pub mod ui;

use std::io::{Read, Write};

use jolokia::base64::{Base64Sink, Base64Source};
use jolokia::cipher::Chacha20Poly1305;
use jolokia::compress::{CompressSource, ExtractSink};
use jolokia::traits::{Base64Decode, Base64Encode, Cipher};

/// Generic cipher key used by jolokia (this is _not secure_!).
pub const DEFAULT_KEY: &str = "edLKPT4jYaabmMwuKzgQwklMC9HxTYmhVY7qln4yrJM";

#[allow(clippy::unnecessary_wraps)] // Keep return type consistent.
pub fn genkey(add_newline: bool) -> Result<(), String> {
    let key = Chacha20Poly1305::generate_key().base64_encode();
    print!("{key}");
    if add_newline {
        println!();
    }
    Ok(())
}

pub fn encrypt(
    key: &str,
    mut plaintext: Box<dyn Read>,
    mut output: Box<dyn Write>,
    from_raw_bytes: bool,
    do_compress: bool,
    add_newline: bool,
) -> Result<(), String> {
    let key = match key.base64_decode() {
        Ok(key) => key,
        Err(reason) => return Err(reason.to_string()),
    };

    // Compress → Encrypt → Base64

    let mut source = if do_compress {
        Box::new(CompressSource::new(&mut plaintext)) as Box<dyn Read>
    } else {
        Box::new(&mut plaintext)
    };

    let mut sink = if from_raw_bytes {
        Box::new(&mut output)
    } else {
        Box::new(Base64Sink::new(&mut output)) as Box<dyn Write>
    };

    Chacha20Poly1305::encrypt_stream(&key, &mut source, &mut sink).map_err(|e| e.to_string())?;

    sink.flush().map_err(|e| e.to_string())?;

    if add_newline {
        // Explicit drop needed to reborrow `&mut output`.
        std::mem::drop(sink);
        _ = writeln!(output);
    }

    Ok(())
}

pub fn decrypt(
    key: &str,
    mut ciphertext: Box<dyn Read>,
    mut output: Box<dyn Write>,
    to_raw_bytes: bool,
    do_extract: bool,
) -> Result<(), String> {
    let key = match key.base64_decode() {
        Ok(key) => key,
        Err(reason) => return Err(reason.to_string()),
    };

    // Base64 → Decrypt → Extract

    let mut source = if to_raw_bytes {
        Box::new(&mut ciphertext)
    } else {
        Box::new(Base64Source::new(&mut ciphertext)) as Box<dyn Read>
    };

    let mut sink = if do_extract {
        Box::new(ExtractSink::new(&mut output)) as Box<dyn Write>
    } else {
        Box::new(&mut output)
    };

    Chacha20Poly1305::decrypt_stream(&key, &mut source, &mut sink).map_err(|e| e.to_string())?;

    sink.flush().map_err(|e| e.to_string())?;

    Ok(())
}
