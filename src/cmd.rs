pub mod cli;
pub mod ui;

use std::io::{Read, Write};

use jolokia::base64::{Base64Sink, Base64Source};
use jolokia::traits::{Base64Decode, Base64Encode, Cipher, GeneratedKey};

#[allow(clippy::unnecessary_wraps)] // Keep return type consistent.
pub fn genkey(cipher: &dyn Cipher, add_newline: bool) -> Result<(), String> {
    match cipher.generate_key() {
        GeneratedKey::Symmetric(key) => {
            print!("{}", key.base64_encode());
        }
        GeneratedKey::None => {
            return Err("The selected algorithm does not generate keys.".to_string());
        }
    }
    if add_newline {
        println!();
    }
    Ok(())
}

pub fn encrypt<R: Read, W: Write>(
    cipher: &dyn Cipher,
    key: &str,
    mut plaintext: R,
    mut output: W,
    from_raw_bytes: bool,
    add_newline: bool,
) -> Result<(), String> {
    let key = decode_base64_key(key)?;

    let mut sink: Box<dyn Write> = if from_raw_bytes {
        Box::new(&mut output)
    } else {
        Box::new(Base64Sink::new(&mut output))
    };

    cipher
        .encrypt_stream(&key, &mut plaintext, &mut sink)
        .map_err(|e| e.to_string())?;

    sink.flush().map_err(|e| e.to_string())?;

    if add_newline {
        // Explicit drop needed to reborrow `&mut output`.
        std::mem::drop(sink);
        _ = writeln!(output);
    }

    Ok(())
}

pub fn decrypt<R: Read, W: Write>(
    cipher: &dyn Cipher,
    key: &str,
    mut ciphertext: R,
    mut output: W,
    to_raw_bytes: bool,
) -> Result<(), String> {
    let key = decode_base64_key(key)?;

    let mut source: Box<dyn Read> = if to_raw_bytes {
        Box::new(&mut ciphertext)
    } else {
        Box::new(Base64Source::new(&mut ciphertext))
    };

    cipher
        .decrypt_stream(&key, &mut source, &mut output)
        .map_err(|e| e.to_string())?;

    Ok(())
}

fn decode_base64_key(key: &str) -> Result<Vec<u8>, String> {
    match key.base64_decode() {
        Ok(key) => Ok(key),
        Err(reason) => Err(reason.to_string()),
    }
}
