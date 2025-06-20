pub mod cli;
pub mod ui;

use std::io::{Read, Write};

use secrecy::{ExposeSecret, zeroize::Zeroizing};

use jolokia::base64::{Base64Sink, Base64Source};
use jolokia::traits::{Base64Decode, Base64Encode, Cipher, GeneratedKey};

#[allow(clippy::unnecessary_wraps)] // Keep return type consistent.
pub fn keygen(cipher: &dyn Cipher, add_newline: bool) -> Result<(), String> {
    match cipher.generate_key() {
        GeneratedKey::Symmetric(key) => {
            let key = Zeroizing::new(key.expose_secret().base64_encode());
            print!("{}", key.as_str());
        }
        GeneratedKey::Asymmetric { private, public } => {
            let public = Zeroizing::new(public.expose_secret().base64_encode());
            let private = Zeroizing::new(private.expose_secret().base64_encode());
            eprintln!("Public:");
            println!("{}", public.as_str());
            eprintln!("Private:");
            print!("{}", private.as_str());
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
    key: &[u8],
    mut plaintext: R,
    mut output: W,
    from_raw_bytes: bool,
    add_newline: bool,
) -> Result<(), String> {
    let key = Zeroizing::new(decode_base64_key(key)?);

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
    key: &[u8],
    mut ciphertext: R,
    mut output: W,
    to_raw_bytes: bool,
) -> Result<(), String> {
    let key = Zeroizing::new(decode_base64_key(key)?);

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

fn decode_base64_key(key: &[u8]) -> Result<Vec<u8>, String> {
    match key.base64_decode() {
        Ok(key) => Ok(key),
        Err(reason) => Err(reason.to_string()),
    }
}
