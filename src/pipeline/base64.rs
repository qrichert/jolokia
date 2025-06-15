//! Base64 encoding and decoding.

use std::io::{self, Read, Write};

use base64::engine;
use base64::prelude::BASE64_STANDARD_NO_PAD;
use base64::{read::DecoderReader, write::EncoderWriter};

use crate::pipeline::traits::{self, Base64Decode, Base64Encode, Error};

// TODO: Implement dedicated `encode_key()`/`decode_key()` methods.
//  As per the `GeneralPurpose` engine docs:
//      It is not constant-time, though, so it is vulnerable to timing
//      side-channel attacks. For loading cryptographic keys, etc, it is
//      suggested to use the forthcoming constant-time implementation.

impl Base64Encode for &[u8] {
    fn base64_encode(&self) -> String {
        let mut reader = io::Cursor::new(self);
        let mut encoded = Vec::new();
        let mut base64_sink = Base64Sink::new(&mut encoded);
        io::copy(&mut reader, &mut base64_sink).expect("this is all in memory");
        std::mem::drop(base64_sink); // Explicit drop needed to reborrow `&mut encoded`.
        String::from_utf8_lossy(&encoded).to_string()
    }
}

impl<const N: usize> Base64Encode for &[u8; N] {
    fn base64_encode(&self) -> String {
        self.as_slice().base64_encode()
    }
}

impl Base64Encode for Vec<u8> {
    fn base64_encode(&self) -> String {
        self.as_slice().base64_encode()
    }
}

impl Base64Decode for &[u8] {
    fn base64_decode(&self) -> traits::Result<Vec<u8>> {
        let mut reader = io::Cursor::new(self);
        let mut decoded = Vec::new();
        let mut base64_source = Base64Source::new(&mut reader);
        io::copy(&mut base64_source, &mut decoded)
            .map_err(|reason| Error::Base64Decode(reason.to_string()))?;
        Ok(decoded)
    }
}

impl Base64Decode for &str {
    fn base64_decode(&self) -> traits::Result<Vec<u8>> {
        self.as_bytes().base64_decode()
    }
}

impl Base64Decode for String {
    fn base64_decode(&self) -> traits::Result<Vec<u8>> {
        self.as_bytes().base64_decode()
    }
}

/// When written to, it encodes the bytes as base64.
pub struct Base64Sink<'a, W: Write> {
    encoder: EncoderWriter<'a, engine::GeneralPurpose, &'a mut W>,
}

impl<'a, W: Write> Base64Sink<'a, W> {
    pub fn new(writer: &'a mut W) -> Self {
        let encoder = EncoderWriter::new(writer, &BASE64_STANDARD_NO_PAD);
        Self { encoder }
    }
}

impl<W: Write> Write for Base64Sink<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.encoder.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.encoder.flush()
    }
}

struct NewlineTrimmer<'a, R: Read> {
    reader: &'a mut R,
    is_trimmed: bool,
}

impl<'a, R: Read> NewlineTrimmer<'a, R> {
    fn new(reader: &'a mut R) -> Self {
        Self {
            reader,
            is_trimmed: false,
        }
    }
}

impl<T: Read> Read for NewlineTrimmer<'_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut n = self.reader.read(buf)?;

        if self.is_trimmed {
            // Trimming is only allowed _once_ at the end.
            //
            // If we are here, it means we are reading _again_ after
            // trimming. This is an error in the input, unless:
            //
            // - We read 0 bytes (EOF).
            // - We read more `\n`s.
            //
            // Anything else is invalid.
            if buf[..n].iter().any(|&c| c != b'\n') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected data after final newline",
                ));
            }
        }

        // Trim trailing `\n`s and remember it.
        while n > 0 && buf[n - 1] == b'\n' {
            n -= 1;
            self.is_trimmed = true;
        }

        Ok(n)
    }
}

/// When read from, it decodes base64 as bytes.
pub struct Base64Source<'a, R: Read> {
    decoder: DecoderReader<'a, engine::GeneralPurpose, NewlineTrimmer<'a, R>>,
}

impl<'a, R: Read> Base64Source<'a, R> {
    pub fn new(reader: &'a mut R) -> Self {
        let newline_stripper = NewlineTrimmer::new(reader);
        let decoder = DecoderReader::new(newline_stripper, &BASE64_STANDARD_NO_PAD);
        Self { decoder }
    }
}

impl<R: Read> Read for Base64Source<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.decoder.read(buf)
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;

    const HELLO_WORLD_1000: &str = "aGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIWhlbGxvLCB3b3JsZCFoZWxsbywgd29ybGQhaGVsbG8sIHdvcmxkIQ";

    #[test]
    fn base64_encode_bytes() {
        let plaintext = b"hello, world!";

        let base64 = plaintext.base64_encode();

        assert_eq!(base64, "aGVsbG8sIHdvcmxkIQ");
    }

    #[test]
    fn base64_decode_string() {
        let base64 = "aGVsbG8sIHdvcmxkIQ";

        let plaintext = base64.base64_decode().unwrap();
        let plaintext = String::from_utf8_lossy(&plaintext).to_string();

        assert_eq!(plaintext, "hello, world!");
    }

    #[test]
    fn base64_encode_sink_short() {
        let plaintext = b"hello, world!";

        let mut writer = io::Cursor::new(plaintext);
        let mut encoded = Vec::new();
        let mut base64_sink = Base64Sink::new(&mut encoded);
        io::copy(&mut writer, &mut base64_sink).unwrap();
        std::mem::drop(base64_sink);

        let base64 = String::from_utf8_lossy(&encoded);

        assert_eq!(base64, "aGVsbG8sIHdvcmxkIQ");
    }

    #[test]
    fn base64_encode_sink_long() {
        let plaintext = b"hello, world!".repeat(1000);

        let mut writer = io::Cursor::new(plaintext);
        let mut encoded = Vec::new();
        let mut base64_sink = Base64Sink::new(&mut encoded);
        io::copy(&mut writer, &mut base64_sink).unwrap();
        std::mem::drop(base64_sink);

        let base64 = String::from_utf8_lossy(&encoded);

        assert_eq!(base64, HELLO_WORLD_1000);
    }

    #[test]
    fn base64_decode_source_short() {
        let base64 = "aGVsbG8sIHdvcmxkIQ";

        let mut reader = io::Cursor::new(base64);
        let mut decoded = Vec::new();
        let mut base64_source = Base64Source::new(&mut reader);
        io::copy(&mut base64_source, &mut decoded).unwrap();

        let plaintext = String::from_utf8_lossy(&decoded);

        assert_eq!(plaintext, "hello, world!");
    }

    #[test]
    fn base64_decode_source_long() {
        let base64 = HELLO_WORLD_1000;

        let mut reader = io::Cursor::new(base64);
        let mut decoded = Vec::new();
        let mut base64_source = Base64Source::new(&mut reader);
        io::copy(&mut base64_source, &mut decoded).unwrap();

        let plaintext = String::from_utf8_lossy(&decoded);

        assert_eq!(plaintext, "hello, world!".repeat(1000));
    }
}
