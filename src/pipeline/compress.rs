//! Compression and extraction.

use std::io::{self, Read, Write};

use flate2::Compression;
use flate2::{read::ZlibEncoder, write::ZlibDecoder};

use crate::pipeline::traits::{self, Compress, Error, Extract};

// Contains algorithm name (4-bytes) and version (1-byte).
const HEADER: &[u8; 5] = b"ZLIB\x01";

impl Compress for &[u8] {
    fn compress(&self) -> Vec<u8> {
        let mut reader = io::Cursor::new(self);
        let mut compressed = Vec::new();
        let mut compress_source = CompressSource::new(&mut reader);
        io::copy(&mut compress_source, &mut compressed).expect("this is all in memory");
        compressed
    }
}

impl<const N: usize> Compress for &[u8; N] {
    fn compress(&self) -> Vec<u8> {
        self.as_slice().compress()
    }
}

impl Compress for Vec<u8> {
    fn compress(&self) -> Vec<u8> {
        self.as_slice().compress()
    }
}

impl Extract for &str {
    fn extract(&self) -> traits::Result<Vec<u8>> {
        let mut reader = io::Cursor::new(self);
        let mut extracted = Vec::new();
        let mut extract_sink = ExtractSink::new(&mut extracted);
        io::copy(&mut reader, &mut extract_sink)
            .map_err(|reason| Error::Extract(reason.to_string()))?;
        std::mem::drop(extract_sink); // Explicit drop needed to reuse `&mut extracted`.
        Ok(extracted)
    }
}

impl Extract for String {
    fn extract(&self) -> traits::Result<Vec<u8>> {
        self.as_str().extract()
    }
}

/// When read from, it reads uncompressed data and compresses it.
pub struct CompressSource<'a> {
    encoder: Box<dyn Read + 'a>,
}

impl<'a> CompressSource<'a> {
    pub fn new<R: Read>(reader: &'a mut R) -> Self {
        let header = io::Cursor::new(HEADER.as_slice());
        let encoder = ZlibEncoder::new(reader, Compression::best());
        let chained = Box::new(header.chain(encoder));
        Self { encoder: chained }
    }
}

impl Read for CompressSource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.encoder.read(buf)
    }
}

enum Decoder<'a, W: Write> {
    Init(ZlibDecoder<&'a mut W>),
    Uninit(Option<&'a mut W>),
}

/// When written to, it uncompresses data and writes it.
pub struct ExtractSink<'a, W: Write> {
    decoder: Decoder<'a, W>,
}

impl<'a, W: Write> ExtractSink<'a, W> {
    pub fn new(writer: &'a mut W) -> Self {
        Self {
            decoder: Decoder::Uninit(Some(writer)),
        }
    }
}

impl<W: Write> Write for ExtractSink<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.decoder {
            Decoder::Init(ref mut decoder) => decoder.write(buf),
            Decoder::Uninit(ref mut writer) => {
                debug_assert!(
                    buf.len() >= HEADER.len(),
                    "Cipher is not reading enough bytes."
                );

                let header = &buf[..HEADER.len()];
                if header != HEADER {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Incompatible compression algorithm.",
                    ));
                }

                // Take `writer` out of `Uninit` to put it in `Init`.
                let Some(writer) = writer.take() else {
                    // `Decoder` must be set to `Init` after we take the
                    // writer out. `Uninit` with `None` inside is a bug.
                    unreachable!("uninitialized decoder with no writer doesn't make sense");
                };

                // Init the decoder with the correct writer.
                let decoder = ZlibDecoder::new(writer);
                self.decoder = Decoder::Init(decoder);

                // Write the chunk without the header.
                let remaining_bytes = &buf[HEADER.len()..];
                if remaining_bytes.is_empty() {
                    // We consumed exactly `HEADER.len()` bytes. Tell
                    // the caller we used them all. If we return `0`,
                    // while formally correct, the caller thinks it's an
                    // error, as he sent in bytes but got nothing back.
                    Ok(HEADER.len())
                } else {
                    self.write(remaining_bytes) // It is `Init` now.
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.decoder {
            Decoder::Init(ref mut decoder) => decoder.flush(),
            Decoder::Uninit(ref mut writer) => {
                if let Some(writer) = writer.as_mut() {
                    writer.flush()
                } else {
                    unreachable!("uninitialized decoder with no writer doesn't make sense")
                }
            }
        }
    }
}

// TODO: tests
