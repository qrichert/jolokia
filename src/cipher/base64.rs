use base64::prelude::{BASE64_STANDARD, Engine as _};

use super::traits;

impl traits::EncodeBase64 for &[u8] {
    fn encode_base64(&self) -> String {
        BASE64_STANDARD.encode(self)
    }
}

impl<const N: usize> traits::EncodeBase64 for &[u8; N] {
    fn encode_base64(&self) -> String {
        self.as_slice().encode_base64()
    }
}

impl traits::EncodeBase64 for Vec<u8> {
    fn encode_base64(&self) -> String {
        self.as_slice().encode_base64()
    }
}

impl traits::DecodeBase64 for &str {
    fn decode_base64(&self) -> traits::Result<Vec<u8>> {
        match BASE64_STANDARD.decode(self) {
            Ok(bytes) => Ok(bytes),
            Err(reason) => Err(traits::Error::Base64Decode(reason.to_string())),
        }
    }
}

impl traits::DecodeBase64 for String {
    fn decode_base64(&self) -> traits::Result<Vec<u8>> {
        self.as_str().decode_base64()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{DecodeBase64, EncodeBase64};

    #[test]
    fn base64_encode_bytes() {
        let plaintext = b"hello, world!";

        let base64 = plaintext.encode_base64();

        assert_eq!(base64, "aGVsbG8sIHdvcmxkIQ==");
    }

    #[test]
    fn base64_decode_string() {
        let base64 = "aGVsbG8sIHdvcmxkIQ==";

        let plaintext = base64.decode_base64().unwrap();
        let plaintext = String::from_utf8_lossy(&plaintext).to_string();

        assert_eq!(plaintext, "hello, world!");
    }
}
