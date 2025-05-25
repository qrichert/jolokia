use base64::prelude::{BASE64_STANDARD, Engine as _};

use super::traits;

impl traits::ToBase64 for &[u8] {
    fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(self)
    }
}

impl<const N: usize> traits::ToBase64 for &[u8; N] {
    fn to_base64(&self) -> String {
        self.as_slice().to_base64()
    }
}

impl traits::ToBase64 for Vec<u8> {
    fn to_base64(&self) -> String {
        self.as_slice().to_base64()
    }
}

impl traits::FromBase64 for &str {
    fn from_base64(&self) -> traits::Result<Vec<u8>> {
        match BASE64_STANDARD.decode(self) {
            Ok(bytes) => Ok(bytes),
            Err(reason) => Err(traits::Error::Base64Decode(reason.to_string())),
        }
    }
}

impl traits::FromBase64 for String {
    fn from_base64(&self) -> traits::Result<Vec<u8>> {
        self.as_str().from_base64()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{FromBase64, ToBase64};

    #[test]
    fn base64_encode_bytes() {
        let plaintext = b"hello, world!";

        let base64 = plaintext.to_base64();

        assert_eq!(base64, "aGVsbG8sIHdvcmxkIQ==");
    }

    #[test]
    fn base64_decode_string() {
        let base64 = "aGVsbG8sIHdvcmxkIQ==";

        let plaintext = base64.from_base64().unwrap();
        let plaintext = String::from_utf8_lossy(&plaintext).to_string();

        assert_eq!(plaintext, "hello, world!");
    }
}
