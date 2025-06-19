use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use secrecy::{ExposeSecret, SecretSlice, SecretString};

use jolokia::cipher;
use jolokia::traits::{Base64Encode, Cipher, GeneratedKey};

pub const KEY_ENV_VAR: &str = "JOLOKIA_CIPHER_KEY";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Command {
    GenKey,
    Encrypt,
    Decrypt,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum Algorithm {
    #[default]
    ChaCha20Poly1305,
    Hpke,
    RotN,
    Brainfuck,
}

impl Algorithm {
    /// Generic cipher key used by jolokia (this is _not secure_!).
    pub fn default_key(self) -> GeneratedKey {
        match self {
            Self::ChaCha20Poly1305 => GeneratedKey::Symmetric(SecretSlice::from(
                b"edLKPT4jYaabmMwuKzgQwklMC9HxTYmhVY7qln4yrJM".to_vec(),
            )),
            Self::Hpke => GeneratedKey::Asymmetric {
                private: SecretSlice::from(b"cMDcZQWSnd6AQh8lZrSvDqMRr5oAA4ooGrEsrxExQAM".to_vec()),
                public: SecretSlice::from(b"eRR5BeA731Ug5In5EELCpc8wqIUbUSHfP9vyjG1FVAU".to_vec()),
            },
            Self::RotN => GeneratedKey::Symmetric(SecretSlice::from(b"DQ".to_vec())), // This is base64 for `13`.
            Self::Brainfuck => GeneratedKey::Symmetric(SecretSlice::from(b"QnJhaW5mdWNr".to_vec())), // Whatever.
        }
    }
}

impl FromStr for Algorithm {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_lowercase().replace('-', "");
        match s.as_str() {
            "chacha20poly1305" | "chacha20" | "chacha" | "cha20" | "cha" => {
                Ok(Self::ChaCha20Poly1305)
            }
            "hpke" => Ok(Self::Hpke),
            "rotn" | "rot" => Ok(Self::RotN),
            "brainfuck" | "bf" => Ok(Self::Brainfuck),
            _ => Err(()),
        }
    }
}

impl From<Algorithm> for Box<dyn Cipher> {
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::ChaCha20Poly1305 => Box::new(cipher::ChaCha20Poly1305),
            Algorithm::Hpke => Box::new(cipher::Hpke),
            Algorithm::RotN => Box::new(cipher::RotN),
            Algorithm::Brainfuck => Box::new(cipher::Brainfuck),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Message {
    String(String),
    File(PathBuf),
    Stdin,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub enum Output {
    File(PathBuf),
    #[default]
    Stdout,
    Redirected,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
pub struct Args {
    pub command: Option<Command>,
    pub algorithm: Option<Algorithm>,
    pub key: Option<SecretString>,
    pub raw: bool,
    pub message: Option<Message>,
    pub output: Output,
    pub short_help: bool,
    pub long_help: bool,
    pub version: bool,
}

impl Args {
    pub fn build_from_args<I>(mut cli_args: I) -> Result<Self, String>
    where
        I: Iterator<Item: AsRef<str> + ToString>,
    {
        let mut args = Self::default();

        while let Some(arg) = cli_args.next() {
            let some_command = args.command.is_some();
            let some_algorithm = args.algorithm.is_some();
            let some_key = args.key.is_some();
            let some_message = args.message.is_some();
            let some_output = matches!(args.output, Output::File(_));

            let is_genkey = args
                .command
                .as_ref()
                .is_some_and(|c| matches!(c, Command::GenKey));
            let message_file = match args.message.as_ref() {
                Some(Message::File(f)) => Some(f),
                _ => None,
            };

            match arg.as_ref() {
                "-h" => args.short_help = true,
                "--help" => args.long_help = true,
                "-V" | "--version" => args.version = true,
                "genkey" if !some_command => args.command = Some(Command::GenKey),
                "encrypt" if !some_command => args.command = Some(Command::Encrypt),
                "decrypt" if !some_command => args.command = Some(Command::Decrypt),
                "-a" | "--algorithm" if some_command && !some_algorithm => {
                    let Some(algorithm) = cli_args.next() else {
                        return Err(format!("Expected algorithm after '{}'", arg.as_ref()));
                    };
                    let Ok(algorithm) = algorithm.as_ref().parse() else {
                        return Err(format!("Unrecognized algorithm '{}'", algorithm.as_ref()));
                    };
                    args.algorithm = Some(algorithm);
                }
                "-k" | "--key" if some_command && !is_genkey && !some_key => {
                    let Some(key) = cli_args.next() else {
                        return Err(format!("Expected key after '{}'", arg.as_ref()));
                    };
                    args.key = Some(SecretString::from(key.as_ref()));

                    // Note: We _don't_ zeroize `arg` here, because it
                    // would make us require a `+ Zeroize` trait bound
                    // for no benefit whatsoever: if the secret was
                    // passed in as a CLI arg, it's _already exposed_ to
                    // other processes, with a (safely) immutable copy
                    // in `argv`.
                }
                "-r" | "--raw" if some_command && !is_genkey => args.raw = true,
                "-o" | "--output" if some_command && !some_output => {
                    let Some(file) = cli_args.next() else {
                        return Err(format!("Expected file name after '{}'", arg.as_ref()));
                    };
                    args.output = Output::File(PathBuf::from(file.as_ref()));
                }
                "-f" | "--file" if some_command && !some_message => {
                    let Some(file) = cli_args.next() else {
                        return Err(format!("Expected file name after '{}'", arg.as_ref()));
                    };
                    args.message = Some(Message::File(PathBuf::from(file.as_ref())));
                }
                "-i" | "--in-place" if message_file.is_some() && !some_output => {
                    let message_file = message_file.expect("it is `Some`");
                    args.output = Output::File(message_file.to_owned());
                }
                message if some_command && !is_genkey && !some_message => {
                    args.message = Some(Message::String(message.to_string()));
                }
                unknown => {
                    return Err(format!("Unknown argument: '{unknown}'"));
                }
            }
        }

        // Default to `--raw` for ROT-n and Brainfuck.
        if matches!(args.algorithm, Some(Algorithm::RotN | Algorithm::Brainfuck)) {
            args.raw = true;
        }

        // If no key, try `env`.
        if args.key.is_none() {
            args.key = Self::maybe_get_key_from_env();
        }
        if let Some(ref key) = args.key {
            // If the given key is a file, use the content of the file
            // as the key.
            if let Some(key) = Self::maybe_get_key_from_file(key) {
                args.key = Some(key);
            }
        }
        // TODO: Simplify with `if let` chain.
        if let Some(ref key) = args.key {
            if args.algorithm == Some(Algorithm::RotN) {
                args.key = Some(Self::normalize_rotn_key_to_base64(key)?);
            }
        }

        // If not message, try `stdin`.
        if args.message.is_none() && Self::does_stdin_have_content() {
            args.message = Some(Message::Stdin);
        }

        // If no explicit `--output`, check if redirected or `stdout`.
        if !matches!(args.output, Output::File(_)) && Self::is_output_redirected() {
            args.output = Output::Redirected;
        }

        Ok(args)
    }

    fn maybe_get_key_from_env() -> Option<SecretString> {
        std::env::var(KEY_ENV_VAR).ok().map(SecretString::from)
    }

    /// Try to extract non empty key from potentially existing file.
    ///
    /// The file _must_ exist, _must_ be readable, and _must_ be
    /// non-empty. If these conditions are met, the content of the file
    /// is returned (trailing whitespace gets removed).
    fn maybe_get_key_from_file(maybe_file: &SecretString) -> Option<SecretString> {
        let maybe_file = Path::new(maybe_file.expose_secret());
        if maybe_file.is_file() {
            if let Ok(key) = fs::read_to_string(maybe_file) {
                let key = key.trim_end();
                if !key.is_empty() {
                    return Some(SecretString::from(key));
                }
            }
        }
        None
    }

    /// Normalize ROT-n keys to base64.
    ///
    /// ROT-n keys are string representations of decimal numbers
    /// (e.g, "13"). We want to normalize them into base64 so they work
    /// the same as all the other keys for all the other algorithms.
    fn normalize_rotn_key_to_base64(key: &SecretString) -> Result<SecretString, String> {
        let key = key.expose_secret();
        let Ok(key) = key.parse::<u8>() else {
            return Err("Not a valid ROT-n key.\nChoose a value in the range 0 to 255".to_string());
        };
        let key = (&[key] as &[u8; 1]).base64_encode();
        Ok(SecretString::from(key))
    }

    fn does_stdin_have_content() -> bool {
        #![allow(unreachable_code)]
        #[cfg(test)]
        return false;
        // If the descriptor/handle refers to a terminal/tty, there is
        // nothing in stdin to be consumed.
        !io::stdin().is_terminal()
    }

    fn is_output_redirected() -> bool {
        #![allow(unreachable_code)]
        #[cfg(test)]
        return false;
        // If the descriptor/handle refers to a terminal/tty, the output
        // is not redirected to a file.
        !io::stdout().is_terminal()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::iter_on_single_items)]

    use super::*;

    #[test]
    fn command_genkey_regular() {
        let args = Args::build_from_args(["genkey"].iter()).unwrap();
        assert!(args.command.is_some_and(|c| c == Command::GenKey));
    }

    #[test]
    fn second_command_does_not_override_genkey() {
        let err = Args::build_from_args(["genkey", "encrypt"].iter()).unwrap_err();
        assert!(err.contains("'encrypt'"));
    }

    #[test]
    fn command_encrypt_regular() {
        let args = Args::build_from_args(["encrypt"].iter()).unwrap();
        assert!(args.command.is_some_and(|c| c == Command::Encrypt));
    }

    #[test]
    fn second_command_does_not_override_encrypt() {
        let args = Args::build_from_args(["encrypt", "decrypt"].iter()).unwrap();
        assert!(args.command.is_some_and(|c| c == Command::Encrypt));
    }

    #[test]
    fn command_decrypt_regular() {
        let args = Args::build_from_args(["decrypt"].iter()).unwrap();
        assert!(args.command.is_some_and(|c| c == Command::Decrypt));
    }

    #[test]
    fn second_command_does_not_override_decrypt() {
        let args = Args::build_from_args(["decrypt", "genkey"].iter()).unwrap();
        assert!(args.command.is_some_and(|c| c == Command::Decrypt));
    }

    #[test]
    fn default_algorithm() {
        assert_eq!(Algorithm::default(), Algorithm::ChaCha20Poly1305);
    }

    #[test]
    fn option_algorithm_default() {
        let args = Args::build_from_args(["encrypt"].iter()).unwrap();
        assert!(args.algorithm.is_none());
    }

    #[test]
    fn option_short_algorithm_regular() {
        let args = Args::build_from_args(["encrypt", "-a", "ChaCha20-Poly1305"].iter()).unwrap();
        assert!(matches!(args.algorithm, Some(Algorithm::ChaCha20Poly1305)));
    }

    #[test]
    fn option_long_algorithm_regular() {
        let args =
            Args::build_from_args(["encrypt", "--algorithm", "ChaCha20-Poly1305"].iter()).unwrap();
        assert!(matches!(args.algorithm, Some(Algorithm::ChaCha20Poly1305)));
    }

    #[test]
    fn option_key_default() {
        let args = Args::build_from_args(["encrypt"].iter()).unwrap();
        assert!(args.key.is_none());
    }

    #[test]
    fn option_short_key_regular() {
        let args = Args::build_from_args(["encrypt", "-k", "abcdef"].iter()).unwrap();
        assert!(args.key.is_some_and(|k| k.expose_secret() == "abcdef"));
    }

    #[test]
    fn option_long_key_regular() {
        let args = Args::build_from_args(["encrypt", "--key", "abcdef"].iter()).unwrap();
        assert!(args.key.is_some_and(|k| k.expose_secret() == "abcdef"));
    }

    #[test]
    fn option_raw_default() {
        let args = Args::build_from_args(["encrypt"].iter()).unwrap();
        assert!(!args.raw);
    }

    #[test]
    fn option_short_raw_regular() {
        let args = Args::build_from_args(["encrypt", "-r"].iter()).unwrap();
        assert!(args.raw);
    }

    #[test]
    fn option_long_raw_regular() {
        let args = Args::build_from_args(["encrypt", "--raw"].iter()).unwrap();
        assert!(args.raw);
    }

    #[test]
    fn option_output_default() {
        let args = Args::build_from_args(["encrypt"].iter()).unwrap();
        assert!(args.output == Output::Stdout);
    }

    #[test]
    fn option_short_output_regular() {
        let args = Args::build_from_args(["encrypt", "-o", "out.enc"].iter()).unwrap();
        assert!(args.output == Output::File(PathBuf::from("out.enc")));
    }

    #[test]
    fn option_long_output_regular() {
        let args = Args::build_from_args(["encrypt", "--output", "out.enc"].iter()).unwrap();
        assert!(args.output == Output::File(PathBuf::from("out.enc")));
    }

    #[test]
    fn option_message_default() {
        let args = Args::build_from_args(["encrypt"].iter()).unwrap();
        assert!(args.message.is_none());
    }

    #[test]
    fn option_short_file_regular() {
        let args = Args::build_from_args(["encrypt", "-f", "in.txt"].iter()).unwrap();
        assert!(args.message == Some(Message::File(PathBuf::from("in.txt"))));
    }

    #[test]
    fn option_long_file_regular() {
        let args = Args::build_from_args(["encrypt", "--file", "in.txt"].iter()).unwrap();
        assert!(args.message == Some(Message::File(PathBuf::from("in.txt"))));
    }

    #[test]
    fn option_short_help_regular() {
        let args = Args::build_from_args(["-h"].iter()).unwrap();
        assert!(args.short_help);
        assert!(!args.long_help);
    }

    #[test]
    fn option_long_help_regular() {
        let args = Args::build_from_args(["--help"].iter()).unwrap();
        assert!(!args.short_help);
        assert!(args.long_help);
    }

    #[test]
    fn option_short_version_regular() {
        let args = Args::build_from_args(["-V"].iter()).unwrap();
        assert!(args.version);
    }

    #[test]
    fn option_long_version_regular() {
        let args = Args::build_from_args(["--version"].iter()).unwrap();
        assert!(args.version);
    }

    #[test]
    fn command_unknown_is_error() {
        let err = Args::build_from_args(["unknown"].iter()).unwrap_err();
        assert!(err.contains("'unknown'"));
    }
}
