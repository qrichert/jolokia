use std::fs;
use std::io::{self, IsTerminal};
use std::path::PathBuf;

pub const KEY_ENV_VAR: &str = "JOLOKIA_CIPHER_KEY";

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    GenKey,
    Encrypt,
    Decrypt,
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
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Args {
    pub command: Option<Command>,
    pub key: Option<String>,
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
            let some_key = args.key.is_some();
            let some_output = matches!(args.output, Output::File(_));
            let some_message = args.message.is_some();

            match arg.as_ref() {
                "genkey" if !some_command => args.command = Some(Command::GenKey),
                "encrypt" if !some_command => args.command = Some(Command::Encrypt),
                "decrypt" if !some_command => args.command = Some(Command::Decrypt),
                "-k" | "--key" if !some_key => args.key = cli_args.next().map(|k| k.to_string()),
                "-h" => args.short_help = true,
                "--help" => args.long_help = true,
                "-V" | "--version" => args.version = true,
                "-o" | "--output" => {
                    if some_command && !some_output {
                        if let Some(file) = cli_args.next() {
                            args.output = Output::File(PathBuf::from(file.as_ref()));
                        }
                    }
                }
                "-f" | "--file" if some_command && !some_message => {
                    args.message = cli_args
                        .next()
                        .map(|m| Message::File(PathBuf::from(m.as_ref())));
                }
                message if some_command && !some_message => {
                    args.message = Some(Message::String(message.to_string()));
                }
                unknown => {
                    return Err(format!("Unknown argument: '{unknown}'"));
                }
            }
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

    fn maybe_get_key_from_env() -> Option<String> {
        std::env::var(KEY_ENV_VAR).ok()
    }

    /// Try to extract non empty key from potentially existing file.
    ///
    /// The file _must_ exist, _must_ be readable, and _must_ be
    /// non-empty. If these conditions are met, the content of the file
    /// is returned (trailing whitespace gets removed).
    fn maybe_get_key_from_file(maybe_file: &str) -> Option<String> {
        let maybe_file = PathBuf::from(maybe_file);
        if maybe_file.is_file() {
            if let Ok(key) = fs::read_to_string(&maybe_file) {
                let key = key.trim_end();
                if !key.is_empty() {
                    return Some(key.to_string());
                }
            }
        }
        None
    }

    fn does_stdin_have_content() -> bool {
        // If the descriptor/handle refers to a terminal/tty, there is
        // nothing in stdin to be consumed.
        !io::stdin().is_terminal()
    }

    fn is_output_redirected() -> bool {
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
        let args = Args::build_from_args(["genkey", "encrypt"].iter()).unwrap();
        assert!(args.command.is_some_and(|c| c == Command::GenKey));
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
    fn command_unknown_is_error() {
        let err = Args::build_from_args(["unknown"].iter()).unwrap_err();
        assert!(err.contains("'unknown'"));
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
}
