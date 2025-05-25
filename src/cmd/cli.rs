#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    GenKey,
    Encrypt,
    Decrypt,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Args {
    pub command: Option<Command>,
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

        #[allow(clippy::while_let_on_iterator)] // TODO: Need it for `--key`.
        while let Some(arg) = cli_args.next() {
            let some_command = args.command.is_some();

            match arg.as_ref() {
                "genkey" if !some_command => args.command = Some(Command::GenKey),
                "encrypt" if !some_command => args.command = Some(Command::Encrypt),
                "decrypt" if !some_command => args.command = Some(Command::Decrypt),
                "-h" => args.short_help = true,
                "--help" => args.long_help = true,
                "-V" | "--version" => args.version = true,
                unknown => {
                    return Err(format!("Unknown argument: '{unknown}'"));
                }
            }
        }

        Ok(args)
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
        let err = Args::build_from_args(["encrypt", "decrypt"].iter()).unwrap_err();
        assert!(err.contains("'decrypt'"));
    }

    #[test]
    fn command_decrypt_regular() {
        let args = Args::build_from_args(["decrypt"].iter()).unwrap();
        assert!(args.command.is_some_and(|c| c == Command::Decrypt));
    }

    #[test]
    fn second_command_does_not_override_decrypt() {
        let err = Args::build_from_args(["decrypt", "genkey"].iter()).unwrap_err();
        assert!(err.contains("'genkey'"));
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
