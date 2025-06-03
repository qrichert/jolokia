mod cmd;

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::SystemTime;
use std::{env, fs, process};

use lessify::Pager;

use jolokia::traits::{Cipher, GeneratedKey};

use cmd::{cli, ui};

// TODO: This deserves refactoring. Error handling is inconsistent, and
// `if is_in_place` logic is brittle because correctness is not enforced
// by the compiler. But it's fine for now as long as we don't add new
// features.

fn main() {
    let args = match cli::Args::build_from_args(env::args().skip(1)) {
        Ok(args) => args,
        Err(err) => {
            eprintln!(
                "\
{fatal}: {err}.
Try '{bin} -h' for help.",
                fatal = ui::Color::error("fatal"),
                bin = env!("CARGO_BIN_NAME")
            );
            process::exit(2);
        }
    };

    if args.long_help {
        long_help();
    } else if args.short_help {
        short_help();
    } else if args.version {
        version();
    } else if let Some(command) = args.command {
        if let Err(reason) = execute_command(command, &args) {
            eprintln!(
                "{error}: {reason}{}",
                // Errors from dependencies may or may not end with `.`.
                if reason.ends_with('.') { "" } else { "." },
                error = ui::Color::error("error"),
            );
            process::exit(1);
        }
    } else {
        // No arguments.
        short_help();
    }
}

fn execute_command(command: cli::Command, args: &cli::Args) -> Result<(), String> {
    let algorithm = args.algorithm.unwrap_or_default();
    let cipher: Box<dyn Cipher> = algorithm.into();
    let add_newline = !matches!(args.output, cli::Output::Redirected);

    match command {
        cli::Command::GenKey => cmd::genkey(cipher.as_ref(), add_newline),
        cli::Command::Encrypt | cli::Command::Decrypt => {
            let is_in_place = is_input_file_used_for_output(args);

            let cipher = cipher.as_ref();
            let key = get_key_or_default(args, algorithm);
            let message = get_message_or_exit(args);
            let output = if is_in_place {
                get_temporary_file_or_exit(args)
            } else {
                get_output_or_exit(args)
            };

            if command == cli::Command::Encrypt {
                cmd::encrypt(cipher, &key, message, output, args.raw, add_newline)?;
            } else if command == cli::Command::Decrypt {
                cmd::decrypt(cipher, &key, message, output, args.raw)?;
            }

            if is_in_place {
                override_output_file_with_temporary_file_or_exit(args);
            }

            Ok(())
        }
    }
}

fn is_input_file_used_for_output(args: &cli::Args) -> bool {
    let (Some(cli::Message::File(input_file)), cli::Output::File(output_file)) =
        (&args.message, &args.output)
    else {
        return false;
    };
    let (Ok(input_file), Ok(output_file)) = (input_file.canonicalize(), output_file.canonicalize())
    else {
        return false;
    };
    input_file == output_file
}

fn get_key_or_default(args: &cli::Args, algorithm: cli::Algorithm) -> Vec<u8> {
    if let Some(ref key) = args.key {
        key.as_bytes().to_owned()
    } else if algorithm == cli::Algorithm::RotN || algorithm == cli::Algorithm::Brainfuck {
        // Special do-not-warn cases.
        algorithm.default_key().get_symmetric().to_owned()
    } else {
        eprintln!(
            "\
{warning}: Using {package}'s default cipher key.

                       {b}THIS IS NOT SECURE!{rt}

Anyone using {package} will be able to decrypt your messages. To generate
a unique cipher key, run `{bin} genkey`, and use it on the command line
with `--key`, or set the `{key_env_var}` environment variable.",
            warning = ui::Color::warning("warning"),
            package = env!("CARGO_PKG_NAME"),
            bin = env!("CARGO_BIN_NAME"),
            key_env_var = cli::KEY_ENV_VAR,
            b = ui::Color::maybe_color(ui::color::BOLD),
            rt = ui::Color::maybe_color(ui::color::RESET),
        );

        let key = algorithm.default_key();
        match key {
            GeneratedKey::Symmetric(_) => key.get_symmetric(),
            GeneratedKey::Asymmetric { .. } => match args.command {
                Some(cli::Command::Encrypt) => key.get_asymmetric_public(),
                Some(cli::Command::Decrypt) => key.get_asymmetric_private(),
                _ => unreachable!(),
            },
            GeneratedKey::None => unreachable!(),
        }
        .to_owned()
    }
}

fn get_message_or_exit(args: &cli::Args) -> Box<dyn Read> {
    if let Some(ref message) = args.message {
        match message {
            cli::Message::String(message) => Box::new(io::Cursor::new(message.to_owned())),
            cli::Message::File(file) => {
                let f = match fs::File::open(file) {
                    Ok(f) => f,
                    Err(reason) => {
                        eprintln!(
                            "{error}: Could not read '{}': {reason}.",
                            file.display(),
                            error = ui::Color::error("error")
                        );
                        process::exit(1);
                    }
                };
                let reader = io::BufReader::new(f);
                Box::new(reader)
            }
            cli::Message::Stdin => Box::new(io::stdin()),
        }
    } else {
        eprintln!(
            "{fatal}: You must provide a message.",
            fatal = ui::Color::error("fatal")
        );
        process::exit(2);
    }
}

fn get_output_or_exit(args: &cli::Args) -> Box<dyn Write> {
    match args.output {
        cli::Output::File(ref file) => {
            let f = match fs::File::create(file) {
                Ok(f) => f,
                Err(reason) => {
                    eprintln!(
                        "{error}: Could not open file for writing '{}': {reason}.",
                        file.display(),
                        error = ui::Color::error("error")
                    );
                    process::exit(1);
                }
            };
            let writer = io::BufWriter::new(f);
            Box::new(writer)
        }
        cli::Output::Stdout | cli::Output::Redirected => Box::new(io::stdout()),
    }
}

fn get_temporary_file_or_exit(args: &cli::Args) -> Box<dyn Write> {
    debug_assert!(
        is_input_file_used_for_output(args),
        "Should only get called if in-place ciphering."
    );
    let tmp_file = build_temporary_file_path(args);
    let f = match fs::File::create(&tmp_file) {
        Ok(f) => f,
        Err(reason) => {
            eprintln!(
                "{error}: Could not open file for writing '{}': {reason}.",
                tmp_file.display(),
                error = ui::Color::error("error")
            );
            process::exit(1);
        }
    };
    let writer = io::BufWriter::new(f);
    Box::new(writer)
}

fn override_output_file_with_temporary_file_or_exit(args: &cli::Args) {
    debug_assert!(
        is_input_file_used_for_output(args),
        "Should only get called if in-place ciphering."
    );
    let cli::Output::File(ref file) = args.output else {
        unreachable!("if in-place, it's necessarily a file");
    };
    let tmp_file = build_temporary_file_path(args);
    if let Err(reason) = std::fs::rename(tmp_file, file) {
        eprintln!(
            "{error}: Could not override '{}': {reason}.",
            file.display(),
            error = ui::Color::error("error")
        );
        process::exit(1);
    }
}

// TODO: Not good that we need to call this twice, refactoring would do
// some good. This whole in-place thing doesn't "fit in" with the
// current design, it's too crafty.
fn build_temporary_file_path(args: &cli::Args) -> PathBuf {
    // File name can't change from create to rename.
    static EXTENSION: OnceLock<String> = OnceLock::new();

    let cli::Output::File(ref file) = args.output else {
        unreachable!("if in-place, it's necessarily a file");
    };

    file.with_extension(EXTENSION.get_or_init(|| {
        let mut extension = env!("CARGO_CRATE_NAME").to_string();
        if let Ok(timestamp) = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|t| t.as_micros())
        {
            extension = format!("{timestamp}.{extension}");
        }
        extension
    }))
}

fn short_help() {
    println!("{}", short_help_message());
    println!(
        "For full help, see `{bin} --help`.",
        bin = env!("CARGO_BIN_NAME")
    );
}

fn short_help_message() -> String {
    format!(
        "\
{description}

Usage: {bin} [<options>] <command> [<args>]

Commands:
  genkey                 Generate cipher key
  encrypt                Encrypt plaintext
  decrypt                Decrypt ciphertext

Args:
  <MESSAGE>
  -k, --key <KEY>        Cipher key (base64)
  -r, --raw              Handle message as raw binary
  -f, --file <FILE>      Read message from file
    -i, --in-place       Write output to input file
  -o, --output <FILE>    Write output to file

Options:
  -h, --help             Show help message and exit
  -V, --version          Show the version and exit
",
        description = env!("CARGO_PKG_DESCRIPTION"),
        bin = env!("CARGO_BIN_NAME"),
    )
}

#[allow(clippy::too_many_lines)]
fn long_help() {
    Pager::page_or_print(&format!(
        "\
{help}
What does {package} do?
  {package} provides strong, modern, hard-to-misuse encryption for the
  general public.

  {warning}: {package} has not been audited for security. It is based on
  audited dependencies for the underlying algorithm implementations, but
  the final package (what you're using) was not.

  {caution}: Do not encrypt data you can't afford to lose. Be especially
  cautious of in-place encryption; always make a backup first. If you
  lose your key, or if there's a bug, {b}YOUR DATA WILL NOT BE RECOVERABLE{rt}.

  If you need a refresher on symmetric and asymmetric encryption, read
  the section at the bottom.

Algorithms:
  {u}Name{rt}                 {u}Key Size{rt}               {u}Type{rt}
  ChaCha20-Poly1305    32-bytes (256-bits)    Symmetric
  HPKE                 32-bytes (256-bits)    Asymmetric
  ROT-n                0..255 (insecure)      Symmetric

Key:
  In {package}, a key is always a base64-encoded string of bytes. The
  size of the key varies depending on the selected algorithm.

  To generate a new key run:

      {h}${rt} {bin} genkey
      hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w

  To use the key, pass it as `--key` or `-k`:

      {h}${rt} {bin} encrypt \"foo\" --key hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w
      Q0gyMAGSwlWJdALzAAAAE448viN3l+rwa7W4RdkRI0V/VckAAAAA

  Or as an environment variable (but `--key` has precedence):

      {h}${rt} export {key_env_var}=hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w
      {h}${rt} {bin} encrypt \"foo\"
      Q0gyMAGSwlWJdALzAAAAE448viN3l+rwa7W4RdkRI0V/VckAAAAA

  The key can also be the name of a file that contains a key:

      {h}${rt} echo hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w > /secrets/{bin}.key
      {h}${rt} {bin} decrypt --key /secrets/{bin}.key Q0gyMAGSwlWJdALzAAAAE448viN3l+rwa7W4RdkRI0V/VckAAAAA
      foo

  To set a key permanently, the recommended solution is to point the
  environment variable to a file:

      {h}${rt} echo hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w > ~/.{bin}.key
      {h}${rt} echo 'export {key_env_var}=\"$HOME/.{bin}.key\"' >> ~/.bashrc

Message:
  The message can be passed on the command line:

      {h}${rt} {bin} encrypt \"bar\"
      Q0gyMAHPNRsLieAOAAAAE/ssTCh2zCm73t+aQf9aKNepgPkAAAAA

  Or from a file:

      {h}${rt} {bin} encrypt --file bar.txt
      Q0gyMAHPNRsLieAOAAAAE/ssTCh2zCm73t+aQf9aKNepgPkAAAAA

  Or via `stdin` (but the command line has precedence):

      {h}${rt} cat bar.txt | {bin} encrypt
      Q0gyMAHPNRsLieAOAAAAE/ssTCh2zCm73t+aQf9aKNepgPkAAAAA

  By definition, you can round-trip it:

      {h}${rt} {bin} encrypt \"hello, world\" -o encrypted.txt
      {h}${rt} {bin} decrypt -f encrypted.txt
      hello, world

  You can also encrypt or decrypt a file in-place:

      {h}${rt} {bin} encrypt -f cat.gif --in-place
      {h}${rt} {bin} decrypt -f cat.gif -i

Raw I/O:
  If you do not want base64 encoding, you can pass the `--raw` or `-r`
  flag. This makes sense for larger files for which you don't want the
  ~33% size overhead of base64.

      {h}${rt} {bin} encrypt --raw \"hello, world\" > hello.enc
      {h}${rt} cat hello.enc | {bin} decrypt --raw
      hello, world

  Base64 is the simplest and safest option for most users. It makes it
  easy to copy-paste and share ciphertext. Use `--raw` only if you know
  what you're doing.

Compression:
  BYOC. {package} does not provide built-in compression, but you can
  bring your own:

      {h}${rt} gzip -c cat.gif | {bin} encrypt -r > out.enc
      {h}${rt} {bin} decrypt -r -f out.enc | gunzip > cat.gif

  If you need to compress and encrypt multiple files or directories,
  consider `tar`ing them:

      {h}${rt} tar -czf - cat.gif more-gifs/ | {bin} encrypt -r > out.enc
      {h}${rt} {bin} decrypt -r -f out.enc | tar -xzf -

  It makes sense to combine compression with `--raw` to get the smallest
  file size possible.

Symmetric vs. Asymmetric Encryption and Authentication:
  With symmetric encryption, all parties share the same key. Anyone who
  has access to the key can both encrypt and decrypt messages.

  Say Bob wants to send a secret message to Alice over a public network.
  Then Bob encrypts the message with the key, and sends it encrypted
  over the public network. Anyone can see the encrypted message, but
  only Alice shares the key with Bob, so only Alice can decrypt it.

  This process is simple, but it has a flaw: unless Alice and Bob meet
  in person, there is no way for them to share the secret key using only
  symmetric encryption. If Bob generates a key, he can't send it in
  plain to Alice, because other people would see the key too, and he
  can't send it encrypted, because how would Alice decrypt it if they
  don't share a key yet? This is where asymmetric encryption comes in.

  With asymmetric encryption, there are two keys: a private key and a
  public key. Only one person has access to the private key, but
  everyone can have the public key. The public key is used to encrypt
  messages, and the only way to decrypt them is with the private key.
  In asymmetric encryption, a key either encrypts or decrypts, but it
  cannot do both.

  If Bob wants to send a secret message to Alice, Alice must first
  generate a key pair. Only Alice will ever see the secret key, but she
  can send the public key in plain to Bob. Then Bob uses Alice's public
  key to encrypt the message. At this point, not even Bob can decrypt
  what he just encrypted. The public key in his possession can only
  encrypt. The only person who can decrypt the message is Alice, using
  her private key.

  This is a common pattern: you first use asymmetric encryption to
  exchange a symmetric key, and then you use symmetric encryption for
  convenience and speed (asymmetric encryption doesn't do well with
  large messages, it is designed for keys, not data).

  Another common pattern is hybrid encryption: you use both at the same
  time. Say Bob wants to send a message to Alice again. He starts by
  generating a one-off symmetric key, which he uses to encrypt the data.
  Bob then uses Alice's public key to encrypt the ephemeral symmetric
  key and sends both parts as one payload. To read the message, Alice
  decrypts the symmetric key with her private key, and then uses that
  key to decrypt the message.

  Another use case for asymmetric encryption is authentication. Not only
  the public key can encrypt messages, the private key can too. And in
  that case, you use the public key for decryption.

  If Alice encrypts the message: \"I am Alice!\" with her private key,
  anyone in posession of Alice's public key can be certain that Alice
  wrote that message. The only way that Alice's public key can decrypt
  it, is that it was encrypted, or _signed_, by Alice's private key.

  If Bob, who is not is possession of Alice's secret key, wrote \"I am
  Alice!\" and signed the message, then Alice's public key would not be
  able to decrypt it, and everyone would know that it wasn't really
  Alice who wrote it.

  That is, signatures are only as worthy as your trust in the public
  key. The cryptography works, but how much do you _trust_ that the
  public key you have really belongs to Alice?
",
        help = short_help_message(),
        bin = env!("CARGO_BIN_NAME"),
        package = env!("CARGO_PKG_NAME"),
        key_env_var = cli::KEY_ENV_VAR,
        warning = ui::Color::warning("warning"),
        caution = ui::Color::error("caution"),
        h = ui::Color::maybe_color(ui::color::HIGHLIGHT),
        b = ui::Color::maybe_color(ui::color::BOLD),
        u = ui::Color::maybe_color(ui::color::UNDERLINE),
        rt = ui::Color::maybe_color(ui::color::RESET),
    ));
}

fn version() {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}
