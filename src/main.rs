mod cmd;

use std::env;
use std::process;

use lessify::Pager;

use cmd::{cli, ui};

fn main() {
    let args = match cli::Args::build_from_args(env::args().skip(1)) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{fatal}: {err}.", fatal = ui::Color::error("fatal"));
            println!("Try '{bin} -h' for help.", bin = env!("CARGO_BIN_NAME"));
            process::exit(2);
        }
    };

    if args.long_help {
        long_help();
    } else if args.short_help {
        short_help();
    } else if args.version {
        version();
    } else if let Some(ref command) = args.command {
        if let Err(reason) = match command {
            cli::Command::GenKey => cmd::genkey(),
            cli::Command::Encrypt => {
                let key = get_key_or_default(&args, true);
                let message = get_message_or_exit(&args);
                cmd::encrypt(key, message)
            }
            cli::Command::Decrypt => {
                let key = get_key_or_default(&args, false);
                let message = get_message_or_exit(&args);
                cmd::decrypt(key, message)
            }
        } {
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

fn get_key_or_default(args: &cli::Args, warn_if_default: bool) -> &str {
    if let Some(ref key) = args.key {
        key.as_str()
    } else {
        if warn_if_default {
            eprintln!(
                "\
{warning}: Using {package}'s default cipher key.

                       {b}THIS IS NOT SECURE!{rt}

Anyone using {package} will be able to decrypt your messages. To generate
a unique cipher key, run `{bin} genkey`, and use it on the command line
with `--key`, or set the `{key_env_var}` environment variable.
",
                warning = ui::Color::warning("warning"),
                package = env!("CARGO_PKG_NAME"),
                bin = env!("CARGO_BIN_NAME"),
                key_env_var = cli::KEY_ENV_VAR,
                b = ui::Color::maybe_color(ui::color::BOLD),
                rt = ui::Color::maybe_color(ui::color::RESET),
            );
        }
        cmd::DEFAULT_KEY
    }
}

fn get_message_or_exit(args: &cli::Args) -> &str {
    if let Some(ref message) = args.message {
        message.as_str()
    } else {
        eprintln!(
            "{fatal}: You must provide a message.",
            fatal = ui::Color::error("fatal")
        );
        process::exit(2);
    }
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
  encrypt
  decrypt

Args:
  <MESSAGE>
  -k, --key <KEY>        Cipher key (base64)

Options:
  -h, --help             Show this message and exit
  -V, --version          Show the version and exit
  -v, --verbose          Show files being copied
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
  TODO: Lorem ipsum {bin}.
  symmetric encryption (explain),
  need a key

Algorithms:
  {u}Name{rt}                 {u}Key Size{rt}
  Chacha20-Poly1305    32-bytes (256-bits)

Key:
  In {package}, a key is always a base64-encoded string of bytes. The
  size of the key varies depending on the selected algorithm.

  To generate a new key run:

      {h}${rt} jolokia genkey
      hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w=

  To use the key, pass it as `--key` or `-k`:

      {h}${rt} jolokia encrypt \"foo\" --key hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w=
      FTqHwIHQJ+IsFMiiYkioNmGoD+3zMp4jRpGLQIcNmw==

  Or as an environment variable (but `--key` has precedence):

      {h}${rt} export {key_env_var}=hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w=
      {h}${rt} jolokia encrypt \"foo\"
      FTqHwIHQJ+IsFMiiYkioNmGoD+3zMp4jRpGLQIcNmw==

  The key can also be the name of a file that contains a key:

      {h}${rt} echo hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w= > /secrets/{bin}.key
      {h}${rt} jolokia decrypt --key /secrets/{bin}.key FTqHwIHQJ+IsFMiiYkioNmGoD+3zMp4jRpGLQIcNmw==
      foo

  To set a key permanently, the recommended solution is to point the
  environment variable to a file:

      {h}${rt} echo hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w= > ~/.{bin}.key
      {h}${rt} echo '{key_env_var}=\"$HOME/.{bin}.key\"' >> ~/.bashrc

Message:
  The message can be passed on the command line:

      {h}${rt} jolokia encrypt \"bar\"
      YfCpYYm7tVjxbs1g28K2sKvCMu3mF2/Cl3s4toQd+A==

  Or via `stdin` (but the command line has precedence):

      {h}${rt} cat bar.txt | jolokia encrypt
      YfCpYYm7tVjxbs1g28K2sKvCMu3mF2/Cl3s4toQd+A==

  By definition, you can round-trip it:

      {h}${rt} jolokia encrypt \"hello, world\" > encrypted.txt
      {h}${rt} cat encrypted.txt | jolokia decrypt
      hello, world
",
        help = short_help_message(),
        bin = env!("CARGO_BIN_NAME"),
        package = env!("CARGO_PKG_NAME"),
        key_env_var = cli::KEY_ENV_VAR,
        h = ui::Color::maybe_color(ui::color::HIGHLIGHT),
        u = ui::Color::maybe_color(ui::color::UNDERLINE),
        rt = ui::Color::maybe_color(ui::color::RESET),
    ));
}

fn version() {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}
