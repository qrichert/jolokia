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
  Lorem ipsum {bin}.
",
        help = short_help_message(),
        bin = env!("CARGO_BIN_NAME"),
        package = env!("CARGO_PKG_NAME"),
    ));
}

fn version() {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}
