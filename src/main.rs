mod cmd;

use std::env;
use std::process;

use lessify::Pager;

use cmd::cli;

fn main() {
    let args = match cli::Args::build_from_args(env::args().skip(1)) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("fatal: {err}.");
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
    } else if let Some(command) = args.command {
        if let Err(reason) = match command {
            cli::Command::GenKey => cmd::genkey(),
            cli::Command::Encrypt => cmd::encrypt(cmd::DEFAULT_KEY, "hi"),
            cli::Command::Decrypt => {
                cmd::decrypt(cmd::DEFAULT_KEY, "wWaYozIrI6og7mWb8YTn/lMb22QZ3KeP2xVfLRaT")
            }
        } {
            eprintln!("{reason}");
            process::exit(1);
        }
    } else {
        // No arguments.
        short_help();
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
