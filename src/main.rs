mod cmd;

use std::io::{self, Read, Write};
use std::process;
use std::{env, fs};

use lessify::Pager;

use cmd::{cli, ui};

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
    } else if let Some(ref command) = args.command {
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

fn execute_command(command: &cli::Command, args: &cli::Args) -> Result<(), String> {
    let add_newline = !matches!(args.output, cli::Output::Redirected);
    match command {
        cli::Command::GenKey => cmd::genkey(add_newline),
        cli::Command::Encrypt => {
            ensure_input_neq_output_or_exit(args);
            let key = get_key_or_default(args);
            let message = get_message_or_exit(args);
            let output = get_output_or_exit(args);
            cmd::encrypt(key, message, output, args.raw, args.compress, add_newline)
        }
        cli::Command::Decrypt => {
            ensure_input_neq_output_or_exit(args);
            let key = get_key_or_default(args);
            let message = get_message_or_exit(args);
            let output = get_output_or_exit(args);
            cmd::decrypt(key, message, output, args.raw, args.extract)
        }
    }
}

fn ensure_input_neq_output_or_exit(args: &cli::Args) {
    if let (Some(cli::Message::File(input_file)), cli::Output::File(output_file)) =
        (&args.message, &args.output)
    {
        let Ok(input_file) = input_file.canonicalize() else {
            return;
        };
        let Ok(output_file) = output_file.canonicalize() else {
            return;
        };

        if input_file == output_file {
            eprintln!(
                "\
{fatal}: Cannot read/write from/to the same file.
Writing to a file truncates it; there's nothing left to read then.
Please write to a separate file, and rename it afterwards.",
                fatal = ui::Color::error("fatal"),
            );
            process::exit(2);
        }
    }
}

fn get_key_or_default(args: &cli::Args) -> &str {
    if let Some(ref key) = args.key {
        key.as_str()
    } else {
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
        cmd::DEFAULT_KEY
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
  -o, --output <FILE>    Write output to file

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
      hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w

  To use the key, pass it as `--key` or `-k`:

      {h}${rt} jolokia encrypt \"foo\" --key hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w
      Q0gyMAGSwlWJdALzAAAAE448viN3l+rwa7W4RdkRI0V/VckAAAAA

  Or as an environment variable (but `--key` has precedence):

      {h}${rt} export {key_env_var}=hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w
      {h}${rt} jolokia encrypt \"foo\"
      Q0gyMAGSwlWJdALzAAAAE448viN3l+rwa7W4RdkRI0V/VckAAAAA

  The key can also be the name of a file that contains a key:

      {h}${rt} echo hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w > /secrets/{bin}.key
      {h}${rt} jolokia decrypt --key /secrets/{bin}.key Q0gyMAGSwlWJdALzAAAAE448viN3l+rwa7W4RdkRI0V/VckAAAAA
      foo

  To set a key permanently, the recommended solution is to point the
  environment variable to a file:

      {h}${rt} echo hNbaua5cGlUNsEp4HSUTSJG7gl5IURQiTvnABzhFW4w > ~/.{bin}.key
      {h}${rt} echo '{key_env_var}=\"$HOME/.{bin}.key\"' >> ~/.bashrc

Message:
  The message can be passed on the command line:

      {h}${rt} jolokia encrypt \"bar\"
      Q0gyMAHPNRsLieAOAAAAE/ssTCh2zCm73t+aQf9aKNepgPkAAAAA

  Or from a file:

      {h}${rt} jolokia encrypt --file bar.txt
      Q0gyMAHPNRsLieAOAAAAE/ssTCh2zCm73t+aQf9aKNepgPkAAAAA

  Or via `stdin` (but the command line has precedence):

      {h}${rt} cat bar.txt | jolokia encrypt
      Q0gyMAHPNRsLieAOAAAAE/ssTCh2zCm73t+aQf9aKNepgPkAAAAA

  By definition, you can round-trip it:

      {h}${rt} jolokia encrypt \"hello, world\" -o encrypted.txt
      {h}${rt} jolokia decrypt -f encrypted.txt
      hello, world

Raw I/O:
  If you do not want base64 encoding, you can pass the `--raw` or `-r`
  flag. This makes sense for larger files for which you don't want the
  ~30% size overhead of base64.

      {h}${rt} jolokia encrypt --raw \"hello, world\" > hello.enc
      {h}${rt} cat hello.enc | jolokia decrypt --raw
      hello, world

  If you care more about size than about speed, consider compressing the
  output.

Compression:
  {package} offers built-in compression. It is not active by default
  because it makes encryption slower, but it you want it, you can pass
  the `--compress` or `-c` and `--extract` or `-x` to `encrypt` and
  `decrypt`, respectively.

      {h}${rt} jolokia encrypt --compress -r -f cat.png -o cat.comp
      {h}${rt} jolokia decrypt --extract -r -f cat.comp -o cat.png

  Compression uses Zlib with the highest compression setting (at the
  expense of speed). The reasoning is since it's optional, if you
  activate it, you probably really need it and so you get it in full.

  Note: `--extract` must be passed explicitly. If you try to `decrypt`
  a compressed message without that flag, it will fail.

  It makes sense to combine `--compress` with `--raw` to get the
  smallest file size possible.
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
