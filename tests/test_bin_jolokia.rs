mod utils;

use utils::run;

#[test]
fn short_help() {
    let output = run(&["-h"]);
    dbg!(&output);

    assert_eq!(output.exit_code, 0);

    assert!(output.stdout.contains(env!("CARGO_PKG_DESCRIPTION")));

    assert!(output.stdout.contains("keygen"));
    assert!(output.stdout.contains("encrypt"));
    assert!(output.stdout.contains("decrypt"));

    assert!(output.stdout.contains("<MESSAGE>"));
    assert!(output.stdout.contains("-k, --key"));
    assert!(output.stdout.contains("-r, --raw"));
    assert!(output.stdout.contains("-f, --file"));
    assert!(output.stdout.contains("-i, --in-place"));
    assert!(output.stdout.contains("-o, --output"));

    assert!(output.stdout.contains("-h, --help"));
    assert!(output.stdout.contains("-V, --version"));

    assert!(output.stdout.contains("`jolokia --help`"));
}

#[test]
fn long_help() {
    let output = run(&["--help"]);
    dbg!(&output);

    assert_eq!(output.exit_code, 0);

    // Short help.
    assert!(output.stdout.contains(env!("CARGO_PKG_DESCRIPTION")));

    assert!(output.stdout.contains("What does jolokia do?"));

    assert!(output.stdout.contains("Algorithms:"));
    assert!(output.stdout.contains("ChaCha20-Poly1305"));
    assert!(output.stdout.contains("HPKE"));
    assert!(output.stdout.contains("ROT-n"));
}

#[test]
fn version() {
    let output = run(&["--version"]);
    dbg!(&output);

    assert_eq!(output.exit_code, 0);

    assert!(output.stdout.contains(env!("CARGO_PKG_NAME")));
    assert!(output.stdout.contains(env!("CARGO_PKG_VERSION")));
}
