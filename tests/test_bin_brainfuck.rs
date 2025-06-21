mod utils;

use std::path::Path;

use utils::{checksum, get_text_file, run};

#[test]
fn brainfuck_keygen() {
    let output = run(&["keygen", "-a", "brainfuck"]);
    dbg!(&output);

    assert_eq!(output.exit_code, 1);
}

#[test]
fn brainfuck_encrypt() {
    let output = run(&["encrypt", "-a", "brainfuck", "lorem ipsum dolor sit amet"]);

    dbg!(&output);

    assert_eq!(output.exit_code, 0);
    assert_eq!(
        output.stdout,
        "\
>++++++++[>++++++++++++<-]>+<<++++++++++[>++++++++++<-]>+>>++++[>+++++++
++++<-]++++++++++++++++++++++++++++++++>[>+>+<<-]>>[<<+>>-]<++>+++++++++
+<<<<+++++++++++.+++.+++.<.>-----.>.<----.+++++++.+++.++.--------.>.<---
------.+++++++++++.---.+++.+++.>.<+.----------.+++++++++++.>.<<----.++++
>-------.<.>+++++++."
    );
}

#[test]
fn brainfuck_decrypt() {
    let output = run(&[
        "decrypt",
        "-a",
        "brainfuck",
        "\
>++++++++[>++++++++++++<-]>+<<++++++++++[>++++++++++<-]>+>>++++[>+++++++
++++<-]++++++++++++++++++++++++++++++++>[>+>+<<-]>>[<<+>>-]<++>+++++++++
+<<<<+++++++++++.+++.+++.<.>-----.>.<----.+++++++.+++.++.--------.>.<---
------.+++++++++++.---.+++.+++.>.<+.----------.+++++++++++.>.<<----.++++
>-------.<.>+++++++.",
    ]);

    dbg!(&output);

    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, "lorem ipsum dolor sit amet");
}

#[test]
fn brainfuck_regular_round_trip() {
    // Get initial file checksum.
    let file = get_text_file("brainfuck_regular_round_trip");
    let file_path = file.to_string_lossy().to_string();
    let file_path_encrypted = file_path.clone() + ".enc";
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Encrypt file in-place.
    let output = run(&[
        "encrypt",
        "-a",
        "brainfuck",
        "-f",
        &file_path,
        "-o",
        &file_path_encrypted,
    ]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(Path::new(&file_path_encrypted));

    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&[
        "decrypt",
        "-a",
        "brainfuck",
        "-f",
        &file_path_encrypted,
        "-o",
        &file_path,
    ]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}

#[test]
fn brainfuck_raw_round_trip() {
    // Get initial file checksum.
    let file = get_text_file("brainfuck_raw_round_trip");
    let file_path = file.to_string_lossy().to_string();
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Encrypt file in-place.
    let output = run(&["encrypt", "-r", "-a", "brainfuck", "-f", &file_path, "-i"]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(&file);
    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&["decrypt", "-r", "-a", "brainfuck", "-f", &file_path, "-i"]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}

#[test]
fn brainfuck_implicit_in_place_round_trip() {
    // Get initial file checksum.
    let file = get_text_file("brainfuck_implicit_in_place_round_trip");
    let file_path = file.to_string_lossy().to_string();
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Encrypt file in-place.
    let output = run(&[
        "encrypt",
        "-a",
        "brainfuck",
        "-f",
        &file_path,
        "-o",
        &file_path,
    ]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(&file);
    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&[
        "decrypt",
        "-a",
        "brainfuck",
        "-f",
        &file_path,
        "-o",
        &file_path,
    ]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}

#[test]
fn brainfuck_in_place_round_trip() {
    // Get initial file checksum.
    let file = get_text_file("brainfuck_in_place_round_trip");
    let file_path = file.to_string_lossy().to_string();
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Encrypt file in-place.
    let output = run(&["encrypt", "-a", "brainfuck", "-f", &file_path, "-i"]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(&file);
    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&["decrypt", "-a", "brainfuck", "-f", &file_path, "-i"]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}
