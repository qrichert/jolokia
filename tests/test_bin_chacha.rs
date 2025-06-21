mod utils;

use std::path::Path;

use jolokia::traits::Base64Decode;

use utils::{checksum, get_test_file, run};

#[test]
fn chacha_keygen() {
    let output = run(&["keygen", "-a", "chacha"]);
    dbg!(&output);
    let key = output.stdout;
    dbg!(&key);

    let key = key.base64_decode().unwrap();

    assert!(key.len() == 32);
}

#[test]
fn chacha_encrypt() {
    let output = run(&[
        "encrypt",
        "-a",
        "chacha",
        "-k",
        "9zcb2kyrHdHG0w7yGUs7dcYK7YWKAuatm77FgoLoO2A",
        "lorem ipsum dolor sit amet",
    ]);

    dbg!(&output);

    assert_eq!(output.exit_code, 0);
    assert!(!output.stdout.is_empty());
    assert!(output.stdout.base64_decode().is_ok());
}

#[test]
fn chacha_decrypt() {
    let output = run(&[
        "decrypt",
        "-a",
        "chacha",
        "-k",
        "9zcb2kyrHdHG0w7yGUs7dcYK7YWKAuatm77FgoLoO2A",
        "Q0gyMAE+uvjw+kK0AAAAKiWpFnhyfdVM5v6z0a2g5eEEVM2FaqguZxjjF7g2CYSncAcmpACrlLkCpQAAAAA",
    ]);

    dbg!(&output);

    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, "lorem ipsum dolor sit amet");
}

#[test]
fn chacha_regular_round_trip() {
    // Get initial file checksum.
    let file = get_test_file("chacha_regular_round_trip");
    let file_path = file.to_string_lossy().to_string();
    let file_path_encrypted = file_path.clone() + ".enc";
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Generate key.
    let output = run(&["keygen", "-a", "chacha"]);
    dbg!(&output);
    let key = output.stdout;
    dbg!(&key);

    // Encrypt file in-place.
    let output = run(&[
        "encrypt",
        "-a",
        "chacha",
        "-k",
        &key,
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
        "chacha",
        "-k",
        &key,
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
fn chacha_raw_round_trip() {
    // Get initial file checksum.
    let file = get_test_file("chacha_raw_round_trip");
    let file_path = file.to_string_lossy().to_string();
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Generate key.
    let output = run(&["keygen", "-a", "chacha"]);
    dbg!(&output);
    let key = output.stdout;
    dbg!(&key);

    // Encrypt file in-place.
    let output = run(&[
        "encrypt", "-r", "-a", "chacha", "-k", &key, "-f", &file_path, "-i",
    ]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(&file);
    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&[
        "decrypt", "-r", "-a", "chacha", "-k", &key, "-f", &file_path, "-i",
    ]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}

#[test]
fn chacha_implicit_in_place_round_trip() {
    // Get initial file checksum.
    let file = get_test_file("chacha_implicit_in_place_round_trip");
    let file_path = file.to_string_lossy().to_string();
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Generate key.
    let output = run(&["keygen", "-a", "chacha"]);
    dbg!(&output);
    let key = output.stdout;
    dbg!(&key);

    // Encrypt file in-place.
    let output = run(&[
        "encrypt", "-a", "chacha", "-k", &key, "-f", &file_path, "-o", &file_path,
    ]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(&file);
    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&[
        "decrypt", "-a", "chacha", "-k", &key, "-f", &file_path, "-o", &file_path,
    ]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}

#[test]
fn chacha_in_place_round_trip() {
    // Get initial file checksum.
    let file = get_test_file("chacha_in_place_round_trip");
    let file_path = file.to_string_lossy().to_string();
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Generate key.
    let output = run(&["keygen", "-a", "chacha"]);
    dbg!(&output);
    let key = output.stdout;
    dbg!(&key);

    // Encrypt file in-place.
    let output = run(&[
        "encrypt", "-a", "chacha", "-k", &key, "-f", &file_path, "-i",
    ]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(&file);
    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&[
        "decrypt", "-a", "chacha", "-k", &key, "-f", &file_path, "-i",
    ]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}

#[test]
fn chacha_default_key_round_trip() {
    // Get initial file checksum.
    let file = get_test_file("chacha_default_key_round_trip");
    let file_path = file.to_string_lossy().to_string();
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Encrypt file in-place.
    let output = run(&["encrypt", "-a", "chacha", "-f", &file_path, "-i"]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(&file);
    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&["decrypt", "-a", "chacha", "-f", &file_path, "-i"]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}
