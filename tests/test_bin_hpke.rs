mod utils;

use std::path::Path;

use jolokia::traits::Base64Decode;

use utils::{checksum, get_test_file, run};

#[test]
fn hpke_keygen() {
    let output = run(&["keygen", "-a", "hpke"]);
    dbg!(&output);
    let (pubkey, privkey) = output.stdout.split_once('\n').unwrap();
    dbg!(pubkey, privkey);

    let pubkey = pubkey.base64_decode().unwrap();
    let privkey = privkey.base64_decode().unwrap();

    assert!(pubkey.len() == 32);
    assert!(privkey.len() == 32);
}

#[test]
fn hpke_encrypt() {
    let output = run(&[
        "encrypt",
        "-a",
        "hpke",
        "-k",
        "QfSivWNCgT8oeOoTuAWK4cat1PpSCU1GhxXwcfxjlFE",
        "lorem ipsum dolor sit amet",
    ]);

    dbg!(&output);

    assert_eq!(output.exit_code, 0);
    assert!(!output.stdout.is_empty());
    assert!(output.stdout.base64_decode().is_ok());
}

#[test]
fn hpke_decrypt() {
    let output = run(&[
        "decrypt",
        "-a",
        "hpke",
        "-k",
        "KkQpXGsXQTmGD0UI0Z8wejnmw8UAg+YRMgviV1x+abA",
        "SFBLRQEAIF8k55ZEOO6wlScUZSntiWqT1dP1T/bMhywp3kEkxQB5Q0gyMAHU1a6oIPlVAAAAKlbKzpjJk0EHu/6gTn/7DllxCLS74Gvad+MojxSnkQFr/PlfB6iToal23AAAAAA",
    ]);

    dbg!(&output);

    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, "lorem ipsum dolor sit amet");
}

#[test]
fn hpke_regular_round_trip() {
    // Get initial file checksum.
    let file = get_test_file("hpke_regular_round_trip");
    let file_path = file.to_string_lossy().to_string();
    let file_path_encrypted = file_path.clone() + ".enc";
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Generate keypair.
    let output = run(&["keygen", "-a", "hpke"]);
    dbg!(&output);
    let (pubkey, privkey) = output.stdout.split_once('\n').unwrap();
    dbg!(pubkey, privkey);

    // Encrypt file in-place.
    let output = run(&[
        "encrypt",
        "-a",
        "hpke",
        "-k",
        pubkey,
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
        "hpke",
        "-k",
        privkey,
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
fn hpke_raw_round_trip() {
    // Get initial file checksum.
    let file = get_test_file("hpke_raw_round_trip");
    let file_path = file.to_string_lossy().to_string();
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Generate keypair.
    let output = run(&["keygen", "-a", "hpke"]);
    dbg!(&output);
    let (pubkey, privkey) = output.stdout.split_once('\n').unwrap();
    dbg!(pubkey, privkey);

    // Encrypt file in-place.
    let output = run(&[
        "encrypt", "-r", "-a", "hpke", "-k", pubkey, "-f", &file_path, "-i",
    ]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(&file);
    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&[
        "decrypt", "-r", "-a", "hpke", "-k", privkey, "-f", &file_path, "-i",
    ]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}

// This is the most wholistic test of the entire test suite. It tests
// in-place ciphering (and detection), base64 encoding, streaming, HPKE,
// and ChaCha. The whole pipeline is tested on its most sensitive parts.
#[test]
fn hpke_implicit_in_place_round_trip() {
    // Get initial file checksum.
    let file = get_test_file("hpke_implicit_in_place_round_trip");
    let file_path = file.to_string_lossy().to_string();
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Generate keypair.
    let output = run(&["keygen", "-a", "hpke"]);
    dbg!(&output);
    let (pubkey, privkey) = output.stdout.split_once('\n').unwrap();
    dbg!(pubkey, privkey);

    // Encrypt file in-place.
    let output = run(&[
        "encrypt", "-a", "hpke", "-k", pubkey, "-f", &file_path, "-o", &file_path,
    ]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(&file);
    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&[
        "decrypt", "-a", "hpke", "-k", privkey, "-f", &file_path, "-o", &file_path,
    ]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}

#[test]
fn hpke_in_place_round_trip() {
    // Get initial file checksum.
    let file = get_test_file("hpke_in_place_round_trip");
    let file_path = file.to_string_lossy().to_string();
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Generate keypair.
    let output = run(&["keygen", "-a", "hpke"]);
    dbg!(&output);
    let (pubkey, privkey) = output.stdout.split_once('\n').unwrap();
    dbg!(pubkey, privkey);

    // Encrypt file in-place.
    let output = run(&[
        "encrypt", "-a", "hpke", "-k", pubkey, "-f", &file_path, "-i",
    ]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(&file);
    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&[
        "decrypt", "-a", "hpke", "-k", privkey, "-f", &file_path, "-i",
    ]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}

#[test]
fn hpke_default_key_round_trip() {
    // Get initial file checksum.
    let file = get_test_file("hpke_default_key_round_trip");
    let file_path = file.to_string_lossy().to_string();
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Encrypt file in-place.
    let output = run(&["encrypt", "-a", "hpke", "-f", &file_path, "-i"]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(&file);
    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&["decrypt", "-a", "hpke", "-f", &file_path, "-i"]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}
