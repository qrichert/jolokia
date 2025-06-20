mod utils;

use utils::{checksum, get_text_file, run};

#[test]
fn rotn_keygen() {
    let output = run(&["keygen", "-a", "rotn"]);
    dbg!(&output);

    assert_eq!(output.exit_code, 1);
}

#[test]
fn rotn_encrypt() {
    let output = run(&[
        "encrypt",
        "-a",
        "rotn",
        "-k",
        "13",
        "lorem ipsum dolor sit amet",
    ]);

    dbg!(&output);

    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, "yberz vcfhz qbybe fvg nzrg");
}

#[test]
fn rotn_decrypt() {
    let output = run(&[
        "decrypt",
        "-a",
        "rotn",
        "-k",
        "13",
        "yberz vcfhz qbybe fvg nzrg",
    ]);

    dbg!(&output);

    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, "lorem ipsum dolor sit amet");
}

#[test]
fn rotn_in_place_round_trip() {
    // Get initial file checksum.
    let file = get_text_file("rotn_in_place_round_trip");
    let file_path = file.to_string_lossy().to_string();
    dbg!(&file);
    let checksum_initial = checksum(&file);
    dbg!(&checksum_initial);

    // Encrypt file in-place.
    let output = run(&["encrypt", "-a", "rotn", "-k", "11", "-f", &file_path, "-i"]);
    dbg!(&output);

    // Ensure the file has changed.
    let checksum_encrypted = checksum(&file);
    dbg!(&checksum_encrypted);
    assert_ne!(checksum_encrypted, checksum_initial);

    // Decrypt file in-place.
    let output = run(&["decrypt", "-a", "rotn", "-k", "11", "-f", &file_path, "-i"]);
    dbg!(&output);

    // Ensure we've restored the original file.
    let checksum_decrypted = checksum(&file);
    dbg!(&checksum_decrypted);
    assert_eq!(checksum_decrypted, checksum_initial);
}
