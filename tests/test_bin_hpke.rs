mod utils;

use utils::{checksum, get_test_file, run};

// This is the most wholistic test of the entire test suite. It tests
// in-place ciphering, base64 encoding, streaming, HPKE, and ChaCha.
// The whole pipeline is tested on its most sensitive parts.
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
