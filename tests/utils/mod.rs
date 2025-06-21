#![allow(dead_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const JOLOKIA: &str = env!("CARGO_BIN_EXE_jolokia");
const TMP_DIR: &str = env!("CARGO_TARGET_TMPDIR");
pub const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");

#[derive(Debug)]
pub struct Output {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn get_test_file(file_name: &str) -> PathBuf {
    let cat_source = Path::new(FIXTURES_DIR).join("chat.webp");
    let cat_dest = Path::new(TMP_DIR)
        .join(file_name)
        .with_extension(cat_source.extension().unwrap());
    std::fs::copy(cat_source, &cat_dest).unwrap();
    cat_dest
}

pub fn get_text_file(file_name: &str) -> PathBuf {
    let lorem_source = Path::new(FIXTURES_DIR).join("lorem.txt");
    let lorem_dest = Path::new(TMP_DIR)
        .join(file_name)
        .with_extension(lorem_source.extension().unwrap());
    std::fs::copy(lorem_source, &lorem_dest).unwrap();
    lorem_dest
}

pub fn run(args: &[&str]) -> Output {
    let mut command = Command::new(JOLOKIA);
    command.env("NO_COLOR", "1");
    command.env_remove("PAGER");

    for arg in args {
        command.arg(arg);
    }

    let output = command.output().unwrap();

    Output {
        exit_code: output.status.code().unwrap(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

pub fn checksum(path: &Path) -> String {
    let payload = std::fs::read(path).unwrap();
    let hash = blake3::hash(&payload);
    // Hexadecimal is nicer to debug than plain bytes.
    hash.to_hex().to_string()
}
