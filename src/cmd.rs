// TODO: For the `Result`s we don't use (yet).
#![allow(clippy::unnecessary_wraps)]

pub mod cli;

pub fn genkey() -> Result<(), i32> {
    println!("genkey");
    Ok(())
}

pub fn encrypt() -> Result<(), i32> {
    println!("encrypt");
    Ok(())
}

pub fn decrypt() -> Result<(), i32> {
    println!("decrypt");
    Ok(())
}
