use sodiumoxide::crypto::box_;
use failure::{Error, ResultExt};
use std::fs;
use std::io::{Read, Write};
use std::fs::File;
use simple_crypt_util::pubkey_ext::PublicKeyExt;

use simple_crypt_disk_formats::{EncryptedFile, Keyfile};

pub fn encrypt(public_key: &str, input_file: &str, output_file: &str) -> Result<(), Error> {
    let public_key = box_::PublicKey::from_base64(&public_key).context("invalid public key")?;
    let mut input_file = fs::File::open(input_file).context("could not open input file")?;
    let mut output_file = fs::File::create(output_file).context("could not create output file")?;

    let mut input_data = Vec::new();

    if let Ok(metadata) = input_file.metadata() {
        input_data.reserve_exact(metadata.len() as usize)
    }
    input_file
        .read_to_end(&mut input_data)
        .context("could not read input file")?;

    EncryptedFile::encrypt(public_key, input_data).write(&mut output_file)?;

    Ok(())
}

pub fn decrypt(keyfile: &str, input_file: &str, output_file: &str) -> Result<(), Error> {
    let keyfile_data =
        Keyfile::read(File::open(keyfile).context("could not open secret key file")?)?;

    let input_file = File::open(input_file).context("could not open input file")?;
    let input_data = EncryptedFile::read(input_file)?;

    let secret_key = keyfile_data.decrypt_interactive()?;

    let decrypted_data = input_data.decrypt(*keyfile_data.public_key(), secret_key)?;

    let mut output_file = File::create(output_file).context("could not open output file")?;
    output_file
        .write_all(&decrypted_data)
        .context("could not write decrypted data")?;

    Ok(())
}
