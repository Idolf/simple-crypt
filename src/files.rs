use base64;
use sodiumoxide::crypto::box_;
use failure::{Error, ResultExt};
use std::fs;
use std::io::{Read, Write};
use bincode;
use std::fs::File;

use disk_formats::keyfile::Keyfile;
use disk_formats::encrypted_file::EncryptedFile;

pub fn encrypt(public_key: &str, input_file: &str, output_file: &str) -> Result<(), Error> {
    let public_key = base64::decode(public_key).context("invalid public key")?;
    ensure!(
        public_key.len() == box_::PUBLICKEYBYTES,
        "invalid public key"
    );

    let public_key = box_::PublicKey(*array_ref!(&public_key, 0, box_::PUBLICKEYBYTES));
    let mut input_file = fs::File::open(input_file).context("could not open input file")?;
    let mut output_file = fs::File::create(output_file).context("could not create output file")?;

    let mut input_data = Vec::new();

    if let Ok(metadata) = input_file.metadata() {
        input_data.reserve_exact(metadata.len() as usize)
    }
    input_file
        .read_to_end(&mut input_data)
        .context("could not read input file")?;

    let encrypted = EncryptedFile::encrypt(public_key, input_data);

    bincode::serialize_into(&mut output_file, &encrypted, bincode::Infinite)
        .context("could not serialize secret key file")?;

    Ok(())
}

pub fn decrypt(keyfile: &str, input_file: &str, output_file: &str) -> Result<(), Error> {
    let keyfile_data: Keyfile = {
        let mut file = File::open(keyfile).context("could not open secret key file")?;
        bincode::deserialize_from(&mut file, bincode::Infinite)
            .context("could not deserialize key file")?
    };

    let input_data: EncryptedFile = {
        let mut file = File::open(input_file).context("could not open input file")?;

        bincode::deserialize_from(&mut file, bincode::Infinite)
            .context("could not deserialize input file")?
    };

    let decrypted_data = input_data.decrypt(&keyfile_data)?;

    let mut output_file = File::create(output_file).context("could not open output file")?;
    output_file
        .write_all(&decrypted_data)
        .context("could not write decrypted data")?;

    Ok(())
}
