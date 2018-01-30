use failure::{self, Error, ResultExt};
use sodiumoxide::crypto::{box_, pwhash};
use std::fs::File;
use bincode;
use tempfile::NamedTempFile;
use std::path::Path;
use simple_crypt_util::pubkey_ext::PublicKeyExt;

use disk_formats::keyfile::Keyfile;

pub fn gen(
    keyfile: &str,
    password_ops_limit: Option<pwhash::OpsLimit>,
    password_mem_limit: Option<pwhash::MemLimit>,
) -> Result<(), Error> {
    let (public_key, secret_key) = box_::gen_keypair();

    let keyfile_data = Keyfile::encrypt(
        public_key,
        secret_key,
        password_ops_limit.unwrap_or(pwhash::OPSLIMIT_SENSITIVE),
        password_mem_limit.unwrap_or(pwhash::MEMLIMIT_SENSITIVE),
    )?;

    println!(
        "Your public key is: {}",
        keyfile_data.public_key.to_base64()
    );

    let mut keyfile = File::create(keyfile).context("unable to create secret key file")?;

    bincode::serialize_into(&mut keyfile, &keyfile_data, bincode::Infinite)
        .context("could not serialize secret key file")?;

    Ok(())
}

pub fn print_public_key(keyfile: &str) -> Result<(), Error> {
    let keyfile_data: Keyfile = {
        let mut file = File::open(keyfile).context("could not open secret key file")?;
        bincode::deserialize_from(&mut file, bincode::Infinite)
            .context("could not deserialize key file")?
    };

    println!("{}", keyfile_data.public_key.to_base64());

    Ok(())
}

pub fn change_password(
    keyfile: &str,
    password_ops_limit: Option<pwhash::OpsLimit>,
    password_mem_limit: Option<pwhash::MemLimit>,
) -> Result<(), Error> {
    let keyfile: &Path = keyfile.as_ref();
    let keyfile = keyfile
        .canonicalize()
        .context("unable to canonicalize keyfile path")?;

    let keyfile_dir = keyfile
        .parent()
        .ok_or_else(|| failure::err_msg("unable to get keyfile parent"))?;

    let keyfile_data: Keyfile = {
        let mut file = File::open(&keyfile).context("could not open secret key file")?;
        bincode::deserialize_from(&mut file, bincode::Infinite)
            .context("could not deserialize key file")?
    };

    println!("Decrypting current keyfile");
    let secret_key = keyfile_data.decrypt()?;

    println!();
    println!("Encrypting new keyfile");
    let new_keyfile_data = Keyfile::encrypt(
        keyfile_data.public_key,
        secret_key,
        password_ops_limit.unwrap_or(pwhash::OPSLIMIT_SENSITIVE),
        password_mem_limit.unwrap_or(pwhash::MEMLIMIT_SENSITIVE),
    )?;

    let mut temp_keyfile =
        NamedTempFile::new_in(keyfile_dir).context("unable to create temporary keyfile")?;

    bincode::serialize_into(&mut temp_keyfile, &new_keyfile_data, bincode::Infinite)
        .context("could not serialize secret key file")?;

    temp_keyfile
        .persist(&keyfile)
        .context("unable to overwrite old keyfile")?;

    Ok(())
}
