use simple_crypt_daemon::service::DaemonService;
use simple_crypt_daemon::client::Client;
use simple_crypt_daemon::messages;
use simple_crypt_util::pubkey_ext::PublicKeyExt;
use failure::{Error, ResultExt};
use std::process::Command;
use sodiumoxide::crypto::box_::PublicKey;
use std::io::Write;

use arguments::DaemonCmd;
use disk_formats::keyfile::Keyfile;
use disk_formats::encrypted_file::EncryptedFile;
use std::fs::File;
use bincode;

pub fn handle(cmd: DaemonCmd) -> Result<(), Error> {
    match cmd {
        DaemonCmd::Start => {
            let _exit_code = Command::new("/proc/self/exe")
                .env(super::SIMPLE_CRYPT_DAEMON_MODE, "1")
                .spawn()
                .context("cannot spawn daemon process")?
                .wait()?;
            return Ok(());
        }
        _ => (),
    };

    let mut client = Client::new()?;

    match cmd {
        DaemonCmd::Start => unreachable!(),
        DaemonCmd::Stop => match client.shutdown()? {
            messages::ShutdownResponse::Ok => (),
        },
        DaemonCmd::AddKey { keyfile } => {
            let keyfile_data: Keyfile = {
                let mut file = File::open(keyfile).context("could not open secret key file")?;
                bincode::deserialize_from(&mut file, bincode::Infinite)
                    .context("could not deserialize key file")?
            };
            let secret_key = keyfile_data.decrypt()?;

            match client.add_key(keyfile_data.public_key, secret_key)? {
                messages::AddKeyResponse::Ok => (),
                messages::AddKeyResponse::OutOfCapacity => bail!("Key not added: out of capacity"),
            }
        }
        DaemonCmd::Decrypt {
            input_file,
            output_file,
        } => {
            let input_data: EncryptedFile = {
                let mut file = File::open(input_file).context("could not open input file")?;

                bincode::deserialize_from(&mut file, bincode::Infinite)
                    .context("could not deserialize input file")?
            };

            let precomputed_key = match client
                .precompute(input_data.public_key, input_data.ephemeral_public_key)?
            {
                messages::PrecomputeResponse::PrecomputeDone(precomputed_key) => precomputed_key,
                messages::PrecomputeResponse::KeyNotFound => {
                    bail!("Key {} not found", input_data.public_key.to_base64())
                }
            };

            let decrypted_data = input_data.decrypt_precomputed(&precomputed_key)?;

            let mut output_file = File::create(output_file).context("could not open output file")?;
            output_file
                .write_all(&decrypted_data)
                .context("could not write decrypted data")?;
        }
        DaemonCmd::RemoveKey { public_key } => {
            let public_key = PublicKey::from_base64(&public_key).context("invalid public key")?;
            match client.remove_key(public_key)? {
                messages::RemoveKeyResponse::Ok => (),
                messages::RemoveKeyResponse::KeyNotFound => bail!("Key not found"),
            }
        }
        DaemonCmd::List => {
            println!("Known keys:");
            for key in client.list()?.0 {
                println!("  {}", key.to_base64());
            }
        }
    }
    Ok(())
}
