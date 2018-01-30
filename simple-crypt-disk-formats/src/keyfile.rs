use sodiumoxide::crypto::{box_, pwhash, secretbox};

use failure::{Error, ResultExt};
use simple_crypt_util::serde_arrays::{self, FixedArray};
use simple_crypt_util::serde_newtype;
use simple_crypt_util::pwhash_limits;
use simple_crypt_util::passwords;
use bincode;
use std::io::{Read, Write};

fixed_value!(MagicHeader, 0xb41f7497, "magic header");
fixed_value!(FileVersion, 1, "secret key version");

pub struct Keyfile {
    header: KeyfileHeader,
}

#[derive(Serialize, Deserialize)]
struct KeyfileHeader {
    pub magic_header: MagicHeader,
    pub version: FileVersion,
    #[serde(with = "serde_arrays")] pub public_key: box_::PublicKey,
    #[serde(with = "serde_arrays")] pub secret_key: box_::SecretKey, // Is encrypted when on the disk
    #[serde(with = "serde_newtype")] pub password_ops_limit: pwhash_limits::OpsLimit,
    #[serde(with = "serde_newtype")] pub password_mem_limit: pwhash_limits::MemLimit,
    #[serde(with = "serde_arrays")] pub password_salt: pwhash::Salt,
    #[serde(with = "serde_arrays")] pub secretbox_nonce: secretbox::Nonce,
    #[serde(with = "serde_arrays")] pub secretbox_tag: secretbox::Tag,
}

const KEYFILE_MEMORY_SIZE: usize = 32 + 32 + 8 + 8 + 32 + 24 + 16;
const KEYFILE_FILE_SIZE: usize = 4 + 4 + KEYFILE_MEMORY_SIZE;
assert_eq_size!(keyfile_size; KeyfileHeader, [u8; KEYFILE_MEMORY_SIZE]);
const_assert!(nice_sized_keyfile; KEYFILE_FILE_SIZE % 16 == 0);

#[derive(Fail, Debug)]
#[fail(display = "Could not compute hash (out of resources?)")]
pub struct HashError;

#[derive(Fail, Debug)]
pub enum KeyfileError {
    #[fail(display = "Could not compute hash (out of resources?)")] HashError,
    #[fail(display = "Error while entering password")]
    PasswordError(#[cause] passwords::PasswordError),
}

impl From<passwords::PasswordError> for KeyfileError {
    fn from(error: passwords::PasswordError) -> KeyfileError {
        KeyfileError::PasswordError(error)
    }
}

impl From<HashError> for KeyfileError {
    fn from(error: HashError) -> KeyfileError {
        let HashError = error;
        KeyfileError::HashError
    }
}

impl Keyfile {
    pub fn read<R: Read>(mut read: R) -> Result<Keyfile, Error> {
        let mut header = [0u8; KEYFILE_FILE_SIZE];

        read.read_exact(&mut header)
            .context("could not read keyfile")?;

        ensure!(read.bytes().next().is_none(), "keyfile has the wrong size");

        let header = bincode::deserialize(&header).context("could not deserialize keyfile")?;

        Ok(Keyfile { header })
    }

    pub fn write<W: Write>(&self, mut write: W) -> Result<(), Error> {
        bincode::serialize_into(&mut write, &self.header, bincode::Infinite)
            .context("could not serialize keyfile")?;

        Ok(())
    }

    pub fn encrypt(
        public_key: box_::PublicKey,
        secret_key: box_::SecretKey,
        password_ops_limit: pwhash_limits::OpsLimit,
        password_mem_limit: pwhash_limits::MemLimit,
        password: &[u8],
    ) -> Result<Keyfile, HashError> {
        let mut header = KeyfileHeader {
            magic_header: MagicHeader,
            version: FileVersion,
            public_key: public_key,
            secret_key: secret_key,
            password_salt: pwhash::gen_salt(),
            password_ops_limit: password_ops_limit,
            password_mem_limit: password_mem_limit,
            secretbox_nonce: secretbox::gen_nonce(),
            secretbox_tag: secretbox::Tag::zero(),
        };
        let secretbox_key = header.derive_key(&password)?;

        header.secretbox_tag = secretbox::seal_detached(
            &mut header.secret_key.0,
            &header.secretbox_nonce,
            &secretbox_key,
        );

        Ok(Keyfile { header })
    }

    pub fn decrypt(&self, password: &[u8]) -> Result<Option<box_::SecretKey>, HashError> {
        let mut secret_key = self.header.secret_key.clone();

        if secretbox::open_detached(
            &mut secret_key.0,
            &self.header.secretbox_tag,
            &self.header.secretbox_nonce,
            &self.header.derive_key(&password)?,
        ).is_ok()
        {
            Ok(Some(secret_key))
        } else {
            Ok(None)
        }
    }

    pub fn decrypt_interactive(&self) -> Result<box_::SecretKey, KeyfileError> {
        loop {
            if let Some(secret_key) = self.decrypt(&passwords::read_password()?)? {
                return Ok(secret_key);
            }

            println!("Sorry, try again.");
        }
    }

    pub fn public_key(&self) -> &box_::PublicKey {
        &self.header.public_key
    }
}

impl KeyfileHeader {
    fn derive_key(&self, password: &[u8]) -> Result<secretbox::Key, HashError> {
        let mut secretbox_key = secretbox::Key([0; 32]);
        {
            pwhash::derive_key(
                &mut secretbox_key.0,
                &password,
                &self.password_salt,
                self.password_ops_limit.into(),
                self.password_mem_limit.into(),
            ).map_err(|()| HashError)?;
        }

        Ok(secretbox_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{self, Rng};
    use bincode;

    fn gen_password<R: Rng>(mut rng: R) -> Vec<u8> {
        (0..rng.gen_range(0usize, 128usize))
            .map(|_| rng.gen())
            .collect()
    }

    #[test]
    fn test_length() {
        let mut rng = rand::thread_rng();
        let (public_key, secret_key) = box_::gen_keypair();

        let keyfile = Keyfile::encrypt(
            public_key,
            secret_key,
            pwhash_limits::OpsLimit(1),
            pwhash_limits::MemLimit(1),
            &gen_password(&mut rng),
        ).unwrap();
        let size = bincode::serialized_size(&keyfile);
        assert_eq!(size as usize, KEYFILE_FILE_SIZE);
    }

    fn gen_change_seen<F: FnMut() -> Keyfile>(mut gen_keyfile: F) -> [bool; KEYFILE_FILE_SIZE] {
        let mut gen_keyfile = move || {
            let res = bincode::serialize(&gen_keyfile(), bincode::Infinite).unwrap();
            assert_eq!(res.len(), KEYFILE_FILE_SIZE);
            res
        };
        let reference = gen_keyfile();

        let mut change_seen = [false; KEYFILE_FILE_SIZE];

        for _ in 0..16 {
            let cur = gen_keyfile();
            for (n, (reference_byte, cur_byte)) in reference.iter().zip(cur.iter()).enumerate() {
                if reference_byte != cur_byte {
                    change_seen[n] = true;
                }
            }
        }
        change_seen
    }

    #[test]
    fn test_change_constant() {
        let mut rng = rand::thread_rng();
        let (public_key, secret_key) = box_::gen_keypair();
        let password = gen_password(&mut rng);

        let change_seen = gen_change_seen(|| {
            Keyfile::encrypt(
                public_key.clone(),
                secret_key.clone(),
                pwhash_limits::OpsLimit(1),
                pwhash_limits::MemLimit(1),
                &password,
            ).unwrap()
        });

        assert!(
            change_seen.as_ref()
                == [
            false, false, false, false, // magic_header
            false, false, false, false, // version
            false, false, false, false, false, false, false, false, // public_key
            false, false, false, false, false, false, false, false, // public_key
            false, false, false, false, false, false, false, false, // public_key
            false, false, false, false, false, false, false, false, // public_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            false, false, false, false, false, false, false, false, // ops_limit
            false, false, false, false, false, false, false, false, // mem_limit
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_tag
            true, true, true, true, true, true, true, true, // secretbox_tag
       ].as_ref()
        );
    }

    #[test]
    fn test_change_keys() {
        let mut rng = rand::thread_rng();
        let password = gen_password(&mut rng);

        let change_seen = gen_change_seen(|| {
            let (public_key, secret_key) = box_::gen_keypair();
            Keyfile::encrypt(
                public_key.clone(),
                secret_key.clone(),
                pwhash_limits::OpsLimit(1),
                pwhash_limits::MemLimit(1),
                &password,
            ).unwrap()
        });

        assert!(
            change_seen.as_ref()
                == [
            false, false, false, false, // magic_header
            false, false, false, false, // version
            true, true, true, true, true, true, true, true, // public_key
            true, true, true, true, true, true, true, true, // public_key
            true, true, true, true, true, true, true, true, // public_key
            true, true, true, true, true, true, true, true, // public_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            false, false, false, false, false, false, false, false, // ops_limit
            false, false, false, false, false, false, false, false, // mem_limit
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_tag
            true, true, true, true, true, true, true, true, // secretbox_tag
       ].as_ref()
        );
    }

    #[test]
    fn test_change_password() {
        let mut rng = rand::thread_rng();
        let (public_key, secret_key) = box_::gen_keypair();

        let change_seen = gen_change_seen(|| {
            let password = gen_password(&mut rng);
            Keyfile::encrypt(
                public_key.clone(),
                secret_key.clone(),
                pwhash_limits::OpsLimit(1),
                pwhash_limits::MemLimit(1),
                &password,
            ).unwrap()
        });

        assert!(
            change_seen.as_ref()
                == [
            false, false, false, false, // magic_header
            false, false, false, false, // version
            false, false, false, false, false, false, false, false, // public_key
            false, false, false, false, false, false, false, false, // public_key
            false, false, false, false, false, false, false, false, // public_key
            false, false, false, false, false, false, false, false, // public_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            false, false, false, false, false, false, false, false, // ops_limit
            false, false, false, false, false, false, false, false, // mem_limit
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_tag
            true, true, true, true, true, true, true, true, // secretbox_tag
       ].as_ref()
        );
    }

    #[test]
    fn test_change_ops() {
        let mut rng = rand::thread_rng();
        let (public_key, secret_key) = box_::gen_keypair();

        let change_seen = gen_change_seen(|| {
            let password = gen_password(&mut rng);
            Keyfile::encrypt(
                public_key.clone(),
                secret_key.clone(),
                pwhash_limits::OpsLimit(rng.gen_range(0, 65535)),
                pwhash_limits::MemLimit(1),
                &password,
            ).unwrap()
        });

        assert!(
            change_seen.as_ref()
                == [
            false, false, false, false, // magic_header
            false, false, false, false, // version
            false, false, false, false, false, false, false, false, // public_key
            false, false, false, false, false, false, false, false, // public_key
            false, false, false, false, false, false, false, false, // public_key
            false, false, false, false, false, false, false, false, // public_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, false, false, false, false, false, false, // ops_limit
            false, false, false, false, false, false, false, false, // mem_limit
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_tag
            true, true, true, true, true, true, true, true, // secretbox_tag
       ].as_ref()
        );
    }

    #[test]
    fn test_change_mem() {
        let mut rng = rand::thread_rng();
        let (public_key, secret_key) = box_::gen_keypair();

        let change_seen = gen_change_seen(|| {
            let password = gen_password(&mut rng);
            Keyfile::encrypt(
                public_key.clone(),
                secret_key.clone(),
                pwhash_limits::OpsLimit(1),
                pwhash_limits::MemLimit(rng.gen_range(0, 65535)),
                &password,
            ).unwrap()
        });

        assert!(
            change_seen.as_ref()
                == [
            false, false, false, false, // magic_header
            false, false, false, false, // version
            false, false, false, false, false, false, false, false, // public_key
            false, false, false, false, false, false, false, false, // public_key
            false, false, false, false, false, false, false, false, // public_key
            false, false, false, false, false, false, false, false, // public_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            false, false, false, false, false, false, false, false, // ops_limit
            true, true, false, false, false, false, false, false, // mem_limit
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_tag
            true, true, true, true, true, true, true, true, // secretbox_tag
       ].as_ref()
        );
    }

    #[test]
    fn test_change_all() {
        let mut rng = rand::thread_rng();

        let change_seen = gen_change_seen(|| {
            let (public_key, secret_key) = box_::gen_keypair();
            let password = gen_password(&mut rng);
            Keyfile::encrypt(
                public_key.clone(),
                secret_key.clone(),
                pwhash_limits::OpsLimit(rng.gen_range(0, 65535)),
                pwhash_limits::MemLimit(rng.gen_range(0, 65535)),
                &password,
            ).unwrap()
        });

        assert!(
            change_seen.as_ref()
                == [
            false, false, false, false, // magic_header
            false, false, false, false, // version
            true, true, true, true, true, true, true, true, // public_key
            true, true, true, true, true, true, true, true, // public_key
            true, true, true, true, true, true, true, true, // public_key
            true, true, true, true, true, true, true, true, // public_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, true, true, true, true, true, true, // secret_key
            true, true, false, false, false, false, false, false, // ops_limit
            true, true, false, false, false, false, false, false, // mem_limit
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // password_salt
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_nonce
            true, true, true, true, true, true, true, true, // secretbox_tag
            true, true, true, true, true, true, true, true, // secretbox_tag
       ].as_ref()
        );
    }
}
