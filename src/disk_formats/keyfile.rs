use sodiumoxide::crypto::{box_, pwhash, secretbox};

use simple_crypt_util::serde_arrays::{self, FixedArray};
use simple_crypt_util::serde_newtype;
use simple_crypt_util::pwhash_limits;
use passwords;

fixed_value!(MagicHeader, 0xb41f7497, "magic header");
fixed_value!(FileVersion, 1, "secret key version");

#[derive(Serialize, Deserialize)]
pub struct Keyfile {
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

pub const KEYFILE_MEMORY_SIZE: usize = 32 + 32 + 8 + 8 + 32 + 24 + 16;
pub const KEYFILE_FILE_SIZE: usize = 4 + 4 + KEYFILE_MEMORY_SIZE;
assert_eq_size!(keyfile_size; Keyfile, [u8; KEYFILE_MEMORY_SIZE]);
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
    pub fn encrypt(
        public_key: box_::PublicKey,
        secret_key: box_::SecretKey,
        password_ops_limit: pwhash_limits::OpsLimit,
        password_mem_limit: pwhash_limits::MemLimit,
        password: &[u8],
    ) -> Result<Keyfile, HashError> {
        let mut result = Keyfile {
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
        let secretbox_key = result.derive_key(&password)?;

        result.secretbox_tag = secretbox::seal_detached(
            &mut result.secret_key.0,
            &result.secretbox_nonce,
            &secretbox_key,
        );

        Ok(result)
    }

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

    pub fn decrypt(&self, password: &[u8]) -> Result<Option<box_::SecretKey>, HashError> {
        let mut secret_key = self.secret_key.clone();

        if secretbox::open_detached(
            &mut secret_key.0,
            &self.secretbox_tag,
            &self.secretbox_nonce,
            &self.derive_key(&password)?,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{self, Rng};
    use bincode;

    #[test]
    fn test_length() {
        let mut rng = rand::thread_rng();
        let (public_key, secret_key) = box_::gen_keypair();

        let keyfile = Keyfile::encrypt(
            public_key,
            secret_key,
            pwhash_limits::OpsLimit(1),
            pwhash_limits::MemLimit(1),
            &(0..rng.gen::<usize>() % 128)
                .map(|_| rng.gen())
                .collect::<Vec<u8>>(),
        ).unwrap();
        let size = bincode::serialized_size(&keyfile);
        assert_eq!(size as usize, KEYFILE_FILE_SIZE);
    }
}
