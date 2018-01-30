use sodiumoxide::crypto::{box_, pwhash, secretbox};

use simple_crypt_util::serde_arrays::{self, FixedArray};
use simple_crypt_util::serde_newtype;
use passwords;

fixed_value!(MagicHeader, 0xb41f7497, "magic header");
fixed_value!(FileVersion, 1, "secret key version");

#[derive(Serialize, Deserialize)]
pub struct Keyfile {
    pub magic_header: MagicHeader,
    pub version: FileVersion,
    #[serde(with = "serde_arrays")] pub public_key: box_::PublicKey,
    #[serde(with = "serde_arrays")] pub secret_key: box_::SecretKey, // Is encrypted when on the disk
    #[serde(with = "serde_newtype")] pub password_ops_limit: pwhash::OpsLimit,
    #[serde(with = "serde_newtype")] pub password_mem_limit: pwhash::MemLimit,
    #[serde(with = "serde_arrays")] pub password_salt: pwhash::Salt,
    #[serde(with = "serde_arrays")] pub secretbox_nonce: secretbox::Nonce,
    #[serde(with = "serde_arrays")] pub secretbox_tag: secretbox::Tag,
}

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

impl Keyfile {
    pub fn encrypt(
        public_key: box_::PublicKey,
        secret_key: box_::SecretKey,
        password_ops_limit: pwhash::OpsLimit,
        password_mem_limit: pwhash::MemLimit,
    ) -> Result<Keyfile, KeyfileError> {
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

        let password = passwords::read_password_twice()?;
        let secretbox_key = result.derive_key(&password)?;

        result.secretbox_tag = secretbox::seal_detached(
            &mut result.secret_key.0,
            &result.secretbox_nonce,
            &secretbox_key,
        );

        Ok(result)
    }

    fn derive_key(&self, password: &[u8]) -> Result<secretbox::Key, KeyfileError> {
        let mut secretbox_key = secretbox::Key([0; 32]);
        {
            pwhash::derive_key(
                &mut secretbox_key.0,
                &password,
                &self.password_salt,
                self.password_ops_limit,
                self.password_mem_limit,
            ).map_err(|()| KeyfileError::HashError)?;
        }

        Ok(secretbox_key)
    }

    pub fn decrypt(&self) -> Result<box_::SecretKey, KeyfileError> {
        loop {
            let password = passwords::read_password()?;
            let mut secret_key = self.secret_key.clone();

            if secretbox::open_detached(
                &mut secret_key.0,
                &self.secretbox_tag,
                &self.secretbox_nonce,
                &self.derive_key(&password)?,
            ).is_ok()
            {
                return Ok(secret_key);
            }

            println!("Sorry, try again.");
        }
    }
}
