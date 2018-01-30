use sodiumoxide::crypto::box_;
use std::fmt;

use simple_crypt_util::serde_arrays::{self, FixedArray};
use simple_crypt_util::pubkey_ext::PublicKeyExt;
use super::keyfile;

fixed_value!(MagicHeader, 0x26b1872d, "magic header");
fixed_value!(FileVersion, 1, "secret key version");

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedFile {
    pub magic_header: MagicHeader,
    pub version: FileVersion,
    #[serde(with = "serde_arrays")] pub box_nonce: box_::Nonce,
    #[serde(with = "serde_arrays")] pub public_key: box_::PublicKey,
    #[serde(with = "serde_arrays")] pub ephemeral_public_key: box_::PublicKey,
    #[serde(with = "serde_arrays")] pub box_tag: box_::Tag,
    pub data: Vec<u8>,
}

#[derive(Fail, Debug)]
pub enum PrecomputedDecryptError {
    SignatureError,
    PaddingError,
}

impl fmt::Display for PrecomputedDecryptError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PrecomputedDecryptError::PaddingError => {
                write!(formatter, "The file padding was incorrect")
            }
            PrecomputedDecryptError::SignatureError => write!(
                formatter,
                "The signature for the file did not match the content"
            ),
        }
    }
}

#[derive(Fail, Debug)]
pub enum DecryptError {
    InvalidPublicKey {
        from_encrypted: box_::PublicKey,
        from_keyfile: box_::PublicKey,
    },
    SignatureError,
    PaddingError,
    KeyfileError(#[cause] keyfile::KeyfileError),
}

impl fmt::Display for DecryptError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecryptError::InvalidPublicKey {
                ref from_encrypted,
                ref from_keyfile,
            } => {
                write!(formatter, "The public keys did not match. ")?;
                write!(
                    formatter,
                    "Encrypted file was destined for {}, while keyfile contained {}.",
                    from_encrypted.to_base64(),
                    from_keyfile.to_base64()
                )
            }
            DecryptError::SignatureError => write!(
                formatter,
                "The signature for the file did not match the content"
            ),
            DecryptError::PaddingError => write!(formatter, "The file padding was incorrect"),
            DecryptError::KeyfileError(..) => write!(formatter, "Error while decrypting keyfile"),
        }
    }
}

impl From<keyfile::KeyfileError> for DecryptError {
    fn from(error: keyfile::KeyfileError) -> DecryptError {
        DecryptError::KeyfileError(error)
    }
}

impl From<PrecomputedDecryptError> for DecryptError {
    fn from(error: PrecomputedDecryptError) -> DecryptError {
        match error {
            PrecomputedDecryptError::PaddingError => DecryptError::PaddingError,
            PrecomputedDecryptError::SignatureError => DecryptError::SignatureError,
        }
    }
}

const PADDING: usize = 32;

impl EncryptedFile {
    pub fn encrypt(public_key: box_::PublicKey, mut data: Vec<u8>) -> EncryptedFile {
        let (ephemeral_public_key, ephemeral_secret_key) = box_::gen_keypair();

        data.push(0x80);
        while data.len() % PADDING != 0 {
            data.push(0);
        }

        let mut result = EncryptedFile {
            magic_header: MagicHeader,
            version: FileVersion,
            public_key: public_key,
            ephemeral_public_key: ephemeral_public_key,
            box_tag: box_::Tag::zero(),
            box_nonce: box_::gen_nonce(),
            data: data,
        };

        result.box_tag = box_::seal_detached(
            &mut result.data,
            &result.box_nonce,
            &result.public_key,
            &ephemeral_secret_key,
        );

        result
    }

    pub fn decrypt(self, keyfile: &keyfile::Keyfile) -> Result<Vec<u8>, DecryptError> {
        if self.public_key != keyfile.public_key {
            Err(DecryptError::InvalidPublicKey {
                from_encrypted: self.public_key,
                from_keyfile: keyfile.public_key,
            })
        } else {
            let secret_key = keyfile.decrypt()?;
            let precomputed_key = box_::precompute(&self.ephemeral_public_key, &secret_key);

            Ok(self.decrypt_precomputed(&precomputed_key)?)
        }
    }

    pub fn decrypt_precomputed(
        mut self,
        precomputed_key: &box_::PrecomputedKey,
    ) -> Result<Vec<u8>, PrecomputedDecryptError> {
        if box_::open_detached_precomputed(
            &mut self.data,
            &self.box_tag,
            &self.box_nonce,
            &precomputed_key,
        ).is_err()
        {
            return Err(PrecomputedDecryptError::SignatureError);
        }

        while Some(&0) == self.data.last() {
            self.data.pop().unwrap();
        }

        if self.data.pop() != Some(0x80) {
            return Err(PrecomputedDecryptError::PaddingError);
        }

        Ok(self.data)
    }
}
