use sodiumoxide::crypto::box_;

use simple_crypt_util::serde_arrays::{self, FixedArray};

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
    #[serde(with = "serde_arrays::vec")] pub data: Vec<u8>,
}

pub const HEADER_MEMORY_SIZE: usize = 24 + 32 + 32 + 16;
pub const HEADER_FILE_SIZE: usize = 4 + 4 + HEADER_MEMORY_SIZE;
assert_eq_size!(encrypted_file_size; EncryptedFile, ([u8; HEADER_MEMORY_SIZE], Vec<u8>));
const_assert!(nice_sized_header; HEADER_FILE_SIZE % 16 == 0);

#[derive(Fail, Debug)]
pub enum PrecomputedDecryptError {
    #[fail(display = "The signature for the file did not match the content")] SignatureError,
    #[fail(display = "The file padding was incorrect")] PaddingError,
}

#[derive(Fail, Debug)]
pub enum DecryptError {
    #[fail(display = "The supplied public key did not match the one from the file")] WrongPublicKey,
    #[fail(display = "The signature for the file did not match the content")] SignatureError,
    #[fail(display = "The file padding was incorrect")] PaddingError,
}

impl From<PrecomputedDecryptError> for DecryptError {
    fn from(error: PrecomputedDecryptError) -> DecryptError {
        match error {
            PrecomputedDecryptError::PaddingError => DecryptError::PaddingError,
            PrecomputedDecryptError::SignatureError => DecryptError::SignatureError,
        }
    }
}

const PADDING: usize = 64;

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

    pub fn decrypt(
        self,
        public_key: box_::PublicKey,
        secret_key: box_::SecretKey,
    ) -> Result<Vec<u8>, DecryptError> {
        if self.public_key != public_key {
            Err(DecryptError::WrongPublicKey)
        } else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{self, Rng};
    use bincode;

    #[test]
    fn test_length() {
        let mut rng = rand::thread_rng();
        let (public_key, _secret_key) = box_::gen_keypair();
        for n in 0..2048 {
            println!("{}", n);
            let data = (0..n).map(|_| rng.gen()).collect();
            let size = bincode::serialized_size(&EncryptedFile::encrypt(public_key, data));
            let padded_size = (n | (PADDING - 1)) + 1;
            let expected_size = padded_size + HEADER_FILE_SIZE;
            assert_eq!(size as usize, expected_size);
        }
    }
}
