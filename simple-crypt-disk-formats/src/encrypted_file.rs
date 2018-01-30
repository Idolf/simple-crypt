use sodiumoxide::crypto::box_;
use std::io::{Read, Write};
use bincode;
use failure::{Error, ResultExt};

use simple_crypt_util::serde_arrays::{self, FixedArray};

fixed_value!(MagicHeader, 0x26b1872d, "magic header");
fixed_value!(FileVersion, 1, "secret key version");

pub struct EncryptedFile {
    header: EncryptionHeader,
    encrypted_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct EncryptionHeader {
    pub magic_header: MagicHeader,
    pub version: FileVersion,
    #[serde(with = "serde_arrays")] pub box_nonce: box_::Nonce,
    #[serde(with = "serde_arrays")] pub public_key: box_::PublicKey,
    #[serde(with = "serde_arrays")] pub ephemeral_public_key: box_::PublicKey,
    #[serde(with = "serde_arrays")] pub box_tag: box_::Tag,
}

const HEADER_MEMORY_SIZE: usize = 24 + 32 + 32 + 16;
const HEADER_FILE_SIZE: usize = 4 + 4 + HEADER_MEMORY_SIZE;
assert_eq_size!(encrypted_file_size; EncryptionHeader, [u8; HEADER_MEMORY_SIZE]);
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
    pub fn read<R: Read>(mut read: R) -> Result<EncryptedFile, Error> {
        let mut header = [0u8; HEADER_FILE_SIZE];

        read.read_exact(&mut header)
            .context("could not read encryption header")?;

        let header = bincode::deserialize(&header).context("could not deserialize input file")?;

        let mut encrypted_data = Vec::new();
        read.read_to_end(&mut encrypted_data)
            .context("could not read encrypted data")?;

        Ok(EncryptedFile {
            header,
            encrypted_data,
        })
    }

    pub fn write<W: Write>(&self, mut write: W) -> Result<(), Error> {
        bincode::serialize_into(&mut write, &self.header, bincode::Infinite)
            .context("could not serialize encryption header")?;

        write
            .write_all(&self.encrypted_data)
            .context("could not write encrypted data")?;

        Ok(())
    }

    pub fn encrypt(public_key: box_::PublicKey, mut data: Vec<u8>) -> EncryptedFile {
        let (ephemeral_public_key, ephemeral_secret_key) = box_::gen_keypair();

        data.push(0x80);
        while data.len() % PADDING != 0 {
            data.push(0);
        }

        let mut header = EncryptionHeader {
            magic_header: MagicHeader,
            version: FileVersion,
            public_key: public_key,
            ephemeral_public_key: ephemeral_public_key,
            box_tag: box_::Tag::zero(),
            box_nonce: box_::gen_nonce(),
        };

        header.box_tag = box_::seal_detached(
            &mut data,
            &header.box_nonce,
            &header.public_key,
            &ephemeral_secret_key,
        );

        EncryptedFile {
            header,
            encrypted_data: data,
        }
    }

    pub fn decrypt(
        self,
        public_key: box_::PublicKey,
        secret_key: box_::SecretKey,
    ) -> Result<Vec<u8>, DecryptError> {
        if self.header.public_key != public_key {
            Err(DecryptError::WrongPublicKey)
        } else {
            let precomputed_key = box_::precompute(&self.header.ephemeral_public_key, &secret_key);

            Ok(self.decrypt_precomputed(&precomputed_key)?)
        }
    }

    pub fn decrypt_precomputed(
        self,
        precomputed_key: &box_::PrecomputedKey,
    ) -> Result<Vec<u8>, PrecomputedDecryptError> {
        let mut data = self.encrypted_data;

        if box_::open_detached_precomputed(
            &mut data,
            &self.header.box_tag,
            &self.header.box_nonce,
            &precomputed_key,
        ).is_err()
        {
            return Err(PrecomputedDecryptError::SignatureError);
        }

        while Some(&0) == data.last() {
            data.pop().unwrap();
        }

        if data.pop() != Some(0x80) {
            return Err(PrecomputedDecryptError::PaddingError);
        }

        Ok(data)
    }

    pub fn public_key(&self) -> &box_::PublicKey {
        &self.header.public_key
    }

    pub fn ephemeral_public_key(&self) -> &box_::PublicKey {
        &self.header.ephemeral_public_key
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
            let (header, data) = EncryptionHeader::encrypt(public_key, data);
            let size = bincode::serialized_size(&header);
            assert_eq!(size as usize, HEADER_FILE_SIZE);
            assert_eq!(data.len(), (n | (PADDING - 1)) + 1);
        }
    }
}
