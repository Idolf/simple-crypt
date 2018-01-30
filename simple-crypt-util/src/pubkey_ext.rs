use serde_arrays::FixedArray;
use base64;
use failure;
use sodiumoxide::crypto::box_::PublicKey;

pub trait PublicKeyExt: Sized {
    fn from_base64(s: &str) -> Result<Self, failure::Error>;
    fn to_base64(&self) -> String;
}

impl PublicKeyExt for PublicKey {
    fn from_base64(s: &str) -> Result<Self, failure::Error> {
        let decoded = base64::decode(s)?;
        ensure!(decoded.len() == Self::SIZE, "invalid base64 length");

        let mut result = Self::zero();
        result.as_mut_slice().copy_from_slice(&decoded);
        Ok(result)
    }

    fn to_base64(&self) -> String {
        base64::encode(self.as_slice())
    }
}
