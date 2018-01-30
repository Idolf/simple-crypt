use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sodiumoxide::crypto::{box_, pwhash, secretbox};

use serde_arrays::FixedArray;

pub trait Newtype {
    type Inner;

    fn from_inner(Self::Inner) -> Self;
    fn inner(&self) -> &Self::Inner;
    fn inner_mut(&mut self) -> &mut Self::Inner;
}

impl<T> FixedArray for T
where
    T: Newtype,
    T::Inner: FixedArray,
{
    const SIZE: usize = T::Inner::SIZE;

    fn zero() -> T {
        T::from_inner(T::Inner::zero())
    }

    fn as_slice(&self) -> &[u8] {
        self.inner().as_slice()
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.inner_mut().as_mut_slice()
    }
}

macro_rules! newtype {
    ($outer:path, $inner:ty) => {
        impl ::serde_newtype::Newtype for $outer {
            type Inner = $inner;

            fn from_inner(value: Self::Inner) -> Self {
                $outer(value)
            }

            fn inner(&self) -> &Self::Inner {
                &self.0
            }

            fn inner_mut(&mut self) -> &mut Self::Inner {
                &mut self.0
            }
        }
    }
}

macro_rules! newtype_array {
    ($outer:path, $size:expr) => {
        newtype!($outer, [u8; $size]);
    }
}

pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Newtype,
    T::Inner: Serialize,
{
    value.inner().serialize(serializer)
}

pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Newtype,
    T::Inner: Deserialize<'de>,
{
    T::Inner::deserialize(deserializer).map(T::from_inner)
}

newtype_array!(box_::PublicKey, box_::PUBLICKEYBYTES);
newtype_array!(box_::SecretKey, box_::SECRETKEYBYTES);
newtype_array!(box_::PrecomputedKey, box_::PRECOMPUTEDKEYBYTES);
newtype_array!(box_::Tag, box_::MACBYTES);
newtype_array!(box_::Nonce, box_::NONCEBYTES);
newtype_array!(pwhash::Salt, pwhash::SALTBYTES);
newtype_array!(secretbox::Nonce, secretbox::NONCEBYTES);
newtype_array!(secretbox::Tag, secretbox::MACBYTES);

newtype!(pwhash::OpsLimit, usize);
newtype!(pwhash::MemLimit, usize);
