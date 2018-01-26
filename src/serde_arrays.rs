use serde::ser::{SerializeTuple, Serializer};
use serde::de::{Deserializer, Error, SeqAccess, Visitor};
use std::fmt;
use std::marker::PhantomData;

pub trait FixedArray {
    const SIZE: usize;
    fn zero() -> Self;
    fn as_slice(&self) -> &[u8];
    fn as_slice_mut(&mut self) -> &mut [u8];
}

macro_rules! fixed_array {
    ($size:expr) => {
        impl FixedArray for [u8; $size] {
            const SIZE: usize = $size;
            fn zero() -> Self {
                [0; $size]
            }

            fn as_slice(&self) -> &[u8] {
                &self[..]
            }

            fn as_slice_mut(&mut self) -> &mut [u8] {
                &mut self[..]
            }
        }
    }
}

fixed_array!(16);
fixed_array!(24);
fixed_array!(32);

pub fn serialize<T, S>(values: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: FixedArray,
{
    let mut serializer = serializer.serialize_tuple(T::SIZE)?;
    for value in values.as_slice() {
        serializer.serialize_element(value)?;
    }
    serializer.end()
}

pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FixedArray,
{
    struct ArrayVisitor<T>(PhantomData<T>);
    impl<'de, T: FixedArray> Visitor<'de> for ArrayVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "expecting {} bytes", T::SIZE)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = T::zero();
            {
                let out = out.as_slice_mut();

                for (n, b) in out.iter_mut().enumerate() {
                    if let Some(next) = seq.next_element()? {
                        *b = next;
                    } else {
                        return Err(A::Error::invalid_length(n, &self));
                    }
                }
            }
            Ok(out)
        }
    }

    deserializer.deserialize_tuple(T::SIZE, ArrayVisitor(PhantomData))
}
