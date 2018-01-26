macro_rules! fixed_value {
    ($ident:ident, $value:expr, $name:expr) => {
        #[derive(Default, Debug)]
        pub struct $ident;
        impl ::serde::Serialize for $ident {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where S: ::serde::Serializer,
            {
                const VALUE: u32 = $value;
                VALUE.serialize(serializer)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $ident {
            fn deserialize<D>(deserializer: D) -> Result<$ident, D::Error>
        where
            D: ::serde::Deserializer<'de>,
            {
                const VALUE: u32 = $value;
                const NAME: &'static str = $name;

                use serde::de::{Visitor, Error, Unexpected};

                struct MyVisitor;
                impl<'de> Visitor<'de> for MyVisitor {
                    type Value = $ident;
                    fn expecting(&self, formatter: &mut ::std::fmt::Formatter)
                                 -> ::std::fmt::Result {
                        write!(formatter, "{} (with expected value {:?})", NAME, VALUE)
                    }

                    fn visit_u32<E>(self, v: u32) -> Result<$ident, E>
                    where E: Error {
                        if v == VALUE {
                            Ok($ident)
                        } else {
                            Err(E::invalid_value(Unexpected::Unsigned(v as u64), &self))
                        }
                    }
                }

                deserializer.deserialize_u32(MyVisitor)
            }
        }

    }
}
