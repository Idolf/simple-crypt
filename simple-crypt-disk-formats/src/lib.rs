extern crate bincode;
#[macro_use]
extern crate failure;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sodiumoxide;
#[macro_use]
extern crate static_assertions;

#[macro_use]
extern crate simple_crypt_util;

mod keyfile;
mod encrypted_file;

pub use keyfile::Keyfile;
pub use encrypted_file::EncryptedFile;
