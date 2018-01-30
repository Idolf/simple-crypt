extern crate bytes;
extern crate daemonize;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate nix;
extern crate serde;
extern crate serde_cbor;
#[macro_use]
extern crate serde_derive;
extern crate simple_crypt_util;
extern crate sodiumoxide;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_proto;
extern crate tokio_service;
extern crate tokio_uds;
extern crate void;

pub mod messages;
mod proto;
pub mod service;
mod service_impl;
mod keystore;
pub mod serve;
pub mod client;
