extern crate bincode;
extern crate clap;
#[macro_use]
extern crate failure;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[cfg(feature = "simple-crypt-daemon")]
extern crate simple_crypt_daemon;
#[macro_use]
extern crate simple_crypt_util;
extern crate sodiumoxide;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate tempfile;
extern crate termion;

use failure::Error;
use structopt::StructOpt;
use std::process;
use sodiumoxide::crypto::pwhash;

// Common utilities
mod passwords;
mod disk_formats;
mod arguments;

// Implemented commands
mod keys;
mod files;
#[cfg(feature = "simple-crypt-daemon")]
mod daemon;

pub use disk_formats::encrypted_file::EncryptedFile;

#[cfg(feature = "simple-crypt-daemon")]
const SIMPLE_CRYPT_DAEMON_MODE: &str = "SIMPLE_CRYPT_DAEMON_MODE";

fn run() -> Result<(), Error> {
    #[cfg(feature = "simple-crypt-daemon")]
    {
        if std::env::var(SIMPLE_CRYPT_DAEMON_MODE) == Ok("1".to_string()) {
            return simple_crypt_daemon::serve::serve();
        }
    }

    let x: u32 = 0;

    // lock 16k of stack below, and 1k above
    simple_crypt_util::memory_security::lock_memory(16 * 1024, 1024, &x)?;
    // lock down /proc and prevent core dumps
    simple_crypt_util::memory_security::set_no_dumpable()?;

    sodiumoxide::init();

    run_arguments()
}

pub fn run_arguments() -> Result<(), Error> {
    use arguments::*;
    match Cmd::from_args() {
        Cmd::Keys {
            cmd:
                KeyCmd::Gen {
                    keyfile,
                    password_ops_limit,
                    password_mem_limit,
                },
        } => keys::gen(
            &keyfile,
            password_ops_limit.map(pwhash::OpsLimit),
            password_mem_limit.map(pwhash::MemLimit),
        ),
        Cmd::Keys {
            cmd: KeyCmd::PrintPublickey { keyfile },
        } => keys::print_public_key(&keyfile),
        Cmd::Keys {
            cmd:
                KeyCmd::ChangePassword {
                    keyfile,
                    password_ops_limit,
                    password_mem_limit,
                },
        } => keys::change_password(
            &keyfile,
            password_ops_limit.map(pwhash::OpsLimit),
            password_mem_limit.map(pwhash::MemLimit),
        ),
        Cmd::Encrypt {
            public_key,
            input_file,
            output_file,
        } => files::encrypt(&public_key, &input_file, &output_file),
        Cmd::Decrypt {
            keyfile,
            input_file,
            output_file,
        } => files::decrypt(&keyfile, &input_file, &output_file),
        #[cfg(feature = "simple-crypt-daemon")]
        Cmd::Daemon { cmd } => daemon::handle(cmd),
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Failure:\n  {}", err);
        let mut fail: &failure::Fail = err.cause();
        let mut n = 0;
        while let Some(cause) = fail.cause() {
            eprintln!("Cause #{}:\n  {}", n, cause);
            n += 1;
            fail = cause;
        }

        eprintln!("{}", err.backtrace());

        process::exit(1);
    }
}
