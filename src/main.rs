#[macro_use]
extern crate arrayref;
extern crate base64;
extern crate bincode;
extern crate clap;
#[macro_use]
extern crate failure;
extern crate libc;
extern crate nix;
extern crate serde;
#[macro_use]
extern crate serde_derive;
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
#[macro_use]
mod serde_fixed_value;
mod serde_arrays;
mod serde_newtype;
mod passwords;

// Dealing with arguments and files
mod disk_formats;
mod arguments;

// Implemented commands
mod keys;
mod files;

pub use disk_formats::encrypted_file::EncryptedFile;

fn lock_stack<T>(bytes: usize, value: &T) -> Result<(), Error> {
    let ptr: usize = value as *const T as usize;
    let first_addr = (ptr - bytes) & !0xfff;
    let last_addr = (ptr | 0xfff) + 1;
    let length = last_addr - first_addr;

    const MLOCK_ONFAULT: libc::c_int = 1;

    ensure!(
        unsafe { libc::syscall(libc::SYS_mlock2, first_addr, length, MLOCK_ONFAULT) } == 0,
        "could not lock memory: {}",
        nix::Errno::last().desc()
    );

    Ok(())
}

fn run() -> Result<(), Error> {
    let x: u32 = 0;
    lock_stack(16 * 1024, &x)?; // lock 16 kilobytes of stack
    sodiumoxide::init();

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
