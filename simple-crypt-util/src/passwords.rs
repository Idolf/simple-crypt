use termion::input::TermRead;
use std::io::{self, stdin, stdout, Write};

#[derive(Fail, Debug)]
#[fail(display = "Aborted while entering password.")]
pub enum PasswordError {
    #[fail(display = "Aborted while entering password.")] Aborted,
    #[fail(display = "IO error: {}", _0)] IoError(#[cause] io::Error),
}

impl From<io::Error> for PasswordError {
    fn from(error: io::Error) -> PasswordError {
        PasswordError::IoError(error)
    }
}

pub fn read_password_prompt(prompt: &[u8]) -> Result<Vec<u8>, PasswordError> {
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();

    stdout.write_all(prompt)?;
    stdout.flush()?;

    match stdin.read_passwd(&mut stdout)? {
        None => Err(PasswordError::Aborted),
        Some(password) => {
            stdout.write_all(b"\n")?;
            Ok(password.into_bytes())
        }
    }
}

pub fn read_password() -> Result<Vec<u8>, PasswordError> {
    read_password_prompt(b"Password: ")
}

pub fn read_password_twice() -> Result<Vec<u8>, PasswordError> {
    loop {
        let password1 = read_password_prompt(b"Password: ")?;
        let password2 = read_password_prompt(b"Re-enter password: ")?;

        if password1 == password2 {
            return Ok(password1);
        }

        println!("");
        println!("Passwords do not match. Try again.");
        println!("");
    }
}
