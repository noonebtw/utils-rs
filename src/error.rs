use std::fmt;
use std::io;

#[cfg(feature = "windows")]
use winapi::um::errhandlingapi::GetLastError;

pub mod prelude {
    pub use crate::error::{Error, Result};
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "windows")]
    Win32Error(u32),
    NullPointer,
    Exhausted,
    DefaultError,
    IoError(io::Error),
}

impl Error {
    #[cfg(feature = "windows")]
    pub fn win32_error() -> Self {
        Self::Win32Error(unsafe { GetLastError() })
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Display not implemented for this Error, use Debug")
    }
}
