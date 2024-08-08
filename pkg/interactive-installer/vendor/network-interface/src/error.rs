use std::string::{FromUtf16Error, FromUtf8Error};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failed to execute `{0}`. Received error code `{1}`")]
    GetIfAddrsError(String, i32),
    #[error("Failed to execute `{0}`. Received error code `{1}`")]
    GetIfNameError(String, u32),
    #[error("Failed to parse bytes into UTF-8 characters. `{0}`")]
    ParseUtf8Error(FromUtf8Error),
    #[error("Failed to parse bytes into UTF-16 characters. `{0}`")]
    ParseUtf16Error(FromUtf16Error),
}

impl From<FromUtf8Error> for Error {
    fn from(error: FromUtf8Error) -> Self {
        Error::ParseUtf8Error(error)
    }
}

impl From<FromUtf16Error> for Error {
    fn from(error: FromUtf16Error) -> Self {
        Error::ParseUtf16Error(error)
    }
}
