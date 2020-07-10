use std::convert::From;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug)]
pub enum FormatError {
    JsonError(String),
}
impl Error for FormatError {}
impl Display for FormatError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            FormatError::JsonError(s) => write!(f, "FormatError::JsonError: {}", s),
        }
    }
}
impl From<serde_json::Error> for FormatError {
    fn from(value: serde_json::Error) -> FormatError {
        FormatError::JsonError(format!("{}", value))
    }
}
