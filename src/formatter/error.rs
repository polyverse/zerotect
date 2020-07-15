use rust_cef;
use std::convert::From;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug)]
pub enum FormatError {
    JsonError(String),
    CefConversionError(String),
}
impl Error for FormatError {}
impl Display for FormatError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self {
            FormatError::JsonError(s) => write!(f, "FormatError::JsonError: {}", s),
            FormatError::CefConversionError(s) => {
                write!(f, "FormatError::CefConversionError: {}", s)
            }
        }
    }
}
impl From<serde_json::Error> for FormatError {
    fn from(value: serde_json::Error) -> FormatError {
        FormatError::JsonError(format!("{}", value))
    }
}
impl From<rust_cef::CefConversionError> for FormatError {
    fn from(value: rust_cef::CefConversionError) -> FormatError {
        FormatError::CefConversionError(format!("{}", value))
    }
}
