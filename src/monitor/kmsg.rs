// Copyright (c) 2019 Polyverse Corporation

use crate::events;
use crate::system;
use chrono::{DateTime, Utc};
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(PartialEq, Debug)]
pub struct KMsg {
    pub timestamp: DateTime<Utc>,
    pub facility: events::LogFacility,
    pub level: events::LogLevel,
    pub message: String,
}

#[derive(Debug)]
pub enum KMsgParserError {
    BadSource(String),
    Generic(String),
}
impl Error for KMsgParserError {}
impl Display for KMsgParserError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "KMsgParserError:: {}",
            match self {
                KMsgParserError::BadSource(s) => format!(
                    "The lines iterator failed. Try another one, if available. (Inner Error: {})",
                    s
                ),
                KMsgParserError::Generic(s) => s.to_string(),
            }
        )
    }
}
impl From<timeout_iterator::TimeoutIteratorError> for KMsgParserError {
    fn from(err: timeout_iterator::TimeoutIteratorError) -> KMsgParserError {
        KMsgParserError::Generic(format!(
            "inner timeout_iterator::TimeoutIteratorError:: {}",
            err
        ))
    }
}
impl From<system::SystemStartTimeReadError> for KMsgParserError {
    fn from(err: system::SystemStartTimeReadError) -> KMsgParserError {
        KMsgParserError::Generic(format!("inner system::SystemStartTimeReadError:: {}", err))
    }
}
impl From<std::io::Error> for KMsgParserError {
    fn from(err: std::io::Error) -> KMsgParserError {
        KMsgParserError::Generic(format!("inner std::io::Error:: {}", err))
    }
}

#[derive(Debug)]
pub enum KMsgParsingError {
    Completed,
    SequenceNumTooOld,
    EmptyLine,
    Generic(String),
}
impl Error for KMsgParsingError {}
impl Display for KMsgParsingError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "KMsgParsingError:: {}",
            match self {
                KMsgParsingError::Completed => "Completed Parsing",
                KMsgParsingError::SequenceNumTooOld =>
                    "sequence number too old (we've parsed newer messages than these)",
                KMsgParsingError::EmptyLine => "Empty line",
                KMsgParsingError::Generic(s) => s,
            }
        )
    }
}
