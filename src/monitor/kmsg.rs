// Copyright (c) 2019 Polyverse Corporation

use crate::events;
use crate::system;
use chrono::{DateTime, Utc};
use rmesg;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

pub type KMsgPtr = Box<KMsg>;

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
impl From<rmesg::error::RMesgError> for KMsgParserError {
    fn from(err: rmesg::error::RMesgError) -> KMsgParserError {
        KMsgParserError::Generic(format!("inner rmesg::error::RMesgError:: {}", err))
    }
}

#[derive(Debug)]
pub enum KMsgParsingError {
    Completed,
    EventTooOld,
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
                KMsgParsingError::EventTooOld =>
                    "Event too old due to timestamp or sequence number (we've parsed newer messages than these)",
                KMsgParsingError::EmptyLine => "Empty line",
                KMsgParsingError::Generic(s) => s,
            }
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::mem;

    #[test]
    fn measure_size_of_event() {
        // cost to move Kmsg
        assert_eq!(40, mem::size_of::<KMsg>());
        // vs ptr
        assert_eq!(8, mem::size_of::<KMsgPtr>());
    }
}
