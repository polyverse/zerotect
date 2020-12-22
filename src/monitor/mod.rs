// Copyright (c) 2019 Polyverse Corporation

mod event_parser;

use crate::events;
use crate::monitor::event_parser::{EventParser, EventParserError};
use futures::stream::Stream;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::time::Duration;

#[derive(Clone)]
pub struct MonitorConfig {
    pub verbosity: u8,
    pub hostname: Option<String>,
    pub gobble_old_events: bool,
}

#[derive(Debug)]
pub struct MonitorError(String);
impl Error for MonitorError {}
impl Display for MonitorError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "MonitorError:: {}", self.0)
    }
}
impl From<EventParserError> for MonitorError {
    fn from(err: EventParserError) -> MonitorError {
        MonitorError(format!("Inner EventParserError :: {}", err))
    }
}

pub async fn monitor(mc: MonitorConfig) -> Result<Box<dyn Stream<Item = events::Version>>, MonitorError> {
    if mc.verbosity > 0 {
        eprintln!("Monitor: Reading and parsing relevant kernel messages...");
    }

    EventParser::new(
        Duration::from_secs(1),
        mc.verbosity,
        mc.hostname,
    ).await?;
}
