// Copyright (c) 2019 Polyverse Corporation

pub mod dev_kmsg_reader;
mod event_parser;
mod kmsg;

use crate::events;
use crate::monitor::dev_kmsg_reader::{DevKMsgReader, DevKMsgReaderConfig};
use crate::monitor::event_parser::{EventParser, EventParserError};
use crate::monitor::kmsg::{KMsg, KMsgParserError};

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::mpsc::Sender;
use std::time::Duration;

#[derive(Clone)]
pub struct MonitorConfig {
    pub verbosity: u8,
}

#[derive(Debug)]
pub struct MonitorError(String);
impl Error for MonitorError {}
impl Display for MonitorError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "MonitorError:: {}", self.0)
    }
}
impl From<KMsgParserError> for MonitorError {
    fn from(err: KMsgParserError) -> MonitorError {
        MonitorError(format!("Inner KMsgParserError :: {}", err))
    }
}
impl From<EventParserError> for MonitorError {
    fn from(err: EventParserError) -> MonitorError {
        MonitorError(format!("Inner EventParserError :: {}", err))
    }
}

pub fn monitor(mc: MonitorConfig, sink: Sender<events::Event>) -> Result<(), MonitorError> {
    if mc.verbosity > 0 {
        eprintln!("Monitor: Reading dmesg periodically to get kernel messages...");
    }

    let monitor_config = DevKMsgReaderConfig {
        from_sequence_number: 0,
        flush_timeout: Duration::from_secs(1),
    };

    let kmsg_iterator: Box<dyn Iterator<Item = KMsg> + Send> =
        Box::new(DevKMsgReader::with_file(monitor_config, mc.verbosity)?);

    let event_iterator = EventParser::from_kmsg_iterator(kmsg_iterator, mc.verbosity)?;

    // infinite iterator
    for event in event_iterator {
        if let Err(e) = sink.send(event) {
            return Err(MonitorError(format!("Monitor: Error occurred sending events. Receipent is dead. Closing monitor. Error: {}", e)));
        }
    }

    return Err(MonitorError(
        "Monitor: Should have been unreachable code, but somehow we got here.".to_owned(),
    ));
}
