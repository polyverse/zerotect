// Copyright (c) 2019 Polyverse Corporation

pub mod dev_kmsg_reader;
mod event_parser;
mod kmsg;
pub mod rmesg_reader;

use crate::events;
use crate::monitor::dev_kmsg_reader::{DevKMsgReader, DevKMsgReaderConfig};
use crate::monitor::event_parser::{EventParser, EventParserError};
use crate::monitor::kmsg::{KMsgParserError, KMsgPtr};
use crate::monitor::rmesg_reader::{RMesgReader, RMesgReaderConfig};

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::mpsc::Sender;
use std::time::Duration;

#[derive(Clone)]
pub struct MonitorConfig {
    pub verbosity: u8,
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
        eprintln!("Monitor: Reading and parsing relevant kernel messages...");
    }

    let dev_msg_reader_config = DevKMsgReaderConfig {
        flush_timeout: Duration::from_secs(1),
        gobble_old_events: mc.gobble_old_events,
    };

    let kmsg_iterator: Box<dyn Iterator<Item = KMsgPtr> + Send> = match DevKMsgReader::with_file(
        dev_msg_reader_config,
        mc.verbosity,
    ) {
        Ok(dmesgreader) => Box::new(dmesgreader),
        Err(e) => {
            eprintln!(
                "Reading /dev/kmsg was a bad idea on this distribution: {:?}",
                e
            );
            eprintln!("Attempting to read directly from kernel using syscall 'klogctl' (through the rmesg crate)");

            let rmesg_reader_config = RMesgReaderConfig {
                poll_interval: Duration::from_secs(10),
                gobble_old_events: mc.gobble_old_events,
            };
            Box::new(RMesgReader::with_config(rmesg_reader_config, mc.verbosity)?)
        }
    };

    let event_iterator =
        EventParser::from_kmsg_iterator(kmsg_iterator, Duration::from_secs(1), mc.verbosity)?;

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
