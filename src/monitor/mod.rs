pub mod dev_kmsg_reader;
mod event_parser;
mod kmsg;

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::mpsc::Sender;
use std::time::Duration;

use crate::events;

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
impl From<dev_kmsg_reader::KMsgParserError> for MonitorError {
    fn from(err: dev_kmsg_reader::KMsgParserError) -> MonitorError {
        MonitorError(format!("Inner KMsgParserError :: {}", err))
    }
}
impl From<event_parser::EventParserError> for MonitorError {
    fn from(err: event_parser::EventParserError) -> MonitorError {
        MonitorError(format!("Inner EventParserError :: {}", err))
    }
}

pub fn monitor(mc: MonitorConfig, sink: Sender<events::Event>) -> Result<(), MonitorError> {
    if mc.verbosity > 0 {
        eprintln!("Monitor: Reading dmesg periodically to get kernel messages...");
    }

    let monitor_config = dev_kmsg_reader::KMsgReaderConfig {
        from_sequence_number: 0,
        flush_timeout: Duration::from_secs(1),
    };

    let kmsg_iterator: Box<dyn Iterator<Item = kmsg::KMsg> + Send> = Box::new(
        dev_kmsg_reader::DevKMsgReader::with_file(monitor_config, mc.verbosity)?,
    );

    let event_iterator =
        event_parser::EventParser::from_kmsg_iterator(kmsg_iterator, mc.verbosity)?;

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
