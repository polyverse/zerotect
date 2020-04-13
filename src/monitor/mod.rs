pub mod dev_kmsg_reader;
mod event_parser;
mod kmsg;

use std::sync::mpsc::Sender;
use std::time::Duration;

use crate::events;

#[derive(Clone)]
pub struct MonitorConfig {
    pub verbosity: u8,
}

pub fn monitor(mc: MonitorConfig, sink: Sender<events::Event>) {
    if mc.verbosity > 0 {
        eprintln!("Monitor: Reading dmesg periodically to get kernel messages...");
    }

    let monitor_config = dev_kmsg_reader::KMsgReaderConfig {
        from_sequence_number: 0,
        flush_timeout: Duration::from_secs(1),
    };

    let kmsg_iterator: Box<dyn Iterator<Item = kmsg::KMsg> + Send> = Box::new(
        dev_kmsg_reader::DevKMsgReader::with_file(monitor_config, mc.verbosity),
    );

    let event_iterator = event_parser::EventParser::from_kmsg_iterator(kmsg_iterator, mc.verbosity);

    // infinite iterator
    for event in event_iterator {
        if let Err(e) = sink.send(event) {
            eprintln!("Monitor: Error occurred sending events. Receipent is dead. Closing monitor. Error: {}", e);
            return;
        }
    }
}
