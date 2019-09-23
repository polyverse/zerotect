pub mod dev_kmsg_reader;
mod event_parser;
mod kmsg;

use std::sync::mpsc::{Sender};

use crate::events;

pub enum MonitorType {
    DevKMsgReader(dev_kmsg_reader::KMsgReaderConfig),
}

pub struct MonitorConfig {
    pub monitor_type: MonitorType,
    pub verbosity: u8,
}

pub fn monitor(mc: MonitorConfig, sink: Sender<events::Event>) {
    if mc.verbosity > 0 { eprintln!("Monitor: Reading dmesg periodically to get kernel messages..."); }


    let kmsg_iterator: Box<dyn Iterator<Item = kmsg::KMsg>> = match mc.monitor_type {
         MonitorType::DevKMsgReader(c) => Box::new(dev_kmsg_reader::DevKMsgReader::with_file(c, mc.verbosity)),
    };

    let event_iterator = event_parser::EventParser::from_kmsg_iterator(kmsg_iterator, mc.verbosity);

    // infinite iterator
    for event in event_iterator {
        if let Err(e) = sink.send(event) {
            eprintln!("Monitor: Error occurred sending events. Receipent is dead. Closing monitor. Error: {}", e);
            return;
        }
    }
}

