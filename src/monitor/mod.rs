pub mod dmesg_poller;
mod event_parser;
mod kmsg;

use std::sync::mpsc::{Sender};

use crate::events;

pub enum MonitorType {
    DMesgPoller(dmesg_poller::DMesgPollerConfig),
    DevKMsgReader,
}

pub struct MonitorConfig {
    pub monitor_type: MonitorType,
    pub verbosity: u8,
}

pub fn monitor(mc: MonitorConfig, sink: Sender<events::Event>) {
    if mc.verbosity > 0 { eprintln!("Monitor: Reading dmesg periodically to get kernel messages..."); }


    let kmsg_iterator = match mc.monitor_type {
         MonitorType::DMesgPoller(c) => dmesg_poller::DMesgPoller::with_poll_settings(c, mc.verbosity),
         MonitorType::DevKMsgReader => return
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

