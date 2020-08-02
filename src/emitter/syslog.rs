// Copyright (c) 2020 Polyverse Corporation

use crate::emitter;
use crate::events;
use crate::formatter::{new as new_formatter, Formatter};
use crate::params;


pub struct Logger {
    config: params::SyslogConfig,
    formatter: Box<dyn Formatter>,
}

impl emitter::Emitter for Logger {
    fn emit(&self, event: &events::Version) {
        match self.formatter.format(event) {
            Ok(formattedstr) => info!("{}", formattedstr),
            Err(e) => eprintln!("Error formatting event to {:?}: {}", self.config.format, e),
        }
    }
}

pub fn new(config: params::SyslogConfig) -> Logger {
    let formatter = new_formatter(&config.format);
    Logger { config, formatter }
}
