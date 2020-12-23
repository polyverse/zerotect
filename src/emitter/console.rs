// Copyright (c) 2019 Polyverse Corporation

use crate::emitter;
use crate::events;
use crate::formatter::{new as new_formatter, Formatter};
use crate::params;
use async_trait::async_trait;

pub struct Console {
    config: params::ConsoleConfig,
    formatter: Box<dyn Formatter>,
}

#[async_trait]
impl emitter::Emitter for Console {
    async fn emit(&mut self, event: &events::Event) {
        match self.formatter.format(event) {
            Ok(formattedstr) => println!("{}", formattedstr),
            Err(e) => eprintln!("Error formatting event to {:?}: {}", self.config.format, e),
        }
    }
}

pub fn new(config: params::ConsoleConfig) -> Console {
    let formatter = new_formatter(&config.format);

    Console { config, formatter }
}
