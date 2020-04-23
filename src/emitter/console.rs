// Copyright (c) 2019 Polyverse Corporation

use crate::emitter;
use crate::events;
use crate::params;
use serde_json;

pub struct Console {
    config: params::ConsoleConfig,
}

impl emitter::Emitter for Console {
    fn emit(&self, event: &events::Event) {
        match self.config.format {
            params::ConsoleOutputFormat::Text => println!("{}", event),
            params::ConsoleOutputFormat::JSON => match serde_json::to_string(&event) {
                Ok(json) => println!("{}", json),
                Err(e) => println!("Unable to Serialize event to JSON: {}", e),
            },
        }
    }
}

pub fn new(config: params::ConsoleConfig) -> Console {
    Console { config }
}
