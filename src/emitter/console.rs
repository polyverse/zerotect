use crate::emitter;
use crate::events;
use serde_json;

#[derive(Debug, Clone)]
pub enum Format {
    UserFriendlyText,
    JSON,
}

#[derive(Clone)]
pub struct ConsoleConfig {
    pub console_format: Format,
}

pub struct Console {
    config: ConsoleConfig,
}

impl emitter::Emitter for Console {
    fn emit(&self, event: &events::Event) {
        match self.config.console_format {
            Format::UserFriendlyText => println!("{}", event),
            Format::JSON => match serde_json::to_string(&event) {
                Ok(json) => println!("{}", json),
                Err(e) => println!("Unable to Serialize event to JSON: {}", e),
            },
        }
    }
}

pub fn new(config: ConsoleConfig) -> Console {
    Console { config }
}
