
use std::sync::mpsc::{Receiver};
use crate::events;

pub struct EmitterConfig {
    pub verbosity: u8,
}

pub fn emit(_ec: EmitterConfig, source: Receiver<events::Event>) {
    eprintln!("Emitter: Printing all received messages to screen");

    loop {
        match source.recv() {
            Ok(message) => eprintln!("Emitter: Received message: {}", message),
            Err(e) => {
                eprintln!("Emitter: Received an error from messages channel. No more possibility of messages coming in. Closing thread. Error: {}", e);
                return;
            }
        }
    }
}