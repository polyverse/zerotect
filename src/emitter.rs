
use std::sync::mpsc::{Receiver};
use crate::events;

pub struct EmitterConfig {
}

pub fn emit(_ec: EmitterConfig, _source: Receiver<events::Event>) {
    eprintln!("Emitter: Printing all received messages to screen");

    loop {
        match _source.recv() {
            Ok(_message) => (), //eprintln!("Emitter: Received message: {}", message),
            Err(e) => {
                eprintln!("Emitter: Received an error from messages channel. No more possibility of messages coming in. Closing thread. Error: {}", e);
                return;
            }
        }
    }
}