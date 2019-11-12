use crate::events;
use std::sync::mpsc::Receiver;
pub mod console;
pub mod tricorder;

pub trait Emitter {
    // Emit this event synchronously (blocks current thread)
    fn emit(&self, event: &events::Event);
}

pub struct EmitterConfig {
    pub verbosity: u8,
    pub console_config: Option<console::ConsoleConfig>,
    pub tricorder_config: Option<tricorder::TricorderConfig>,
}

pub fn emit(ec: EmitterConfig, source: Receiver<events::Event>) {
    eprintln!("Emitter: Initializing...");

    let mut emitters: Vec<Box<dyn Emitter>> = vec![];
    if let Some(cc) = ec.console_config {
        eprintln!("Emitter: Initialized Console emitter. Expect messages to be printed to Standard Output.");
        emitters.push(Box::new(console::new(cc)));
    }
    if let Some(tc) = ec.tricorder_config {
        eprintln!("Emitter: Initialized Tricorder emitter. Expect messages to be phoned home to the Polyverse tricorder service.");
        emitters.push(Box::new(tricorder::new(tc)));
    }

    loop {
        match source.recv() {
            Ok(event) => {
                for emitter in &emitters {
                    emitter.emit(&event)
                }
            }
            Err(e) => {
                eprintln!("Emitter: Received an error from messages channel. No more possibility of messages coming in. Closing thread. Error: {}", e);
                return;
            }
        }
    }
}
