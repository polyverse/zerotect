// Copyright (c) 2019 Polyverse Corporation

use crate::events;
use crate::params;

use std::convert::From;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::mpsc::Receiver;

mod console;
mod polycorder;

pub trait Emitter {
    // Emit this event synchronously (blocks current thread)
    fn emit(&self, event: &events::Event);
}

pub struct EmitterConfig {
    pub verbosity: u8,
    pub console_config: Option<params::ConsoleConfig>,
    pub polycorder_config: Option<params::PolycorderConfig>,
}

#[derive(Debug)]
pub struct EmitterError(String);
impl error::Error for EmitterError {}
impl Display for EmitterError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "EmitterError: {}", self.0)
    }
}
impl From<polycorder::PolycorderError> for EmitterError {
    fn from(err: polycorder::PolycorderError) -> EmitterError {
        EmitterError(format!("polycorder::PolycorderError: {}", err))
    }
}

pub fn emit(ec: EmitterConfig, source: Receiver<events::Event>) -> Result<(), EmitterError> {
    eprintln!("Emitter: Initializing...");

    let mut emitters: Vec<Box<dyn Emitter>> = vec![];
    if let Some(cc) = ec.console_config {
        eprintln!("Emitter: Initialized Console emitter. Expect messages to be printed to Standard Output.");
        emitters.push(Box::new(console::new(cc)));
    }
    if let Some(tc) = ec.polycorder_config {
        eprintln!("Emitter: Initialized Polycorder emitter. Expect messages to be phoned home to the Polyverse polycorder service.");
        emitters.push(Box::new(polycorder::new(tc)?));
    }

    loop {
        match source.recv() {
            Ok(event) => {
                for emitter in &emitters {
                    emitter.emit(&event)
                }
            }
            Err(e) => {
                return Err(EmitterError(format!("Emitter: Received an error from messages channel. No more possibility of messages coming in. Closing thread. Error: {}", e)));
            }
        }
    }
}
