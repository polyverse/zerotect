// Copyright (c) 2019 Polyverse Corporation

use crate::events;
use crate::params;

use std::convert::From;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::mpsc::{Sender, Receiver};

pub trait Emitter {
    // Emit this event synchronously (blocks current thread)
    fn emit(&mut self, event: &events::Version);
}

pub struct AnalyzerConfig {
    pub verbosity: u8,
}

#[derive(Debug)]
pub struct AnalyzerError(String);
impl error::Error for AnalyzerError {}
impl Display for AnalyzerError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "AnalyzerError: {}", self.0)
    }
}

pub fn analyze(ac: AnalyzerConfig, source: Receiver<events::Event>, sink: Sender<events::Event>) -> Result<(), AnalyzerError> {
    eprintln!("Analyzer: Initializing...");

    loop {
        match source.recv() {
            Ok(event) => match sink.send(event) {
                Err(e) => return Err(AnalyzerError(format!("Analyzer: Error occurred sending events. Receipent is dead. Closing analyzer. Error: {}", e))),
                _ => {},
            }
            Err(e) => {
                return Err(AnalyzerError(format!("Analyzer: Received an error from messages channel. No more possibility of messages coming in. Closing thread. Error: {}", e)));
            }
        }
    }
}
