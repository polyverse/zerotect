// Copyright (c) 2019 Polyverse Corporation

use crate::events;
use crate::params;

use std::convert::From;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::mpsc::Receiver;

mod console;
mod filelogger;
mod polycorder;
mod syslogger;

pub trait Emitter {
    // Emit this event synchronously (blocks current thread)
    fn emit(&mut self, event: &events::Event);
}

pub struct EmitterConfig {
    pub verbosity: u8,
    pub console: Option<params::ConsoleConfig>,
    pub polycorder: Option<params::PolycorderConfig>,
    pub syslog: Option<params::SyslogConfig>,
    pub logfile: Option<params::LogFileConfig>,
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

impl From<syslogger::SysLoggerError> for EmitterError {
    fn from(err: syslogger::SysLoggerError) -> EmitterError {
        EmitterError(format!("syslogger::SysLoggerError: {}", err))
    }
}

impl From<filelogger::FileLoggerError> for EmitterError {
    fn from(err: filelogger::FileLoggerError) -> EmitterError {
        EmitterError(format!("filelogger::FileLoggerError: {}", err))
    }
}

pub fn emit(ec: EmitterConfig, source: Receiver<events::Event>) -> Result<(), EmitterError> {
    eprintln!("Emitter: Initializing...");

    let mut emitters: Vec<Box<dyn Emitter>> = vec![];
    if let Some(cc) = ec.console {
        eprintln!("Emitter: Initialized Console emitter. Expect messages to be printed to Standard Output.");
        emitters.push(Box::new(console::new(cc)));
    }
    if let Some(tc) = ec.polycorder {
        eprintln!("Emitter: Initialized Polycorder emitter. Expect messages to be phoned home to the Polyverse polycorder service.");
        emitters.push(Box::new(polycorder::new(tc, ec.verbosity)?));
    }
    if let Some(sc) = ec.syslog {
        eprintln!("Emitter: Initialized Syslog emitter. Expect messages to be sent to Syslog.");
        emitters.push(Box::new(syslogger::new(sc)?));
    }
    if let Some(lfc) = ec.logfile {
        eprintln!("Emitter: Initialized LogFile emitter. Expect messages to be sent to a file.");
        emitters.push(Box::new(filelogger::new(lfc)?));
    }

    if emitters.is_empty() {
        return Err(EmitterError("Emitter: There are no emitters configured. Zerotect is useless if not emitting somewhere.".to_owned()));
    }

    loop {
        match source.recv() {
            Ok(event) => {
                for emitter in emitters.iter_mut() {
                    emitter.emit(&event)
                }
            }
            Err(e) => {
                return Err(EmitterError(format!("Emitter: Received an error from messages channel. No more possibility of messages coming in. Closing thread. Error: {}", e)));
            }
        }
    }
}
