// Copyright (c) 2019 Polyverse Corporation

use crate::events;
use crate::params;

use core::future::Future;
use core::pin::Pin;
use futures::future::join_all;
use futures::stream::Stream;
use futures::StreamExt;
use std::convert::From;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use tokio::sync::broadcast;

mod console;
mod filelogger;
//mod pagerduty;
mod polycorder;
mod syslogger;

type EmitForeverFuture = Pin<Box<dyn Future<Output = Result<(), EmitterError>>>>;

pub struct EmitterConfig {
    pub verbosity: u8,
    pub console: Option<params::ConsoleConfig>,
    pub polycorder: Option<params::PolycorderConfig>,
    pub syslog: Option<params::SyslogConfig>,
    pub logfile: Option<params::LogFileConfig>,
    pub pagerduty_routing_key: Option<String>,
}

#[derive(Debug)]
pub enum EmitterError {
    UnexpectedExit,
    StreamEnded,
    NoEmitters,
    SendError(broadcast::error::SendError<events::Event>),
    Polycorder(polycorder::PolycorderError),
    Syslogger(syslogger::SysLoggerError),
    FileLogger(filelogger::FileLoggerError),
    //Pagerduty(pagerduty::PagerDutyError),
}

impl error::Error for EmitterError {}
impl Display for EmitterError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::UnexpectedExit => write!(f, "EmitterError: Unexpected exited from an infinite loop. Usually an error is associated with this but none was reported."),
            Self::StreamEnded => write!(f, "EmitterError: The event stream unexpectedly exited. Zerotect streams should be perpetual and not expected."),
            Self::NoEmitters => write!(f, "EmitterError: No emitters were configured. Zerotect is useless if it isn't emitting to at least one destination."),
            Self::SendError(e) => write!(f, "Error Sending an event to Emitters: {}", e),
            Self::Polycorder(e) => write!(f, "Error in Polycorder Emitter: {}", e),
            Self::Syslogger(e) => write!(f, "Error in Syslogger Emitter: {}", e),
            Self::FileLogger(e) => write!(f, "Error in FileLogger Emitter: {}", e),
            //Self::Pagerduty(e) => write!(f, "Error in Pagerduty Emitter: {}", e),
        }
    }
}

impl From<polycorder::PolycorderError> for EmitterError {
    fn from(err: polycorder::PolycorderError) -> Self {
        Self::Polycorder(err)
    }
}

impl From<syslogger::SysLoggerError> for EmitterError {
    fn from(err: syslogger::SysLoggerError) -> Self {
        Self::Syslogger(err)
    }
}

impl From<filelogger::FileLoggerError> for EmitterError {
    fn from(err: filelogger::FileLoggerError) -> Self {
        Self::FileLogger(err)
    }
}

/*
impl From<pagerduty::PagerDutyError> for EmitterError {
    fn from(err: pagerduty::PagerDutyError) -> Self {
        Self::Pagerduty(err)
    }
}
*/

impl From<broadcast::error::SendError<events::Event>> for EmitterError {
    fn from(err: broadcast::error::SendError<events::Event>) -> Self {
        Self::SendError(err)
    }
}

pub async fn emit_forever(
    ec: EmitterConfig,
    source: impl Stream<Item = events::Event> + Unpin + 'static,
    hostname: Option<String>,
) -> Result<(), EmitterError> {
    eprintln!("Emitter: Initializing...");

    // start a channel to all emitters with plenty of buffer
    let (tx, _) = broadcast::channel(1000);

    let mut emit_forever_futures: Vec<EmitForeverFuture> = vec![];
    if let Some(cc) = ec.console {
        eprintln!("Emitter: Initialized Console emitter. Expect messages to be printed to Standard Output.");
        emit_forever_futures.push(Box::pin(console::emit_forever(cc, tx.subscribe())));
    }
    if let Some(sc) = ec.syslog {
        eprintln!("Emitter: Initialized Syslog emitter. Expect messages to be sent to Syslog.");
        emit_forever_futures.push(Box::pin(syslogger::emit_forever(
            sc,
            hostname,
            tx.subscribe(),
        )));
    }
    if let Some(lfc) = ec.logfile {
        eprintln!("Emitter: Initialized LogFile emitter. Expect messages to be sent to a file.");
        emit_forever_futures.push(Box::pin(filelogger::emit_forever(lfc, tx.subscribe())));
    }
    /*
    if let Some(prk) = ec.pagerduty_routing_key {
        eprintln!("Emitter: Initialized PagerDuty emitter. Expect messages to be sent to a PagerDuty Service.");
        emit_forever_futures.push(pagerduty::emit_forever(prk, tx.subscribe()));
    }
    */
    if let Some(tc) = ec.polycorder {
        eprintln!("Emitter: Initialized Polycorder emitter. Expect messages to be phoned home to the Polyverse polycorder service.");
        emit_forever_futures.push(Box::pin(polycorder::emit_forever(ec.verbosity, tc, tx.subscribe())));
    }

    if emit_forever_futures.is_empty() {
        return Err(EmitterError::NoEmitters);
    }

    // add the stream-to-broadcasting future as well
    emit_forever_futures.push(Box::pin(transmit_forever(source, tx)));

    // then just wait on all of them!
    join_all(emit_forever_futures).await;

    Err(EmitterError::StreamEnded)
}

async fn transmit_forever(
    mut source: impl Stream<Item = events::Event> + Unpin,
    tx: broadcast::Sender<events::Event>,
) -> Result<(), EmitterError> {
    while let Some(event) = source.next().await {
        tx.send(event)?;
    }

    Err(EmitterError::UnexpectedExit)
}
