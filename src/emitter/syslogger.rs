// Copyright (c) 2020 Polyverse Corporation

use crate::emitter;
use crate::events;
use crate::formatter::{new as new_formatter, Formatter as EventFormatter};
use crate::params;
use libc::getpid;
use params::{SyslogConfig, SyslogDestination};
use std::error;
use std::fmt::{Display, Formatter as FmtFormatter, Result as FmtResult};
use syslog::{Error as SyslogError, Facility, Formatter3164, Logger, LoggerBackend};

#[derive(Debug)]
pub enum SysLoggerError {
    MissingParameter(String),
    Syslog(SyslogError),
}

impl error::Error for SysLoggerError {}
impl Display for SysLoggerError {
    fn fmt(&self, f: &mut FmtFormatter) -> FmtResult {
        match self {
            Self::MissingParameter(s) => write!(f, "SysLoggerError::MissingParameter: {}", s),
            Self::Syslog(s) => write!(f, "SysLoggerError::Syslog internal error: {}", s),
        }
    }
}

impl From<syslog::Error> for SysLoggerError {
    fn from(err: syslog::Error) -> SysLoggerError {
        SysLoggerError::Syslog(err)
    }
}

pub struct SysLogger {
    output_format: params::OutputFormat,
    event_formatter: Box<dyn EventFormatter>,
    inner_logger: Logger<LoggerBackend, Formatter3164>,
}

impl emitter::Emitter for SysLogger {
    fn emit(&mut self, event: &events::Event) {
        match self.event_formatter.format(event) {
            Ok(formattedstr) => match self.inner_logger.info(&formattedstr) {
                Err(e) => eprintln!(
                    "Error writing event to syslog due to error {:?}. The event string: {}",
                    e, &formattedstr
                ),
                Ok(_) => {}
            },
            Err(e) => eprintln!("Error formatting event to {:?}: {}", self.output_format, e),
        }
    }
}

pub fn new(sc: SyslogConfig) -> Result<SysLogger, SysLoggerError> {
    let pid = getpid_safe();
    let syslog_formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: sc.hostname,
        process: "zerotect".to_owned(),
        pid,
    };

    // fire up the syslogger logger
    let inner_logger = match sc.destination {
        SyslogDestination::Default => match syslog::unix(syslog_formatter.clone()) {
            // logic copied from 'init'
            // https://docs.rs/syslog/5.0.0/src/syslog/lib.rs.html#429
            Err(unix_err) => {
                eprintln!("Unable to connect to syslog on the default unix sockets: {}. Moving on to TCP...", unix_err);
                match syslog::tcp(syslog_formatter.clone(), "127.0.0.1:601") {
                    Err(tcp_err) => {
                        eprintln!("Unable to connect to syslog on the default tcp endpoint: {}. Moving on to UDP (this rarely fails)...", tcp_err);
                        syslog::udp(syslog_formatter, "127.0.0.1:0", "127.0.0.1:514")?
                    },
                    Ok(tcp_logger) => tcp_logger,
                }
            },
            Ok(unix_logger) => unix_logger,
        }
        SyslogDestination::Unix => match sc.path {
            Some(path) => syslog::unix_custom(syslog_formatter, path)?,
            None => return Err(SysLoggerError::MissingParameter(format!("Parameter 'path' was not provided, but required to connect syslog to unix socket."))),
        }
        SyslogDestination::Tcp => match sc.server {
            Some(server) => syslog::tcp(syslog_formatter, server)?,
            None => return Err(SysLoggerError::MissingParameter(format!("Parameter 'server' was not provided, but required to connect syslog to unix socket."))),
        }
        SyslogDestination::Udp => match sc.server {
            Some(server) => match sc.local {
                Some(local) => syslog::udp(syslog_formatter, local, server)?,
                None => return Err(SysLoggerError::MissingParameter(format!("Parameter 'local' was not provided, but required to connect syslog to unix socket."))),
            },
            None => return Err(SysLoggerError::MissingParameter(format!("Parameter 'server' was not provided, but required to connect syslog to unix socket."))),
        }
    };

    let event_formatter = new_formatter(&sc.format);

    Ok(SysLogger {
        output_format: sc.format,
        event_formatter,
        inner_logger,
    })
}

fn getpid_safe() -> i32 {
    unsafe { getpid() }
}
