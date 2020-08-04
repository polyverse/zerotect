// Copyright (c) 2020 Polyverse Corporation

use crate::emitter;
use crate::events;
use crate::formatter::{new as new_formatter, Formatter};
use crate::params;
use log::LevelFilter;
use params::{SyslogConfig, SyslogDestination};
use std::error;
use std::fmt::{Display, Formatter as FmtFormatter, Result as FmtResult};
use syslog::{Error as SyslogError, Facility};

#[derive(Debug)]
pub enum LoggerError {
    MissingParameter(String),
    Syslog(SyslogError),
}

impl error::Error for LoggerError {}
impl Display for LoggerError {
    fn fmt(&self, f: &mut FmtFormatter) -> FmtResult {
        match self {
            Self::MissingParameter(s) => write!(f, "LoggerError::MissingParameter: {}", s),
            Self::Syslog(s) => write!(f, "LoggerError::Syslog internal error: {}", s),
        }
    }
}

impl From<syslog::Error> for LoggerError {
    fn from(err: syslog::Error) -> LoggerError {
        LoggerError::Syslog(err)
    }
}

pub struct Logger {
    format: params::OutputFormat,
    formatter: Box<dyn Formatter>,
}

impl emitter::Emitter for Logger {
    fn emit(&self, event: &events::Version) {
        match self.formatter.format(event) {
            Ok(formattedstr) => info!("{}", formattedstr),
            Err(e) => eprintln!("Error formatting event to {:?}: {}", self.format, e),
        }
    }
}

pub fn new(sc: SyslogConfig) -> Result<Logger, LoggerError> {
    // fire up the logger
    match sc.destination {
        SyslogDestination::Default => syslog::init(
            Facility::LOG_USER, // log as user facility
            LevelFilter::Info, // since we log at info level - use that level
            None, // pick up application name from executable
        )?,
        SyslogDestination::Unix => match sc.path {
            Some(path) => syslog::init_unix_custom(Facility::LOG_USER, LevelFilter::Info, path)?,
            None => return Err(LoggerError::MissingParameter(format!("Parameter 'path' was not provided, but required to connect syslog to unix socket."))),
        }
        SyslogDestination::Tcp => match sc.server {
            Some(server) => match sc.hostname {
                Some(hostname) => syslog::init_tcp(server, hostname, Facility::LOG_USER, LevelFilter::Info)?,
                None => return Err(LoggerError::MissingParameter(format!("Parameter 'hostname' was not provided, but required to connect syslog to unix socket."))),
            },
            None => return Err(LoggerError::MissingParameter(format!("Parameter 'server' was not provided, but required to connect syslog to unix socket."))),
        }
        SyslogDestination::Udp => match sc.server {
            Some(server) => match sc.local {
                Some(local) => match sc.hostname {
                    Some(hostname) => syslog::init_udp(local, server, hostname, Facility::LOG_USER, LevelFilter::Info)?,
                    None => return Err(LoggerError::MissingParameter(format!("Parameter 'hostname' was not provided, but required to connect syslog to unix socket."))),
                },
                None => return Err(LoggerError::MissingParameter(format!("Parameter 'local' was not provided, but required to connect syslog to unix socket."))),
            },
            None => return Err(LoggerError::MissingParameter(format!("Parameter 'server' was not provided, but required to connect syslog to unix socket."))),
        }
    };

    let formatter = new_formatter(&sc.format);

    Ok(Logger {
        format: sc.format,
        formatter,
    })
}
