// Copyright (c) 2020 Polyverse Corporation

use crate::emitter;
use crate::events;
use crate::formatter::new as new_formatter;
use crate::params;
use libc::getpid;
use params::{SyslogConfig, SyslogDestination};
use std::error;
use std::fmt::{Display, Formatter as FmtFormatter, Result as FmtResult};
use syslog::{Error as SyslogError, Facility, Formatter3164};
use tokio::sync::broadcast;

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
impl From<SyslogError> for SysLoggerError {
    fn from(err: SyslogError) -> Self {
        Self::Syslog(err)
    }
}

pub async fn emit_forever(
    sc: SyslogConfig,
    hostname: Option<String>,
    source: broadcast::Receiver<events::Event>,
) -> Result<(), emitter::EmitterError> {
    // Value in capturing local errors here and wrapping them to EmitterError
    Ok(emit_forever_syslogger_error(sc, hostname, source).await?)
}

pub async fn emit_forever_syslogger_error(
    sc: SyslogConfig,
    hostname: Option<String>,
    mut source: broadcast::Receiver<events::Event>,
) -> Result<(), SysLoggerError> {
    let pid = getpid_safe();
    let syslog_formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname,
        process: "zerotect".to_owned(),
        pid,
    };

    // fire up the syslogger logger
    let mut inner_logger = match sc.destination {
        SyslogDestination::Default => match syslog::unix(syslog_formatter.clone()) {
            Ok(unix_logger) => unix_logger,
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
        },
        SyslogDestination::Unix => match sc.path {
            Some(path) => syslog::unix_custom(syslog_formatter, path)?,
            None => return Err(SysLoggerError::MissingParameter("Parameter 'path' was not provided, but required to connect syslog to unix socket.".to_owned()).into()),
        },
        SyslogDestination::Tcp => match sc.server {
            Some(server) => syslog::tcp(syslog_formatter, server)?,
            None => return Err(SysLoggerError::MissingParameter("Parameter 'server' was not provided, but required to connect syslog to unix socket.".to_owned()).into()),
        },
        SyslogDestination::Udp => match sc.server {
            Some(server) => match sc.local {
                Some(local) => syslog::udp(syslog_formatter, local, server)?,
                None => return Err(SysLoggerError::MissingParameter("Parameter 'local' was not provided, but required to connect syslog to unix socket.".to_owned()).into()),
            },
            None => return Err(SysLoggerError::MissingParameter("Parameter 'server' was not provided, but required to connect syslog to unix socket.".to_owned()).into()),
        },
    };

    let event_formatter = new_formatter(&sc.format);

    loop {
        match source.recv().await {
            Ok(event) => match event_formatter.format(&event) {
                Ok(formattedstr) => {
                    if let Err(e) = inner_logger.info(&formattedstr) {
                        eprintln!(
                            "Error writing event to syslog due to error {:?}. The event string: {}",
                            e, &formattedstr
                        )
                    }
                }
                Err(e) => eprintln!("Error formatting event to {:?}: {}", sc.format, e),
            },
            Err(broadcast::error::RecvError::Lagged(count)) => {
                eprintln!(
                    "Syslogger is lagging behind generated events. {} events have been dropped.",
                    count
                )
            }
            Err(broadcast::error::RecvError::Closed) => {
                panic!("Syslogger event source closed. Panicking and exiting.")
            }
        }
    }
}

fn getpid_safe() -> i32 {
    unsafe { getpid() }
}
