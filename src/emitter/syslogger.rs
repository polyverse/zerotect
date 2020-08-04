// Copyright (c) 2020 Polyverse Corporation

use crate::emitter;
use crate::events;
use crate::formatter::{new as new_formatter, Formatter};
use crate::params;
use syslog::{Error as SyslogError, Facility};
use log::LevelFilter;
use params::{SyslogConfig, SyslogDestination};

pub struct Syslogger {
    format: params::OutputFormat,
    formatter: Box<dyn Formatter>,
}

impl emitter::Emitter for Syslogger {
    fn emit(&self, event: &events::Version) {
        match self.formatter.format(event) {
            Ok(formattedstr) => info!("{}", formattedstr),
            Err(e) => eprintln!("Error formatting event to {:?}: {}", self.format, e),
        }
    }
}

pub fn new(sc: SyslogConfig) -> Result<Syslogger, SyslogError> {
    // fire up the syslogger
    match sc.destination {
        SyslogDestination::Default => syslog::init(
            Facility::LOG_USER, // log as user facility
            LevelFilter::Info, // since we log at info level - use that level
            None, // pick up application name from executable
        )?,
        SyslogDestination::Unix{path} => syslog::init_unix_custom(Facility::LOG_USER, LevelFilter::Info, path)?,
        SyslogDestination::Tcp{server, hostname} => syslog::init_tcp(server, hostname, Facility::LOG_USER, LevelFilter::Info)?,
        SyslogDestination::Udp{local, server, hostname} => syslog::init_udp(local, server, hostname, Facility::LOG_USER, LevelFilter::Info)?,
    };

    let formatter = new_formatter(&sc.format);

    Ok(Syslogger {
        format: sc.format,
        formatter,
    })
}
