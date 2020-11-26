// Copyright (c) 2019 Polyverse Corporation

use crate::events;
use crate::params;
use chrono::Duration as ChronoDuration;
use chrono::{DateTime, Utc};
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs;
use std::io;
use std::num;
use std::ops::Sub;
use std::str;
use std::sync::Arc;
use sys_info::os_type;
use sysctl::Sysctl;

pub const PRINT_FATAL_SIGNALS_CTLNAME: &str = "kernel.print-fatal-signals";
pub const EXCEPTION_TRACE_CTLNAME: &str = "debug.exception-trace";
pub const KLOG_INCLUDE_TIMESTAMP: &str = "klog.include-timestamp";
pub const PROC_UPTIME: &str = "/proc/uptime";

#[derive(Debug)]
pub struct OperatingSystemValidationError(String);
impl Error for OperatingSystemValidationError {}
impl Display for OperatingSystemValidationError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "OperatingSystemValidationError:: {}", self.0)
    }
}
impl From<sys_info::Error> for OperatingSystemValidationError {
    fn from(err: sys_info::Error) -> OperatingSystemValidationError {
        OperatingSystemValidationError(format!("Inner sys_info::Error :: {}", err))
    }
}

#[derive(Debug)]
pub struct SystemUptimeReadError(String);
impl Error for SystemUptimeReadError {}
impl Display for SystemUptimeReadError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "SystemUptimeReadError:: {}", self.0)
    }
}
impl From<io::Error> for SystemUptimeReadError {
    fn from(err: io::Error) -> SystemUptimeReadError {
        SystemUptimeReadError(format!("Inner io::Error :: {}", err))
    }
}
impl From<str::Utf8Error> for SystemUptimeReadError {
    fn from(err: str::Utf8Error) -> SystemUptimeReadError {
        SystemUptimeReadError(format!("Inner str::Utf8Error :: {}", err))
    }
}
impl From<num::ParseFloatError> for SystemUptimeReadError {
    fn from(err: num::ParseFloatError) -> SystemUptimeReadError {
        SystemUptimeReadError(format!("Inner num::ParseFloatError :: {}", err))
    }
}

#[derive(Debug)]
pub struct SystemStartTimeReadError(String);
impl Error for SystemStartTimeReadError {}
impl Display for SystemStartTimeReadError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "SystemStartTimeReadError:: {}", self.0)
    }
}
impl From<SystemUptimeReadError> for SystemStartTimeReadError {
    fn from(err: SystemUptimeReadError) -> SystemStartTimeReadError {
        SystemStartTimeReadError(format!("Inner SystemUptimeReadError :: {}", err))
    }
}

#[derive(Debug)]
pub struct SystemCtlError(String);
impl Error for SystemCtlError {}
impl Display for SystemCtlError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "SystemCtlError:: {}", self.0)
    }
}
impl From<sysctl::SysctlError> for SystemCtlError {
    fn from(err: sysctl::SysctlError) -> SystemCtlError {
        SystemCtlError(format!("Inner sysctl::SysctlError :: {}", err))
    }
}
impl From<rmesg::error::RMesgError> for SystemCtlError {
    fn from(err: rmesg::error::RMesgError) -> SystemCtlError {
        SystemCtlError(format!("Inner rmesg::error::RMesgError :: {}", err))
    }
}
pub fn system_start_time() -> Result<DateTime<Utc>, SystemStartTimeReadError> {
    let system_uptime_nanos: i64 = (system_uptime_secs()? * 1000000000.0) as i64;
    Ok(Utc::now().sub(ChronoDuration::nanoseconds(system_uptime_nanos)))
}

// https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/s2-proc-uptime
pub fn system_uptime_secs() -> Result<f64, SystemUptimeReadError> {
    let contentsu8 = fs::read(PROC_UPTIME)?;
    let contents = str::from_utf8(&contentsu8)?;
    match contents.split_whitespace().next() {
        None => Err(SystemUptimeReadError(format!("Contents of the file {} not what was expected. Unable to parse the first number from: {}", PROC_UPTIME, contents))),
        Some(numstr) => Ok(numstr.trim().parse::<f64>()?),
    }
}

pub fn ensure_linux() -> Result<(), OperatingSystemValidationError> {
    let osname = os_type()?;
    if osname != "Linux" {
        return Err(OperatingSystemValidationError(format!("The Operating System detected is {} and not supported. This program modifies operating system settings in funamental ways and thus fails safely when it is not supported.", osname)));
    }
    Ok(())
}

pub async fn modify_environment(
    auto_configure: &params::AutoConfigure,
    hostname: &Option<String>,
) -> Result<Vec<events::Event>, SystemCtlError> {
    let mut env_events = Vec::<events::Event>::new();

    eprintln!("Configuring kernel paramters as requested...");
    if auto_configure.exception_trace {
        let maybe_event = ensure_systemctl(
            hostname,
            EXCEPTION_TRACE_CTLNAME,
            bool_to_0_1_string(auto_configure.exception_trace),
        )?;
        if let Some(event) = maybe_event {
            env_events.push(event);
        }
    }

    if auto_configure.fatal_signals {
        let maybe_event = ensure_systemctl(
            hostname,
            PRINT_FATAL_SIGNALS_CTLNAME,
            bool_to_0_1_string(auto_configure.fatal_signals),
        )?;
        if let Some(event) = maybe_event {
            env_events.push(event);
        }
    }

    if auto_configure.klog_include_timestamp && !rmesg::kernel_log_timestamps_enabled()? {
        rmesg::kernel_log_timestamps_enable(true)?;

        env_events.push(Arc::new(events::Version::V1 {
            timestamp: Utc::now(),
            hostname: hostname.clone(),
            event: events::EventType::ConfigMismatch(events::ConfigMismatch {
                key: rmesg::SYS_MODULE_PRINTK_PARAMETERS_TIME.to_owned(),
                expected_value: "Y".to_owned(),
                observed_value: "N".to_owned(),
            }),
        }));
    }

    Ok(env_events)
}

fn ensure_systemctl(
    hostname: &Option<String>,
    ctlstr: &str,
    valuestr: &str,
) -> Result<Option<events::Event>, SystemCtlError> {
    eprintln!("==> Ensuring {} is set to {}", ctlstr, valuestr);

    let ctl = sysctl::Ctl::new(ctlstr)?;
    let prev_value_str = ctl.value_string()?;

    if prev_value_str.trim() == valuestr.trim() {
        eprintln!("====> Already enabled, not reenabling: {}", ctlstr);
        Ok(None)
    } else {
        ctl.set_value_string(valuestr)?;
        Ok(Some(Arc::new(events::Version::V1 {
            timestamp: Utc::now(),
            hostname: hostname.clone(),
            event: events::EventType::ConfigMismatch(events::ConfigMismatch {
                key: ctlstr.to_owned(),
                expected_value: valuestr.to_owned(),
                observed_value: prev_value_str,
            }),
        })))
    }
}

fn bool_to_0_1_string(b: bool) -> &'static str {
    match b {
        false => "0\n",
        true => "1\n",
    }
}
