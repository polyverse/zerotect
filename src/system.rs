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
use sys_info::os_type;
use sysctl::Sysctl;

pub const PRINT_FATAL_SIGNALS_CTLNAME: &str = "kernel.print-fatal-signals";
pub const EXCEPTION_TRACE_CTLNAME: &str = "debug.exception-trace";
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
        SystemCtlError(format!("Inner ysctl::ctl_error::SysctlError :: {}", err))
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

pub fn modify_environment(
    auto_configure: &params::AutoConfigure,
) -> Result<Vec<events::Event>, SystemCtlError> {
    let mut env_events = Vec::<events::Event>::new();

    eprintln!("Configuring kernel paramters as requested...");
    if auto_configure.exception_trace {
        let maybe_event = ensure_systemctl(
            EXCEPTION_TRACE_CTLNAME,
            bool_to_sysctl_string(auto_configure.exception_trace),
        )?;
        if let Some(event) = maybe_event {
            env_events.push(event);
        }
    }

    if auto_configure.fatal_signals {
        let maybe_event = ensure_systemctl(
            PRINT_FATAL_SIGNALS_CTLNAME,
            bool_to_sysctl_string(auto_configure.fatal_signals),
        )?;
        if let Some(event) = maybe_event {
            env_events.push(event);
        }
    }

    Ok(env_events)
}

fn ensure_systemctl(ctlstr: &str, valuestr: &str) -> Result<Option<events::Event>, SystemCtlError> {
    eprintln!("==> Ensuring {} is set to {}", ctlstr, valuestr);

    let ctl = sysctl::Ctl::new(ctlstr)?;
    let prev_value_str = ctl.value_string()?;

    if prev_value_str == valuestr {
        eprintln!("====> Already enabled, not reenabling: {}", ctlstr);
        Ok(None)
    } else {
        ctl.set_value_string(valuestr)?;
        Ok(Some(events::Event {
            version: events::Version::V1,
            timestamp: Utc::now(),
            platform: events::Platform::Linux(events::LinuxPlatform {
                facility: events::LogFacility::Polytect,
                level: events::LogLevel::Error,
                event: events::LinuxEvent::ConfigMismatch(events::ConfigMisMatchInfo {
                    key: ctlstr.to_owned(),
                    expected_value: valuestr.to_owned(),
                    observed_value: prev_value_str.to_owned(),
                }),
            }),
        }))
    }
}

fn bool_to_sysctl_string(b: bool) -> &'static str {
    match b {
        false => "0",
        true => "1",
    }
}
