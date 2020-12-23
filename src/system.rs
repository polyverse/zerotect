// Copyright (c) 2019 Polyverse Corporation

use crate::events;
use crate::params;
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
use futures::stream::Stream;
use core::future::Future;
use core::pin::Pin;
use futures::task::{Context, Poll};

// Change to below once we upgrade to Tokio 0.3.x which is gated
// on hyper: https://github.com/hyperium/hyper/issues/2302
//use tokio::time::{sleep, Sleep};
// Workaround for tokio 0.2.24 that keeps all inline code identical:
use tokio::time::{delay_for as sleep, Delay as Sleep};

use std::time::Duration;
use time::OffsetDateTime;

pub const PRINT_FATAL_SIGNALS_CTLNAME: &str = "kernel.print-fatal-signals";
pub const EXCEPTION_TRACE_CTLNAME: &str = "debug.exception-trace";
pub const KLOG_INCLUDE_TIMESTAMP: &str = "klog.include-timestamp";
pub const PROC_UPTIME: &str = "/proc/uptime";

#[derive(Debug)]
pub struct SystemConfigError(String);
impl Error for SystemConfigError {}
impl Display for SystemConfigError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "SystemConfigError:: {}", self.0)
    }
}
impl From<sysctl::SysctlError> for SystemConfigError {
    fn from(err: sysctl::SysctlError) -> Self {
        Self(format!("Inner sysctl::SysctlError :: {}", err))
    }
}
impl From<rmesg::error::RMesgError> for SystemConfigError {
    fn from(err: rmesg::error::RMesgError) -> Self {
        Self(format!("Inner rmesg::error::RMesgError :: {}", err))
    }
}
impl From<io::Error> for SystemConfigError {
    fn from(err: io::Error) -> Self {
        Self(format!("Inner io::Error :: {}", err))
    }
}
impl From<str::Utf8Error> for SystemConfigError {
    fn from(err: str::Utf8Error) -> Self {
        Self(format!("Inner str::Utf8Error :: {}", err))
    }
}
impl From<num::ParseFloatError> for SystemConfigError {
    fn from(err: num::ParseFloatError) -> Self {
        Self(format!("Inner num::ParseFloatError :: {}", err))
    }
}
impl From<sys_info::Error> for SystemConfigError {
    fn from(err: sys_info::Error) -> Self {
        Self(format!("Inner sys_info::Error :: {}", err))
    }
}

pub struct EnvironmentConfigurator {
    auto_config: params::AutoConfigure,
    sleep_interval: Duration,
    hostname: Option<String>,
    change_events: Vec<events::Event>,
    sleep_future: Option<Sleep>,
}
impl EnvironmentConfigurator {
    pub fn new(auto_config: params::AutoConfigure, hostname: Option<String>) -> Self {
        Self {
            auto_config,
            sleep_interval: Duration::from_secs(300),
            hostname,
            change_events: Vec::new(),
            sleep_future: Option::<Sleep>::None,
        }
    }

    fn enforce_config(&mut self) -> Result<(), SystemConfigError> {
        // if not sleeping.. reinforce the system with config
        let events = modify_environment(&self.auto_config, &self.hostname)?;
        for event in events.into_iter() {
            eprintln!(
                "Configuration modified. {}",
                &event
            );
            self.change_events.push(event);
        }

        Ok(())
    }
}
impl Stream for EnvironmentConfigurator {
    type Item = Result<events::Event, SystemConfigError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::option::Option<<Self as Stream>::Item>> {

        // if already sleeping... handle that.
        if let Some(mut sf) = self.sleep_future.take() {
            match Future::poll(Pin::new(&mut sf), cx) {
                // still sleeping? Go back to sleep.
                Poll::Pending => {
                    // put the future back in
                    self.sleep_future = Some(sf);
                    return Poll::Pending;
                }

                // Not sleeping? continue...
                Poll::Ready(()) => {}
            }
        }

        // enforce configuration
        if let Err(e) = self.enforce_config() {
            return Poll::Ready(Some(Err(e)));
        }

        // entries empty? then go to sleep...
        if self.change_events.is_empty() {
            let mut sf = sleep(self.sleep_interval);
            match Future::poll(Pin::new(&mut sf), cx) {
                Poll::Pending => {
                    self.sleep_future = Some(sf);
                    return Poll::Pending;
                },
                Poll::Ready(_) => {
                    eprintln!("Sleep future did not return Poll::Pending as expected despite being asked to sleep for {:?}", self.sleep_interval);
                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Some(Ok(self.change_events.remove(0))))
    }
}
/*
async fn configure_environment(
    auto_config: params::AutoConfigure,
    hostname: Option<String>,
    config_event_sink: UnboundedSender<events::Event>,
) -> Result<(), MainError> {
    // initialize the system with config
    system::modify_environment(&auto_config, &hostname).await?;

    // let the first time go from config-mismatch event reporting
    loop {


        // ensure configuratione very five minutes.
        sleep().await;
    }
}
*/

pub fn system_start_time() -> Result<OffsetDateTime, SystemConfigError> {
    let system_uptime_nanos: u64 = (system_uptime_secs()? * 1000000000.0) as u64;
    Ok(OffsetDateTime::now_utc().sub(Duration::from_nanos(system_uptime_nanos)))
}

// https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/s2-proc-uptime
pub fn system_uptime_secs() -> Result<f64, SystemConfigError> {
    let contentsu8 = fs::read(PROC_UPTIME)?;
    let contents = str::from_utf8(&contentsu8)?;
    match contents.split_whitespace().next() {
        None => Err(SystemConfigError(format!("Contents of the file {} not what was expected. Unable to parse the first number from: {}", PROC_UPTIME, contents))),
        Some(numstr) => Ok(numstr.trim().parse::<f64>()?),
    }
}

pub fn ensure_linux() -> Result<(), SystemConfigError> {
    let osname = os_type()?;
    if osname != "Linux" {
        return Err(SystemConfigError(format!("The Operating System detected is {} and not supported. This program modifies operating system settings in funamental ways and thus fails safely when it is not supported.", osname)));
    }
    Ok(())
}

pub fn modify_environment(
    auto_configure: &params::AutoConfigure,
    hostname: &Option<String>,
) -> Result<Vec<events::Event>, SystemConfigError> {
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

    if auto_configure.klog_include_timestamp && !rmesg::klogctl::klog_timestamps_enabled()? {
        rmesg::klogctl::klog_timestamps_enable(true)?;

        env_events.push(Arc::new(events::Version::V1 {
            timestamp: OffsetDateTime::now_utc(),
            hostname: hostname.clone(),
            event: events::EventType::ConfigMismatch(events::ConfigMismatch {
                key: rmesg::klogctl::SYS_MODULE_PRINTK_PARAMETERS_TIME.to_owned(),
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
) -> Result<Option<events::Event>, SystemConfigError> {
    eprintln!("==> Ensuring {} is set to {}", ctlstr, valuestr);

    let ctl = sysctl::Ctl::new(ctlstr)?;
    let prev_value_str = ctl.value_string()?;

    if prev_value_str.trim() == valuestr.trim() {
        eprintln!("====> Already enabled, not reenabling: {}", ctlstr);
        Ok(None)
    } else {
        ctl.set_value_string(valuestr)?;
        Ok(Some(Arc::new(events::Version::V1 {
            timestamp: OffsetDateTime::now_utc(),
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
