use crate::params;
use chrono::Duration as ChronoDuration;
use chrono::{DateTime, Utc};
use std::fs;
use std::io::Read;
use std::ops::Sub;
use sys_info::os_type;
use sysctl::Sysctl;

pub const PRINT_FATAL_SIGNALS_CTLNAME: &str = "kernel.print-fatal-signals";
pub const EXCEPTION_TRACE_CTLNAME: &str = "debug.exception-trace";
pub const PROC_UPTIME: &str = "/proc/uptime";

pub fn system_start_time() -> DateTime<Utc> {
    let system_uptime_nanos: i64 = (system_uptime_secs() * 1000000000.0) as i64;
    Utc::now().sub(ChronoDuration::nanoseconds(system_uptime_nanos))
}

// https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/s2-proc-uptime
pub fn system_uptime_secs() -> f64 {
    match fs::File::open(PROC_UPTIME) {
        Err(e) => {
            eprintln!(
                "Unable to open the file {} to read uptime: {}",
                PROC_UPTIME, e
            );
            0.0
        }
        Ok(mut proc_uptime) => {
            let mut contents = String::new();
            match proc_uptime.read_to_string(&mut contents) {
                Err(e) => {
                    eprintln!(
                        "Unable to read contents of the file {} to read uptime: {}",
                        PROC_UPTIME, e
                    );
                    0.0
                }
                Ok(_) => match contents.split_whitespace().next() {
                    None => {
                        eprintln!("Contents of the file {} not what was expected. Unable to parse the first number from: {}", PROC_UPTIME, contents);
                        0.0
                    }
                    Some(numstr) => match numstr.trim().parse::<f64>() {
                        Err(e) => {
                            eprintln!("Unable to parse the first number (of seconds of uptime) {} as a floating point number: {}", numstr, e);
                            0.0
                        }
                        Ok(num) => num,
                    },
                },
            }
        }
    }
}

pub fn ensure_linux() {
    const OS_DETECT_FAILURE: &str = "Unable to detect Operating System type. This program modifies the operating system in fundamental ways and fails safely when unable to detect the operating system.";
    let osname = os_type().expect(OS_DETECT_FAILURE);
    if osname != "Linux" {
        panic!("The Operating System detected is {} and not supported. This program modifies operating system settings in funamental ways and thus fails safely when it is not supported.", osname)
    }
}

pub fn modify_environment(config: &params::PolytectParams) {
    eprintln!("Configuring kernel paramters as requested...");
    if let Some(exception_trace) = config.exception_trace {
        ensure_systemctl(
            EXCEPTION_TRACE_CTLNAME,
            bool_to_sysctl_string(exception_trace),
        );
    }

    if let Some(fatal_signals) = config.fatal_signals {
        ensure_systemctl(
            PRINT_FATAL_SIGNALS_CTLNAME,
            bool_to_sysctl_string(fatal_signals),
        );
    }
}

fn ensure_systemctl(ctlstr: &str, valuestr: &str) {
    eprintln!("==> Ensuring {} is set to {}", ctlstr, valuestr);

    let ctl = sysctl::Ctl::new(ctlstr).unwrap();
    let prev_value_str = ctl
        .value_string()
        .expect(format!("Unable to read value of {}", ctlstr).as_str());
    if prev_value_str == valuestr {
        eprintln!("====> Already enabled, not reenabling: {}", ctlstr);
    } else {
        let real_value_str = ctl.set_value_string(valuestr).expect(
            format!(
                "Unable to set value of {} to {}, from a previous value of {}",
                ctlstr, valuestr, prev_value_str
            )
            .as_str(),
        );
        assert!(
            real_value_str == valuestr,
            "The value of {} was set to {} successfully, but value returned {}.",
            ctlstr,
            valuestr,
            real_value_str
        )
    }
}

fn bool_to_sysctl_string(b: bool) -> &'static str {
    match b {
        false => "0",
        true => "1",
    }
}
