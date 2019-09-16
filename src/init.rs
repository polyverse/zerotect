extern crate clap;
extern crate sys_info;
extern crate sysctl;

use clap::{Arg, App};
use sys_info::{os_type};
use sysctl::Sysctl;

const ENABLE_FATAL_SIGNALS_FLAG: &str = "enable-fatal-signals";
const ENABLE_EXCEPTION_TRACE_FLAG: &str = "enable-exception-trace";
const PRINT_FATAL_SIGNALS_CTLNAME: &str = "kernel.print-fatal-signals";
const EXCEPTION_TRACE_CTLNAME: &str = "debug.exception-trace";

struct SystemConfig {
    exception_trace: Option<bool>,
    fatal_signals: Option<bool>,
}

pub fn initialize() {
    ensure_linux();
    let config = parse_args();
    modify_environment(config);
}

fn parse_args() -> SystemConfig {
        let matches = App::new("Polytect")
                        .version("1.0")
                        .author("Polyverse Corporation <support@polyverse.com>")
                        .about("Detect attempted (and ultimately failed) attacks and exploits using known and unknown vulnerabilities by observing side effects (segfaults, crashes, etc.)")
                        .arg(Arg::with_name(ENABLE_EXCEPTION_TRACE_FLAG)
                            .short("e")
                            .long(ENABLE_EXCEPTION_TRACE_FLAG)
                            .help(format!("Sets the {} value to enable segfaults to be logged to dmesg.", EXCEPTION_TRACE_CTLNAME).as_str()))
                        .arg(Arg::with_name(ENABLE_FATAL_SIGNALS_FLAG)
                            .short("f")
                            .long(ENABLE_FATAL_SIGNALS_FLAG)
                            .help(format!("Sets the {} value to enable details of fatals to be logged to dmesg.", PRINT_FATAL_SIGNALS_CTLNAME).as_str()))
                        .get_matches();

    let exception_trace = bool_flag(&matches, ENABLE_EXCEPTION_TRACE_FLAG);
    let fatal_signals = bool_flag(&matches, ENABLE_FATAL_SIGNALS_FLAG);

    SystemConfig{
        exception_trace, 
        fatal_signals,
    }
}

fn modify_environment(config: SystemConfig) {
    eprintln!("Configuring kernel paramters as requested...");
    if let Some(exception_trace) = config.exception_trace {
        ensure_systemctl(EXCEPTION_TRACE_CTLNAME, bool_to_sysctl_string(exception_trace));
    }

    if let Some(fatal_signals) = config.fatal_signals {
        ensure_systemctl(PRINT_FATAL_SIGNALS_CTLNAME, bool_to_sysctl_string(fatal_signals));
    }
}


fn ensure_linux() {
    const OS_DETECT_FAILURE: &str = "Unable to detect Operating System type. This program modifies the operating system in fundamental ways and fails safely when unable to detect the operating system.";
    let osname = os_type().expect(OS_DETECT_FAILURE);
    if osname != "Linux" {
        panic!("The Operating System detected is {} and not supported. This program modifies operating system settings in funamental ways and thus fails safely when it is not supported.", osname)
    }
}


fn ensure_systemctl(ctlstr: &str, valuestr: &str) {
    eprintln!("==> Ensuring {} is set to {}", ctlstr, valuestr);

    let exception_trace_ctl = sysctl::Ctl::new(ctlstr).unwrap();
    let prev_value_str = exception_trace_ctl.value_string().expect(format!("Unable to read value of {}", ctlstr).as_str());
    if prev_value_str ==  valuestr {
        eprintln!("====> Already enabled, not reenabling: {}", ctlstr);
    } else {
        let real_value_str = exception_trace_ctl.set_value_string(valuestr)
            .expect(format!("Unable to set value of {} to {}, from a previous value of {}", ctlstr, valuestr, prev_value_str).as_str());
        assert!(real_value_str == valuestr, "The value of {} was set to {} successfully, but value returned {}.", ctlstr, valuestr, real_value_str)
    }
}

fn bool_to_sysctl_string(b: bool) -> &'static str {
    match b {
        false => "0",
        true => "1"
    }
}


fn bool_flag(matches: &clap::ArgMatches, flag_name: &str) -> Option<bool> {
    match matches.occurrences_of(flag_name) {
        1 => Some(true),
        0 => None,
        _ => { 
            eprintln!("You specified {} flag {} number of times. Please specify it at most once or never at all. Ignoring this flag entirely.", flag_name, matches.occurrences_of(flag_name)); 
            None
        },
    }
}
