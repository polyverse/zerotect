extern crate clap;

use clap::{Arg, App};
use std::convert::TryFrom;
use crate::monitor;

const ENABLE_FATAL_SIGNALS_FLAG: &str = "enable-fatal-signals";
const ENABLE_EXCEPTION_TRACE_FLAG: &str = "enable-exception-trace";
const PRINT_FATAL_SIGNALS_CTLNAME: &str = "kernel.print-fatal-signals";
const EXCEPTION_TRACE_CTLNAME: &str = "debug.exception-trace";

pub struct PolytectParams {
    pub exception_trace: Option<bool>,
    pub fatal_signals: Option<bool>,
    pub monitor_type: monitor::MonitorType,
    pub verbosity: u8,
}

pub fn initialize() -> PolytectParams {
    let config = parse_args();
    config
}

fn parse_args() -> PolytectParams {
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
                        .arg(Arg::with_name("verbose")
                            .short("v")
                            .long("verbose")
                            .multiple(true)
                            .help(format!("Increase debug verbosity of polytect.").as_str()))
                        .get_matches();

    let exception_trace = bool_flag(&matches, ENABLE_EXCEPTION_TRACE_FLAG);
    let fatal_signals = bool_flag(&matches, ENABLE_FATAL_SIGNALS_FLAG);
    let verbosity = u8::try_from(matches.occurrences_of("verbose")).ok().unwrap();
     
    println!("monitor-type option: {:?}",matches.value_of("monitor-type"));

    let monitor_type = monitor::MonitorType::DevKMsgReader(monitor::dev_kmsg_reader::KMsgReaderConfig{
        from_sequence_number: 0,
    });

    PolytectParams{
        exception_trace, 
        fatal_signals,
        monitor_type,
        verbosity,
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
