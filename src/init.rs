extern crate clap;

use clap::{Arg, App};
use std::convert::TryFrom;
use crate::monitor;
use std::time::Duration;
use crate::emitter::console;
use crate::emitter::tricorder;

const ENABLE_FATAL_SIGNALS_FLAG: &str = "enable-fatal-signals";
const ENABLE_EXCEPTION_TRACE_FLAG: &str = "enable-exception-trace";
const PRINT_FATAL_SIGNALS_CTLNAME: &str = "kernel.print-fatal-signals";
const EXCEPTION_TRACE_CTLNAME: &str = "debug.exception-trace";

const CONSOLE_OUTPUT_FLAG: &str = "console";
const TRICORDER_OUTPUT_FLAG: &str = "tricorder";

const NODE_ID_FLAG: &str = "node";
const UNIDENTIFIED_NODE: &str = "unidentified";

pub struct PolytectParams {
    pub exception_trace: Option<bool>,
    pub fatal_signals: Option<bool>,
    
    pub monitor_type: monitor::MonitorType,

    pub console_config: Option<console::ConsoleConfig>,
    pub tricorder_config: Option<tricorder::TricorderConfig>,

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
                        .arg(Arg::with_name(CONSOLE_OUTPUT_FLAG)
                            .short("c")
                            .long(CONSOLE_OUTPUT_FLAG)
                            .default_value_if(CONSOLE_OUTPUT_FLAG, None, "text")
                            .help(format!("Prints all monitored data to the console. Optionally takes a value of 'text' or 'json'").as_str()))
                        .arg(Arg::with_name(TRICORDER_OUTPUT_FLAG)
                            .short("t")
                            .long(TRICORDER_OUTPUT_FLAG)
                            .takes_value(true)
                            .help(format!("Sends all monitored data to the Polyverse tricorder service. When specified, must provide a Polyverse Account AuthKey which has an authorized scope to publish to Polyverse.").as_str()))
                        .arg(Arg::with_name(NODE_ID_FLAG)
                            .short("n")
                            .long(NODE_ID_FLAG)
                            .default_value_if(TRICORDER_OUTPUT_FLAG, None, UNIDENTIFIED_NODE)
                            .help(format!("All reported events are attributed to this 'node' within your overall organization, allowing for filtering, separation and more...").as_str()))
                        .arg(Arg::with_name("verbose")
                            .short("v")
                            .long("verbose")
                            .multiple(true)
                            .help(format!("Increase debug verbosity of polytect.").as_str()))
                        .get_matches();

    let exception_trace = bool_flag(&matches, ENABLE_EXCEPTION_TRACE_FLAG);
    let fatal_signals = bool_flag(&matches, ENABLE_FATAL_SIGNALS_FLAG);
    let verbosity = u8::try_from(matches.occurrences_of("verbose")).ok().unwrap();
    
    let monitor_type = monitor::MonitorType::DevKMsgReader(monitor::dev_kmsg_reader::KMsgReaderConfig{
        from_sequence_number: 0,
        flush_timeout: Duration::from_secs(1),
    });

    let console_config = match matches.value_of(CONSOLE_OUTPUT_FLAG) {
        None => None,
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "text" => Some(console::ConsoleConfig{
                console_format: console::Format::UserFriendlyText
                }),
            "json" => Some(console::ConsoleConfig{
                console_format: console::Format::JSON
                }),
            _ => None,
        }
    };

    let node_id = match matches.value_of(NODE_ID_FLAG) {
        None => UNIDENTIFIED_NODE,
        Some(n) => n,
    };

    let tricorder_config = match matches.value_of(TRICORDER_OUTPUT_FLAG) {
        None => None,
        Some(v) => Some(tricorder::TricorderConfig{
            auth_key: v.to_owned(),
            node_id: node_id.to_owned(),
            flush_timeout: Duration::from_secs(10),
            flush_event_count: 10,
        })
    };

    PolytectParams{
        exception_trace, 
        fatal_signals,
        monitor_type,
        console_config,
        tricorder_config,
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
