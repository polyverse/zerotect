use crate::system::{EXCEPTION_TRACE_CTLNAME, PRINT_FATAL_SIGNALS_CTLNAME};
use clap::{App, Arg};
use serde::Deserialize;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs;
use std::io;
use std::time::Duration;

const ENABLE_FATAL_SIGNALS_FLAG: &str = "enable-fatal-signals";
const ENABLE_EXCEPTION_TRACE_FLAG: &str = "enable-exception-trace";

const CONSOLE_OUTPUT_FLAG: &str = "console";
const POLYCORDER_OUTPUT_FLAG: &str = "polycorder";

const NODE_ID_FLAG: &str = "node";
const UNIDENTIFIED_NODE: &str = "unidentified";

#[derive(Debug, Clone, Deserialize)]
pub enum ConsoleOutputFormat {
    UserFriendlyText,
    JSON,
}

#[derive(Clone, Deserialize)]
pub struct ConsoleConfig {
    pub console_format: ConsoleOutputFormat,
}

#[derive(Clone, Deserialize)]
pub struct ConsoleConfigOptions {
    pub console_format: Option<ConsoleOutputFormat>,
}

#[derive(Clone, Deserialize)]
pub struct PolycorderConfig {
    pub auth_key: String,
    pub node_id: String,

    // Flush all events if none arrive for this interval
    pub flush_timeout: Duration,

    // Flush after this number of items, even if more are arriving...
    pub flush_event_count: usize,
}

#[derive(Clone, Deserialize)]
pub struct PolycorderConfigOptions {
    pub auth_key: Option<String>,
    pub node_id: Option<String>,

    // Flush all events if none arrive for this interval
    pub flush_timeout: Option<Duration>,

    // Flush after this number of items, even if more are arriving...
    pub flush_event_count: Option<usize>,
}

#[derive(Clone, Deserialize)]
pub struct PolytectParams {
    pub exception_trace: bool,
    pub fatal_signals: bool,

    pub console_config: Option<ConsoleConfig>,
    pub polycorder_config: Option<PolycorderConfig>,

    pub verbosity: u8,
}

#[derive(Clone, Deserialize)]
pub struct PolytectParamOptions {
    pub exception_trace: Option<bool>,
    pub fatal_signals: Option<bool>,

    pub console_config: Option<ConsoleConfigOptions>,
    pub polycorder_config: Option<PolycorderConfigOptions>,

    pub verbosity: Option<u8>,
}

#[derive(Debug)]
pub struct ConfigFileParsingError(String);
impl Error for ConfigFileParsingError {}
impl Display for ConfigFileParsingError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "ConfigFileParsingError:: {}", self)
    }
}
impl From<io::Error> for ConfigFileParsingError {
    fn from(err: io::Error) -> ConfigFileParsingError {
        ConfigFileParsingError(format!("Inner io::Error :: {}", err))
    }
}

/// Parse params from config file if one was provided
/// https://github.com/clap-rs/clap/issues/748
pub fn parse_config_file(
    maybe_file: Option<&str>,
) -> Result<PolytectParamOptions, ConfigFileParsingError> {
    match maybe_file {
        None => Ok(PolytectParamOptions {
            exception_trace: None,
            fatal_signals: None,
            console_config: None,
            polycorder_config: None,
            verbosity: None,
        }),
        Some(filepath) => {
            let _filecontents = fs::read(filepath)?;

            Ok(PolytectParamOptions {
                exception_trace: None,
                fatal_signals: None,
                console_config: None,
                polycorder_config: None,
                verbosity: None,
            })
        }
    }
}

/// Parse command-line arguments
pub fn parse_args() -> PolytectParams {
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
                            .value_name("text|json")
                            .default_value_if(CONSOLE_OUTPUT_FLAG, None, "text")
                            .help(format!("Prints all monitored data to the console. Optionally takes a value of 'text' or 'json'").as_str()))
                        .arg(Arg::with_name(POLYCORDER_OUTPUT_FLAG)
                            .short("p")
                            .long(POLYCORDER_OUTPUT_FLAG)
                            .value_name("authkey")
                            .takes_value(true)
                            .help(format!("Sends all monitored data to the polycorder service. When specified, must provide a Polyverse Account AuthKey which has an authorized scope to publish to Polyverse.").as_str()))
                        .arg(Arg::with_name(NODE_ID_FLAG)
                            .short("n")
                            .long(NODE_ID_FLAG)
                            .value_name("node_identifier")
                            .default_value_if(POLYCORDER_OUTPUT_FLAG, None, UNIDENTIFIED_NODE)
                            .help(format!("All reported events are attributed to this 'node' within your overall organization, allowing for filtering, separation and more...").as_str()))
                        .arg(Arg::with_name("configfile")
                            .long("configfile")
                            .value_name("filepath")
                            .help(format!("Read configuration from a TOML-formatted file. Any command-line parameters also specified will take priority over the file-configured values.").as_str()))
                        .arg(Arg::with_name("verbose")
                            .short("v")
                            .long("verbose")
                            .multiple(true)
                            .help(format!("Increase debug verbosity of polytect.").as_str()))
                        .get_matches();

    let file_configured_params = match parse_config_file(matches.value_of("configfile")) {
        Ok(p) => p,
        Err(e) => {
            panic!(
                "Unable to read configuration parameters from file due to error: {}",
                e
            );
        }
    };

    let exception_trace = bool_flag(&matches, ENABLE_EXCEPTION_TRACE_FLAG)
        .unwrap_or(file_configured_params.exception_trace.unwrap_or(false));

    let fatal_signals = bool_flag(&matches, ENABLE_FATAL_SIGNALS_FLAG)
        .unwrap_or(file_configured_params.fatal_signals.unwrap_or(false));

    let cmd_verbosity_result = u8::try_from(matches.occurrences_of("verbose"));
    let verbosity = match cmd_verbosity_result {
        Ok(cmd_verbosity) => match cmd_verbosity {
            0 => file_configured_params.verbosity.unwrap_or(0),
            v => v,
        },
        Err(e) => panic!("Number of occurrences of verbose flag on commandline couldn't be converted into an 8-bit (one-byte) integer due to Error: {}. That's a LOT of verbosity. Since this is a system-level agent, it does not default to something saner. Aborting program.", e),
    };

    let console_config = match matches.value_of(CONSOLE_OUTPUT_FLAG) {
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "text" => Some(ConsoleConfig {
                console_format: ConsoleOutputFormat::UserFriendlyText,
            }),
            "json" => Some(ConsoleConfig {
                console_format: ConsoleOutputFormat::JSON,
            }),
            unrecognized_format => {
                panic!("Console configuration value set to {}, which is unrecognized. Only supported values are 'text' and 'json'. Since this is a system-level agent, it does not default to something saner. Aborting program", unrecognized_format)
            },
        },
        None => match file_configured_params.console_config {
            Some(c) => match c.console_format {
                Some(cf) => Some(ConsoleConfig{ console_format: cf}),
                None => None,
            }
            None => None,
        },
    };

    // First we need a polycorder auth key - either from CLI and then the file as
    // the secondary source.
    let maybe_polycorder_auth_key = match matches.value_of(POLYCORDER_OUTPUT_FLAG) {
        Some(key) => Some(key.to_owned()),
        None => match file_configured_params.polycorder_config.as_ref() {
            Some(pc) => match pc.auth_key.as_ref() {
                Some(ak) => Some(ak.to_owned()),
                None => None,
            },
            None => None,
        },
    };

    // Only construct Polycorder config if an auth key was found,
    // either on the CLI or from the config file.
    let polycorder_config = match maybe_polycorder_auth_key {
        None => {
            println!("WARNING: No Polycorder auth key found. Not launching an emitter to it. You will not see any events from this host in the Polyverse dashboard.");
            None
        }
        Some(auth_key) => {
            let node_id = match matches.value_of(NODE_ID_FLAG) {
                Some(n) => n.to_owned(),
                None => match file_configured_params.polycorder_config.as_ref() {
                    Some(pc) => match pc.node_id.as_ref() {
                        Some(node_id) => node_id.to_owned(),
                        None => UNIDENTIFIED_NODE.to_owned(),
                    },
                    None => UNIDENTIFIED_NODE.to_owned(),
                },
            };

            let flush_timeout = match file_configured_params.polycorder_config.as_ref() {
                Some(pc) => match pc.flush_timeout {
                    Some(ft) => ft,
                    None => Duration::from_secs(10),
                },
                None => Duration::from_secs(10),
            };

            let flush_event_count = match file_configured_params.polycorder_config.as_ref() {
                Some(pc) => match pc.flush_event_count {
                    Some(fec) => fec,
                    None => 10,
                },
                None => 10,
            };

            Some(PolycorderConfig {
                auth_key,
                node_id,
                flush_timeout,
                flush_event_count,
            })
        }
    };

    PolytectParams {
        exception_trace,
        fatal_signals,
        console_config,
        polycorder_config,
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
        }
    }
}
