use crate::system::{EXCEPTION_TRACE_CTLNAME, PRINT_FATAL_SIGNALS_CTLNAME};
use clap::{App, Arg};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::error::Error;
use std::ffi::OsString;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs;
use std::io;
use std::str;
use std::time::Duration;

const ENABLE_FATAL_SIGNALS_FLAG: &str = "enable-fatal-signals";
const ENABLE_EXCEPTION_TRACE_FLAG: &str = "enable-exception-trace";

const CONSOLE_OUTPUT_FLAG: &str = "console";
const POLYCORDER_OUTPUT_FLAG: &str = "polycorder";

const NODE_ID_FLAG: &str = "node";
const UNIDENTIFIED_NODE: &str = "unidentified";

const CONFIG_FILE_FLAG: &str = "configfile";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConsoleOutputFormat {
    UserFriendlyText,
    JSON,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConsoleConfig {
    pub format: ConsoleOutputFormat,
}

#[derive(Clone, Deserialize)]
pub struct ConsoleConfigOptions {
    pub format: Option<ConsoleOutputFormat>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolycorderConfig {
    pub auth_key: String,
    pub node_id: String,

    // Flush after this number of items, even if more are arriving...
    pub flush_event_count: usize,

    // Flush all events if none arrive for this interval
    pub flush_timeout: Duration,
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolytectParams {
    pub verbosity: u8,

    pub exception_trace: bool,
    pub fatal_signals: bool,

    pub console_config: Option<ConsoleConfig>,
    pub polycorder_config: Option<PolycorderConfig>,
}

#[derive(Clone, Deserialize)]
pub struct PolytectParamOptions {
    pub verbosity: Option<u8>,

    pub exception_trace: Option<bool>,
    pub fatal_signals: Option<bool>,

    pub console_config: Option<ConsoleConfigOptions>,
    pub polycorder_config: Option<PolycorderConfigOptions>,
}

#[derive(Debug)]
pub enum InnerError {
    None,
    IoError(io::Error),
    ClapError(clap::Error),
    Utf8Error(str::Utf8Error),
    TomlDeserializationError(toml::de::Error),
}

#[derive(Debug)]
pub struct ParsingError {
    pub message: String,
    pub inner_error: InnerError,
}
impl Error for ParsingError {}
impl Display for ParsingError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "ParsingError:: {}", self.message)
    }
}
impl From<io::Error> for ParsingError {
    fn from(err: io::Error) -> ParsingError {
        ParsingError {
            message: format!("Inner io::Error :: {}", err),
            inner_error: InnerError::IoError(err),
        }
    }
}
impl From<clap::Error> for ParsingError {
    fn from(err: clap::Error) -> ParsingError {
        ParsingError {
            message: format!("Inner clap::Error :: {}", err),
            inner_error: InnerError::ClapError(err),
        }
    }
}
impl From<str::Utf8Error> for ParsingError {
    fn from(err: str::Utf8Error) -> ParsingError {
        ParsingError {
            message: format!("Inner str::Utf8Error :: {}", err),
            inner_error: InnerError::Utf8Error(err),
        }
    }
}
impl From<toml::de::Error> for ParsingError {
    fn from(err: toml::de::Error) -> ParsingError {
        ParsingError {
            message: format!("Inner toml::de::Error :: {}", err),
            inner_error: InnerError::TomlDeserializationError(err),
        }
    }
}

/// Parse params from config file if one was provided
/// https://github.com/clap-rs/clap/issues/748
pub fn parse_config_file(maybe_file: Option<&str>) -> Result<PolytectParamOptions, ParsingError> {
    match maybe_file {
        None => Ok(PolytectParamOptions {
            exception_trace: None,
            fatal_signals: None,
            console_config: None,
            polycorder_config: None,
            verbosity: None,
        }),
        Some(filepath) => {
            let filecontents = fs::read(filepath)?;
            let polytect_param_options: PolytectParamOptions =
                toml::from_str(str::from_utf8(&filecontents)?)?;
            Ok(polytect_param_options)
        }
    }
}

/// Parse command-line arguments
/// maybe_args - allows unit-testing of arguments. Use None to parse
///     arguments from the operating system.
pub fn parse_args(maybe_args: Option<Vec<OsString>>) -> Result<PolytectParams, ParsingError> {
    let args: Vec<OsString> = match maybe_args {
        Some(args) => args,
        None => {
            let mut osargs = vec![];
            for arg in std::env::args_os().into_iter() {
                osargs.push(arg);
            }
            osargs
        }
    };

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
                            .long(CONFIG_FILE_FLAG)
                            .value_name("filepath")
                            .takes_value(true)
                            .help(format!("Read configuration from a TOML-formatted file. Any command-line parameters also specified will take priority over the file-configured values.").as_str()))
                        .arg(Arg::with_name("verbose")
                            .short("v")
                            .long("verbose")
                            .multiple(true)
                            .help(format!("Increase debug verbosity of polytect.").as_str()))
                        .get_matches_from_safe(args)?;

    let file_configured_params = parse_config_file(matches.value_of("CONFIG_FILE_FLAG"))?;

    let exception_trace = bool_flag(&matches, ENABLE_EXCEPTION_TRACE_FLAG)?
        || file_configured_params.exception_trace.unwrap_or(false);

    let fatal_signals = bool_flag(&matches, ENABLE_FATAL_SIGNALS_FLAG)?
        || file_configured_params.fatal_signals.unwrap_or(false);

    let cmd_verbosity_result = u8::try_from(matches.occurrences_of("verbose"));
    let verbosity = match cmd_verbosity_result {
        Ok(cmd_verbosity) => match cmd_verbosity {
            0 => file_configured_params.verbosity.unwrap_or(0),
            v => v,
        },
        Err(e) => panic!("Number of occurrences of verbose flag on commandline couldn't be converted into an 8-bit (one-byte) integer due to Error: {}. That's a LOT of verbosity. Since this is a system-level agent, it does not default to something saner. Aborting program.", e),
    };

    let console_config = match matches.value_of(CONSOLE_OUTPUT_FLAG) {
        Some(v) => match v.trim().to_ascii_lowercase().as_str() {
            "text" => Some(ConsoleConfig {
                format: ConsoleOutputFormat::UserFriendlyText,
            }),
            "json" => Some(ConsoleConfig {
                format: ConsoleOutputFormat::JSON,
            }),
            unrecognized_format => {
                panic!("Console configuration value set to {}, which is unrecognized. Only supported values are 'text' and 'json'. Since this is a system-level agent, it does not default to something saner. Aborting program", unrecognized_format)
            },
        },
        None => match file_configured_params.console_config {
            Some(c) => match c.format {
                Some(cf) => Some(ConsoleConfig{ format: cf}),
                None => None,
            }
            None => None,
        },
    };

    // First we need a polycorder auth key - either from CLI and then the file as
    // the secondary source.
    let maybe_polycorder_auth_key = match matches.value_of(POLYCORDER_OUTPUT_FLAG) {
        Some(key) => Some(key.trim().to_owned()),
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
                Some(n) => n.trim().to_owned(),
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

    Ok(PolytectParams {
        exception_trace,
        fatal_signals,
        console_config,
        polycorder_config,
        verbosity,
    })
}

fn bool_flag(matches: &clap::ArgMatches, flag_name: &str) -> Result<bool, ParsingError> {
    match matches.occurrences_of(flag_name) {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(ParsingError{
            message: format!("You specified {} flag {} number of times. Please specify it at most once. Aborting program.", flag_name, matches.occurrences_of(flag_name)),
            inner_error: InnerError::None,
        }),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;
    use std::ffi::OsString;
    use std::panic;
    use std::time;

    #[test]
    fn commandline_args_parse_all() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. First param ignored."),
            OsString::from("-e"),
            OsString::from("-f"),
            OsString::from("-c"),
            OsString::from("text"),
            OsString::from("-p"),
            OsString::from("authkey"),
            OsString::from("-n"),
            OsString::from("nodeid"),
            OsString::from("-v"),
        ];

        let config = parse_args(Some(args)).unwrap();

        assert_eq!(true, config.exception_trace);
        assert_eq!(true, config.fatal_signals);
        assert_eq!(true, config.console_config.is_some());
        assert_eq!(true, config.polycorder_config.is_some());
        assert_eq!(1, config.verbosity);

        let cc = config.console_config.unwrap();
        assert_eq!(ConsoleOutputFormat::UserFriendlyText, cc.format);

        let pc = config.polycorder_config.unwrap();
        assert_eq!("authkey", pc.auth_key);
        assert_eq!("nodeid", pc.node_id);
        assert_eq!(time::Duration::from_secs(10), pc.flush_timeout);
        assert_eq!(10, pc.flush_event_count);
    }

    #[test]
    fn commandline_args_parse_space_within_param() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("-e"),
            OsString::from("-f"),
            OsString::from("-c text"),
            OsString::from("-p"),
            OsString::from("authkey"),
            OsString::from("-n"),
            OsString::from("nodeid"),
            OsString::from("-v"),
        ];

        let config = parse_args(Some(args)).unwrap();

        assert_eq!(true, config.exception_trace);
        assert_eq!(true, config.fatal_signals);
        assert_eq!(true, config.console_config.is_some());
        assert_eq!(true, config.polycorder_config.is_some());
        assert_eq!(1, config.verbosity);

        let cc = config.console_config.unwrap();
        assert_eq!(ConsoleOutputFormat::UserFriendlyText, cc.format);

        let pc = config.polycorder_config.unwrap();
        assert_eq!("authkey", pc.auth_key);
        assert_eq!("nodeid", pc.node_id);
        assert_eq!(time::Duration::from_secs(10), pc.flush_timeout);
        assert_eq!(10, pc.flush_event_count);
    }

    #[test]
    fn commandline_args_parse_bools_off() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("-c text"),
            OsString::from("-p"),
            OsString::from("authkey"),
            OsString::from("-n"),
            OsString::from("nodeid"),
            OsString::from("-v"),
        ];

        let config = parse_args(Some(args)).unwrap();

        assert_eq!(false, config.exception_trace);
        assert_eq!(false, config.fatal_signals);
        assert_eq!(true, config.console_config.is_some());
        assert_eq!(true, config.polycorder_config.is_some());
        assert_eq!(1, config.verbosity);

        let cc = config.console_config.unwrap();
        assert_eq!(ConsoleOutputFormat::UserFriendlyText, cc.format);

        let pc = config.polycorder_config.unwrap();
        assert_eq!("authkey", pc.auth_key);
        assert_eq!("nodeid", pc.node_id);
        assert_eq!(time::Duration::from_secs(10), pc.flush_timeout);
        assert_eq!(10, pc.flush_event_count);
    }

    #[test]
    fn commandline_args_parse_invalid_console_format() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("-c invalid"),
        ];

        let result = panic::catch_unwind(|| {
            parse_args(Some(args)).unwrap();
        });
        assert!(result.is_err());
    }

    #[test]
    fn commandline_args_parse_missing_polycorder_authkey() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("-n"),
            OsString::from("nodeid"),
        ];

        let config = parse_args(Some(args)).unwrap();
        assert!(config.polycorder_config.is_none());
    }

    #[test]
    fn commandline_args_parse_multiple_flags() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("-e"),
            OsString::from("-e"),
        ];

        let config = parse_args(Some(args));
        assert!(config.is_err());
    }

    #[test]
    fn commandline_args_parse_multiple_options() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("-c text"),
            OsString::from("-c json"),
        ];

        let config = parse_args(Some(args));
        assert!(config.is_err());
    }

    #[test]
    fn toml_parse_all() {
        let tomlcontents = r#"
        verbosity = 3
        exception_trace = true
        fatal_signals = true

        [console_config]
        format = 'JSON'

        [polycorder_config]
        auth_key = 'AuthKeyFromAccountManager'
        node_id = 'NodeDiscriminator'
        flush_event_count = 10

        [polycorder_config.flush_timeout]
        secs = 10
        nanos = 0
        "#;

        let toml_file = format!(
            "/tmp/config_{}.toml",
            rand::thread_rng().gen_range(0, 32000)
        );
        println!("Writing TOML string to file: {}", &toml_file);
        fs::write(&toml_file, tomlcontents).expect("Unable to write TOML test file.");

        let maybe_config = parse_config_file(Some(&toml_file));
        if let Err(e) = &maybe_config {
            match &e.inner_error {
                InnerError::ClapError(ce) => ce.exit(),
                _ => assert!(
                    false,
                    "Unexpected error when parsing command-line config file flag."
                ),
            }
        }
        let config = maybe_config.unwrap();

        assert_eq!(true, config.exception_trace.unwrap());
        assert_eq!(true, config.fatal_signals.unwrap());
        assert_eq!(true, config.console_config.is_some());
        assert_eq!(true, config.polycorder_config.is_some());
        assert_eq!(3, config.verbosity.unwrap());

        let cc = config.console_config.unwrap();
        assert_eq!(ConsoleOutputFormat::JSON, cc.format.unwrap());

        let pc = config.polycorder_config.unwrap();
        assert_eq!("AuthKeyFromAccountManager", pc.auth_key.unwrap());
        assert_eq!("NodeDiscriminator", pc.node_id.unwrap());
        assert_eq!(time::Duration::from_secs(10), pc.flush_timeout.unwrap());
        assert_eq!(10, pc.flush_event_count.unwrap());
    }

    #[test]
    fn toml_serialize_and_parse_random_values() {
        let config_expected = PolytectParams {
            exception_trace: rand::thread_rng().gen_bool(0.5),
            fatal_signals: rand::thread_rng().gen_bool(0.5),
            console_config: Some(ConsoleConfig {
                format: match rand::thread_rng().gen_bool(0.5) {
                    true => ConsoleOutputFormat::JSON,
                    false => ConsoleOutputFormat::UserFriendlyText,
                },
            }),
            polycorder_config: Some(PolycorderConfig {
                auth_key: format!(
                    "AuthKeyFromAccountManagerRandom{}",
                    rand::thread_rng().gen_range(0, 32000)
                ),
                node_id: format!(
                    "NodeDiscriminatorRandom{}",
                    rand::thread_rng().gen_range(0, 32000)
                ),
                flush_timeout: time::Duration::from_secs(rand::thread_rng().gen_range(0, 500)),
                flush_event_count: rand::thread_rng().gen_range(0, 500),
            }),
            verbosity: rand::thread_rng().gen_range(0, 250),
        };

        let toml_file = format!(
            "/tmp/config_{}.toml",
            rand::thread_rng().gen_range(0, 32000)
        );
        let config_toml_string = toml::to_string_pretty(&config_expected).unwrap();
        println!("Writing TOML string to file: {}", &toml_file);
        fs::write(&toml_file, config_toml_string).expect("Unable to write TOML test file.");

        let maybe_config = parse_config_file(Some(&toml_file));
        if let Err(e) = &maybe_config {
            match &e.inner_error {
                InnerError::ClapError(ce) => ce.exit(),
                _ => assert!(
                    false,
                    "Unexpected error when parsing command-line config file flag."
                ),
            }
        }
        let config_options_obtained = maybe_config.unwrap();

        let polycorder_options_config = config_options_obtained.polycorder_config.unwrap();
        let polycorder_config = PolycorderConfig {
            auth_key: polycorder_options_config.auth_key.unwrap(),
            node_id: polycorder_options_config.node_id.unwrap(),
            flush_timeout: polycorder_options_config.flush_timeout.unwrap(),
            flush_event_count: polycorder_options_config.flush_event_count.unwrap(),
        };

        let console_config = ConsoleConfig {
            format: config_options_obtained
                .console_config
                .unwrap()
                .format
                .unwrap(),
        };

        let config_obtained = PolytectParams {
            verbosity: config_options_obtained.verbosity.unwrap(),
            exception_trace: config_options_obtained.exception_trace.unwrap(),
            fatal_signals: config_options_obtained.fatal_signals.unwrap(),
            polycorder_config: Some(polycorder_config),
            console_config: Some(console_config),
        };

        assert_eq!(config_expected, config_obtained);
    }

    #[test]
    fn toml_parse_all_through_args() {
        let tomlcontents = r#"
        verbosity = 3
        exception_trace = true
        fatal_signals = true

        [console_config]
        format = 'JSON'

        [polycorder_config]
        auth_key = 'AuthKeyFromAccountManager'
        node_id = 'NodeDiscriminator'
        flush_event_count = 10

        [polycorder_config.flush_timeout]
        secs = 10
        nanos = 0
        "#;

        let toml_file = format!(
            "/tmp/config_{}.toml",
            rand::thread_rng().gen_range(0, 32000)
        );
        println!("Writing TOML string to file: {}", &toml_file);
        fs::write(&toml_file, tomlcontents).expect("Unable to write TOML test file.");

        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("--configfile"),
            OsString::from(&toml_file),
        ];

        let maybe_config = parse_args(Some(args));
        if let Err(e) = &maybe_config {
            match &e.inner_error {
                InnerError::ClapError(ce) => ce.exit(),
                _ => assert!(
                    false,
                    "Unexpected error when parsing command-line config file flag."
                ),
            }
        }
        let config = maybe_config.unwrap();

        assert_eq!(true, config.exception_trace);
        assert_eq!(true, config.fatal_signals);
        assert_eq!(true, config.console_config.is_some());
        assert_eq!(true, config.polycorder_config.is_some());
        assert_eq!(3, config.verbosity);

        let cc = config.console_config.unwrap();
        assert_eq!(ConsoleOutputFormat::JSON, cc.format);

        let pc = config.polycorder_config.unwrap();
        assert_eq!("AuthKeyFromAccountManager", pc.auth_key);
        assert_eq!("NodeDiscriminator", pc.node_id);
        assert_eq!(time::Duration::from_secs(10), pc.flush_timeout);
        assert_eq!(10, pc.flush_event_count);
    }

    #[test]
    fn toml_serialize_and_parse_random_values_through_args() {
        let config_expected = PolytectParams {
            exception_trace: rand::thread_rng().gen_bool(0.5),
            fatal_signals: rand::thread_rng().gen_bool(0.5),
            console_config: Some(ConsoleConfig {
                format: match rand::thread_rng().gen_bool(0.5) {
                    true => ConsoleOutputFormat::JSON,
                    false => ConsoleOutputFormat::UserFriendlyText,
                },
            }),
            polycorder_config: Some(PolycorderConfig {
                auth_key: format!(
                    "AuthKeyFromAccountManagerRandom{}",
                    rand::thread_rng().gen_range(0, 32000)
                ),
                node_id: format!(
                    "NodeDiscriminatorRandom{}",
                    rand::thread_rng().gen_range(0, 32000)
                ),
                flush_timeout: time::Duration::from_secs(rand::thread_rng().gen_range(0, 500)),
                flush_event_count: rand::thread_rng().gen_range(0, 500),
            }),
            verbosity: rand::thread_rng().gen_range(0, 250),
        };

        let toml_file = format!(
            "/tmp/config_{}.toml",
            rand::thread_rng().gen_range(0, 32000)
        );
        let config_toml_string = toml::to_string_pretty(&config_expected).unwrap();
        println!("Writing TOML string to file: {}", &toml_file);
        fs::write(&toml_file, config_toml_string).expect("Unable to write TOML test file.");

        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("--configfile"),
            OsString::from(&toml_file),
        ];

        let maybe_config = parse_args(Some(args));
        if let Err(e) = &maybe_config {
            match &e.inner_error {
                InnerError::ClapError(ce) => ce.exit(),
                _ => assert!(
                    false,
                    "Unexpected error when parsing command-line config file flag."
                ),
            }
        }
        let config_obtained = maybe_config.unwrap();

        assert_eq!(config_expected, config_obtained);
    }
}
