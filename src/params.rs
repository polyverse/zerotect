// Copyright (c) 2019 Polyverse Corporation


use crate::system::{EXCEPTION_TRACE_CTLNAME, PRINT_FATAL_SIGNALS_CTLNAME};
use clap::{App, AppSettings, Arg};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::error::Error;
use std::ffi::OsString;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs;
use std::io;
use std::str;
use std::str::FromStr;
use std::time::Duration;
use strum_macros::EnumString;

const AUTO_CONFIGURE: &str = "auto-configure";

const CONSOLE_OUTPUT_FLAG: &str = "console";

const POLYCORDER_OUTPUT_FLAG: &str = "polycorder";
const NODE_ID_FLAG: &str = "node";
const UNIDENTIFIED_NODE: &str = "unidentified";
const FLUSH_TIMEOUT_SECONDS_FLAG: &str = "flush-timeout-secs";
const FLUSH_EVENT_COUNT_FLAG: &str = "flush-event-count";

const CONFIG_FILE_FLAG: &str = "configfile";

const DEFAULT_POLYCORDER_FLUSH_EVENT_COUNT: usize = 10;
const DEFAULT_POLYCORDER_FLUSH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, EnumString)]
pub enum ConsoleOutputFormat {
    #[strum(serialize = "text")]
    Text,
    #[strum(serialize = "json")]
    JSON,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConsoleConfig {
    pub format: ConsoleOutputFormat,
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AutoConfigure {
    pub exception_trace: bool,
    pub fatal_signals: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolytectParams {
    pub verbosity: u8,

    pub auto_configure: AutoConfigure,

    pub console_config: Option<ConsoleConfig>,
    pub polycorder_config: Option<PolycorderConfig>,
}

// A proxy-structure to deserialize into
// really helps with TOML-deserialization to know
// what values were specified in TOML and which ones
// were not.
#[derive(Deserialize)]
pub struct PolytectParamOptions {
    pub verbosity: Option<u8>,

    pub auto_configure: Option<AutoConfigureOptions>,

    pub console_config: Option<ConsoleConfigOptions>,
    pub polycorder_config: Option<PolycorderConfigOptions>,
}

// A proxy-structure to deserialize into
// really helps with TOML-deserialization to know
// what values were specified in TOML and which ones
// were not.#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[derive(Deserialize)]
pub struct AutoConfigureOptions {
    pub exception_trace: Option<bool>,
    pub fatal_signals: Option<bool>,
}

// A proxy-structure to deserialize into
// really helps with TOML-deserialization to know
// what values were specified in TOML and which ones
// were not.
#[derive(Deserialize)]
pub struct PolycorderConfigOptions {
    pub auth_key: Option<String>,
    pub node_id: Option<String>,

    // Flush all events if none arrive for this interval
    pub flush_timeout: Option<Duration>,

    // Flush after this number of items, even if more are arriving...
    pub flush_event_count: Option<usize>,
}

// A proxy-structure to deserialize into
// really helps with TOML-deserialization to know
// what values were specified in TOML and which ones
// were not.
#[derive(Deserialize)]
pub struct ConsoleConfigOptions {
    pub format: Option<String>,
}

#[derive(Debug)]
pub enum InnerError {
    None,
    IoError(io::Error),
    ClapError(clap::Error),
    Utf8Error(str::Utf8Error),
    TomlDeserializationError(toml::de::Error),
    StrumParseError(strum::ParseError),
    ParseIntError(std::num::ParseIntError),
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
impl From<std::num::ParseIntError> for ParsingError {
    fn from(err: std::num::ParseIntError) -> ParsingError {
        ParsingError {
            message: format!("Inner std::num::ParseIntError :: {}", err),
            inner_error: InnerError::ParseIntError(err),
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
                        .setting(AppSettings::DeriveDisplayOrder)
                        .version("1.0")
                        .author("Polyverse Corporation <support@polyverse.com>")
                        .about("Detect attempted (and ultimately failed) attacks and exploits using known and unknown vulnerabilities by observing side effects (segfaults, crashes, etc.)")
                        .arg(Arg::with_name(CONFIG_FILE_FLAG)
                            .long(CONFIG_FILE_FLAG)
                            .value_name("filepath")
                            .takes_value(true)
                            .conflicts_with_all(&[AUTO_CONFIGURE, CONSOLE_OUTPUT_FLAG, POLYCORDER_OUTPUT_FLAG, NODE_ID_FLAG, "verbose"])
                            .help(format!("Read configuration from a TOML-formatted file. When specified, all other command-line arguments are ignored. (NOTE: Considerably more options can be configured in the file than through CLI arguments.)").as_str()))
                        .arg(Arg::with_name(AUTO_CONFIGURE)
                            .long(AUTO_CONFIGURE)
                            .value_name("sysctl-flag-to-auto-configure")
                            .takes_value(true)
                            .possible_values(&[EXCEPTION_TRACE_CTLNAME, PRINT_FATAL_SIGNALS_CTLNAME])
                            .multiple(true)
                            .help(format!("Automatically configure the system on the user's behalf.").as_str()))
                        .arg(Arg::with_name(CONSOLE_OUTPUT_FLAG)
                            .long(CONSOLE_OUTPUT_FLAG)
                            .value_name("format")
                            .possible_values(&["text", "json"])
                            .case_insensitive(true)
                            .help(format!("Prints all monitored data to the console in the specified format.").as_str()))
                        .arg(Arg::with_name(POLYCORDER_OUTPUT_FLAG)
                            .long(POLYCORDER_OUTPUT_FLAG)
                            .value_name("authkey")
                            .takes_value(true)
                            .empty_values(false)
                            .help(format!("Sends all monitored data to the polycorder service. When specified, must provide a Polyverse Account AuthKey which has an authorized scope to publish to Polyverse.").as_str()))
                        .arg(Arg::with_name(NODE_ID_FLAG)
                            .long(NODE_ID_FLAG)
                            .value_name("node_identifier")
                            .empty_values(false)
                            .requires(POLYCORDER_OUTPUT_FLAG)
                            .help(format!("All reported events are attributed to this 'node' within your overall organization, allowing for filtering, separation and more.").as_str()))
                        .arg(Arg::with_name(FLUSH_TIMEOUT_SECONDS_FLAG)
                            .long(FLUSH_TIMEOUT_SECONDS_FLAG)
                            .value_name("seconds")
                            .empty_values(false)
                            .requires(POLYCORDER_OUTPUT_FLAG)
                            .help(format!("After how many seconds should events be flushed to Polycorder, if no new events occur. This avoids chatty communication with Polycorder.").as_str()))
                        .arg(Arg::with_name(FLUSH_EVENT_COUNT_FLAG)
                            .long(FLUSH_EVENT_COUNT_FLAG)
                            .value_name("count")
                            .empty_values(false)
                            .requires(POLYCORDER_OUTPUT_FLAG)
                            .help(format!("The number of events, when buffered, are flushed to Polycorder. This allows batching of events. Make this too high, and upon failure, a large number of events may be lost. Make it too low, and connections will be chatty.").as_str()))
                        .arg(Arg::with_name("verbose")
                            .short("v")
                            .long("verbose")
                            .multiple(true)
                            .help(format!("Increase debug verbosity of polytect.").as_str()))
                        .get_matches_from_safe(args)?;

    if let Some(configfile) = matches.value_of(CONFIG_FILE_FLAG) {
        let file_configured_params = parse_config_file(configfile)?;
        return Ok(file_configured_params);
    }

    let maybe_auto_conf_values = matches.values_of(AUTO_CONFIGURE);
    let auto_configure = match maybe_auto_conf_values {
        Some(auto_conf_values) => AutoConfigure {
            exception_trace: auto_configure_flag(
                auto_conf_values.clone(),
                EXCEPTION_TRACE_CTLNAME,
            )?,
            fatal_signals: auto_configure_flag(
                auto_conf_values.clone(),
                PRINT_FATAL_SIGNALS_CTLNAME,
            )?,
        },
        None => AutoConfigure {
            exception_trace: false,
            fatal_signals: false,
        },
    };

    let verbosity = match u8::try_from(matches.occurrences_of("verbose")) {
        Ok(cmd_verbosity) => cmd_verbosity,
        Err(e) => panic!("Number of occurrences of verbose flag on commandline couldn't be converted into an 8-bit (one-byte) integer due to Error: {}. That's a LOT of verbosity. Since this is a system-level agent, it does not default to something saner. Aborting program.", e),
    };

    let console_config = match matches.value_of(CONSOLE_OUTPUT_FLAG) {
        Some(v) => match ConsoleOutputFormat::from_str(v.trim().to_ascii_lowercase().as_str()) {
            Ok(format) => Some(ConsoleConfig{format}),
            Err(e) => {
                return Err(ParsingError{inner_error: InnerError::None, message: format!("Console configuration value set to {} had a parsing error: {}. Since this is a system-level agent, it does not default to something saner. Aborting program", v, e)})
            },
        },
        None => None,
    };

    // First we need a polycorder auth key - either from CLI and then the file as
    // the secondary source.
    let polycorder_config = match matches.value_of(POLYCORDER_OUTPUT_FLAG) {
        None => None,
        Some(key) => {
            // Only construct Polycorder config if an auth key was found,
            // either on the CLI or from the config file.
            let auth_key = key.trim().to_owned();

            let node_id = match matches.value_of(NODE_ID_FLAG) {
                Some(n) => n.trim().to_owned(),
                None => UNIDENTIFIED_NODE.to_owned(),
            };

            let flush_timeout = match matches.value_of(FLUSH_TIMEOUT_SECONDS_FLAG) {
                Some(nstr) => Duration::from_secs(nstr.parse::<u64>()?),
                None => DEFAULT_POLYCORDER_FLUSH_TIMEOUT,
            };

            let flush_event_count = match matches.value_of(FLUSH_EVENT_COUNT_FLAG) {
                Some(nstr) => nstr.parse::<usize>()?,
                None => DEFAULT_POLYCORDER_FLUSH_EVENT_COUNT,
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
        auto_configure,
        console_config,
        polycorder_config,
        verbosity,
    })
}

/// Parse params from config file if one was provided
/// https://github.com/clap-rs/clap/issues/748
pub fn parse_config_file(filepath: &str) -> Result<PolytectParams, ParsingError> {
    let filecontents = fs::read(filepath)?;
    let polytect_param_options: PolytectParamOptions =
        toml::from_str(str::from_utf8(&filecontents)?)?;

    let params = PolytectParams{
            verbosity: polytect_param_options.verbosity.unwrap_or(0),
            auto_configure: match polytect_param_options.auto_configure {
                Some(ac) => AutoConfigure {
                    exception_trace: ac.exception_trace.unwrap_or(false),
                    fatal_signals: ac.fatal_signals.unwrap_or(false),
                },
                None => AutoConfigure{
                    exception_trace: false,
                    fatal_signals: false
                },
            },
            console_config: match polytect_param_options.console_config {
                Some(cco) => match cco.format {
                    Some(f) => match ConsoleOutputFormat::from_str(f.trim().to_ascii_lowercase().as_str()) {
                        Ok(format) => Some(ConsoleConfig{format}),
                        Err(e) => return Err(ParsingError{inner_error: InnerError::StrumParseError(e), message: format!("Unable to parse {} into the enum ConsoleOutputFormat, due to error: {}", f, e)}),
                    },
                    None => None,
                }
                None => None,
            },
            polycorder_config: match polytect_param_options.polycorder_config {
                None => None,
                Some(pco) => {
                    match pco.auth_key {
                        None => None,
                        Some(ak) => Some(PolycorderConfig{
                            auth_key: ak.trim().to_owned(),
                            node_id: pco.node_id.unwrap_or(UNIDENTIFIED_NODE.to_owned()),
                            flush_event_count: pco.flush_event_count.unwrap_or(DEFAULT_POLYCORDER_FLUSH_EVENT_COUNT),
                            flush_timeout:  pco.flush_timeout.unwrap_or(DEFAULT_POLYCORDER_FLUSH_TIMEOUT),
                        }),
                    }
                }
            }
        };

    Ok(params)
}

fn auto_configure_flag(values: clap::Values, value: &str) -> Result<bool, ParsingError> {
    let mut seen_before: bool = false;
    for val in values {
        if val == value {
            if !seen_before {
                seen_before = true
            } else {
                return Err(ParsingError{
                    inner_error: InnerError::None,
                    message: format!("Auto-configure value '{}' found more than once. Please set it at most once.", value),
                });
            }
        }
    }
    return Ok(seen_before);
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;
    use std::ffi::OsString;
    use std::panic;

    fn unique_temp_toml_file() -> String {
        format!(
            "/tmp/config_{}.toml",
            rand::thread_rng().gen_range(0, 32000)
        )
    }

    #[test]
    fn commandline_args_parse_all() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. First param ignored."),
            OsString::from("--auto-configure"),
            OsString::from(EXCEPTION_TRACE_CTLNAME),
            OsString::from("--auto-configure"),
            OsString::from(PRINT_FATAL_SIGNALS_CTLNAME),
            OsString::from("--console"),
            OsString::from("text"),
            OsString::from("--polycorder"),
            OsString::from("authkey"),
            OsString::from("--node"),
            OsString::from("nodeid34235"),
            OsString::from("--flush-event-count"),
            OsString::from("53"),
            OsString::from("--flush-timeout-secs"),
            OsString::from("89"),
            OsString::from("-v"),
        ];

        let config = parse_args(Some(args)).unwrap();

        assert_eq!(true, config.auto_configure.exception_trace);
        assert_eq!(true, config.auto_configure.fatal_signals);
        assert_eq!(true, config.console_config.is_some());
        assert_eq!(true, config.polycorder_config.is_some());
        assert_eq!(1, config.verbosity);

        let cc = config.console_config.unwrap();
        assert_eq!(ConsoleOutputFormat::Text, cc.format);

        let pc = config.polycorder_config.unwrap();
        assert_eq!("authkey", pc.auth_key);
        assert_eq!("nodeid34235", pc.node_id);
        assert_eq!(Duration::from_secs(89), pc.flush_timeout);
        assert_eq!(53, pc.flush_event_count);
    }

    #[test]
    fn commandline_args_parse_space_within_param() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from(format!("--auto-configure {}", EXCEPTION_TRACE_CTLNAME)),
            OsString::from(format!("--auto-configure {}", PRINT_FATAL_SIGNALS_CTLNAME)),
            OsString::from("--console text"),
            OsString::from("--polycorder authkey231241"),
        ];

        let maybe_config = parse_args(Some(args));
        assert!(maybe_config.is_err());
    }

    #[test]
    fn commandline_args_parse_space_across_param() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from(format!("--auto-configure")),
            OsString::from(format!(
                "{} --auto-configure {}",
                EXCEPTION_TRACE_CTLNAME, PRINT_FATAL_SIGNALS_CTLNAME
            )),
            OsString::from("--console"),
            OsString::from("text --polycorder authkey346534"),
        ];

        let maybe_config = parse_args(Some(args));
        assert!(maybe_config.is_err());
    }

    #[test]
    fn commandline_args_parse_invalid_console_format() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("--console invalid"),
        ];

        let maybe_parsed = parse_args(Some(args));
        assert!(maybe_parsed.is_err());
    }

    #[test]
    fn commandline_args_parse_case_insensitive_console_format() {
        {
            let args: Vec<OsString> = vec![
                OsString::from("burner program name. Also test words aren't split"),
                OsString::from("--console"),
                OsString::from("Text"),
            ];

            let pc = parse_args(Some(args));
            assert!(
                pc.is_ok(),
                "Error parsing arguments for text: {}",
                pc.err().unwrap()
            );
            assert_eq!(
                ConsoleOutputFormat::Text,
                pc.unwrap().console_config.unwrap().format
            )
        }

        {
            let args: Vec<OsString> = vec![
                OsString::from("burner program name. Also test words aren't split"),
                OsString::from("--console"),
                OsString::from("jSoN"),
            ];

            let pc = parse_args(Some(args));
            assert!(
                pc.is_ok(),
                "Error parsing arguments for json: {}",
                pc.err().unwrap()
            );
            assert_eq!(
                ConsoleOutputFormat::JSON,
                pc.unwrap().console_config.unwrap().format
            );
        }
    }

    #[test]
    fn commandline_args_parse_missing_polycorder_authkey() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("--node"),
            OsString::from("nodeid"),
            OsString::from("--flush-event-count"),
            OsString::from("20"),
            OsString::from("--flush-timeout-secs"),
            OsString::from("15"),
        ];

        let maybe_parsed = parse_args(Some(args));
        assert!(maybe_parsed.is_err());
    }

    #[test]
    fn commandline_args_parse_polycorder_defaults() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("--polycorder"),
            OsString::from("authkey97097"),
        ];

        let maybe_parsed = parse_args(Some(args));
        assert!(maybe_parsed.is_ok());

        let config = maybe_parsed.unwrap();
        assert!(config.polycorder_config.is_some());

        let pc = config.polycorder_config.unwrap();
        assert_eq!("authkey97097", pc.auth_key);
        assert_eq!(UNIDENTIFIED_NODE, pc.node_id);
        assert_eq!(DEFAULT_POLYCORDER_FLUSH_TIMEOUT, pc.flush_timeout);
        assert_eq!(DEFAULT_POLYCORDER_FLUSH_EVENT_COUNT, pc.flush_event_count);
    }

    #[test]
    fn commandline_args_parse_multiple_options() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("--console"),
            OsString::from("text"),
            OsString::from("--console"),
            OsString::from("json"),
        ];

        let config = parse_args(Some(args));
        assert!(config.is_err());
    }

    #[test]
    fn commandline_args_parse_multiple_auto_configs() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("--auto-configure"),
            OsString::from(EXCEPTION_TRACE_CTLNAME),
            OsString::from("--auto-configure"),
            OsString::from(PRINT_FATAL_SIGNALS_CTLNAME),
            OsString::from("--auto-configure"),
            OsString::from(EXCEPTION_TRACE_CTLNAME),
        ];

        let config = parse_args(Some(args));
        assert!(config.is_err());
    }

    #[test]
    fn toml_parse_all() {
        let tomlcontents = r#"
        verbosity = 40

        [auto_configure]
        exception_trace = true
        fatal_signals = true

        [console_config]
        format = 'text'

        [polycorder_config]
        auth_key = 'AuthKeyFromAccountManager3700793'
        node_id = 'NodeDiscriminator5462654'
        flush_event_count = 23

        [polycorder_config.flush_timeout]
        secs = 39
        nanos = 0
        "#;

        let toml_file = unique_temp_toml_file();
        println!("Writing TOML string to file: {}", &toml_file);
        fs::write(&toml_file, tomlcontents).expect("Unable to write TOML test file.");

        let config = parse_config_file(&toml_file).unwrap();

        assert_eq!(true, config.auto_configure.exception_trace);
        assert_eq!(true, config.auto_configure.fatal_signals);
        assert_eq!(true, config.console_config.is_some());
        assert_eq!(true, config.polycorder_config.is_some());
        assert_eq!(40, config.verbosity);

        let cc = config.console_config.unwrap();
        assert_eq!(ConsoleOutputFormat::Text, cc.format);

        let pc = config.polycorder_config.unwrap();
        assert_eq!("AuthKeyFromAccountManager3700793", pc.auth_key);
        assert_eq!("NodeDiscriminator5462654", pc.node_id);
        assert_eq!(Duration::from_secs(39), pc.flush_timeout);
        assert_eq!(23, pc.flush_event_count);
    }

    #[test]
    fn toml_serialize_and_parse_random_values() {
        let config_expected = PolytectParams {
            auto_configure: AutoConfigure {
                exception_trace: rand::thread_rng().gen_bool(0.5),
                fatal_signals: rand::thread_rng().gen_bool(0.5),
            },
            console_config: Some(ConsoleConfig {
                format: match rand::thread_rng().gen_bool(0.5) {
                    true => ConsoleOutputFormat::JSON,
                    false => ConsoleOutputFormat::Text,
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
                flush_timeout: Duration::from_secs(rand::thread_rng().gen_range(0, 500)),
                flush_event_count: rand::thread_rng().gen_range(0, 500),
            }),
            verbosity: rand::thread_rng().gen_range(0, 250),
        };

        let toml_file = unique_temp_toml_file();
        let config_toml_string = toml::to_string_pretty(&config_expected).unwrap();
        println!("Writing TOML string to file: {}", &toml_file);
        fs::write(&toml_file, &config_toml_string).expect("Unable to write TOML test file.");

        let maybe_config = parse_config_file(&toml_file);
        if let Err(e) = &maybe_config {
            match &e.inner_error {
                InnerError::ClapError(ce) => ce.exit(),
                e => assert!(
                    false,
                    "Unexpected error when parsing command-line config file flag: {:?}",
                    e
                ),
            }
        }
        let config_options_obtained = maybe_config.unwrap();

        let polycorder_options_config = config_options_obtained.polycorder_config.unwrap();
        let polycorder_config = PolycorderConfig {
            auth_key: polycorder_options_config.auth_key,
            node_id: polycorder_options_config.node_id,
            flush_timeout: polycorder_options_config.flush_timeout,
            flush_event_count: polycorder_options_config.flush_event_count,
        };

        let console_config = ConsoleConfig {
            format: config_options_obtained.console_config.unwrap().format,
        };

        let config_obtained = PolytectParams {
            verbosity: config_options_obtained.verbosity,
            auto_configure: config_options_obtained.auto_configure,
            polycorder_config: Some(polycorder_config),
            console_config: Some(console_config),
        };

        assert_eq!(
            config_expected, config_obtained,
            "The File contents are: \n\n{}",
            &config_toml_string
        );
    }

    #[test]
    fn toml_parse_all_through_args() {
        let tomlcontents = r#"
        verbosity = 7

        [auto_configure]
        exception_trace = true
        fatal_signals = true

        [console_config]
        format = 'Text'

        [polycorder_config]
        auth_key = 'AuthKeyFromPolyverseAccountManager97439'
        node_id = 'UsefulNodeIdentifierToGroupEvents903439'
        flush_event_count = 10

        [polycorder_config.flush_timeout]
        secs = 10
        nanos = 0
        "#;

        let toml_file = unique_temp_toml_file();
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
                e => assert!(
                    false,
                    "Unexpected error when parsing command-line config file flag: {:?}",
                    e
                ),
            }
        }
        let config = maybe_config.unwrap();

        assert_eq!(true, config.auto_configure.exception_trace);
        assert_eq!(true, config.auto_configure.fatal_signals);
        assert_eq!(true, config.console_config.is_some());
        assert_eq!(true, config.polycorder_config.is_some());
        assert_eq!(7, config.verbosity);

        let cc = config.console_config.unwrap();
        assert_eq!(ConsoleOutputFormat::Text, cc.format);

        let pc = config.polycorder_config.unwrap();
        assert_eq!("AuthKeyFromPolyverseAccountManager97439", pc.auth_key);
        assert_eq!("UsefulNodeIdentifierToGroupEvents903439", pc.node_id);
        assert_eq!(Duration::from_secs(10), pc.flush_timeout);
        assert_eq!(10, pc.flush_event_count);
    }

    #[test]
    fn toml_serialize_and_parse_random_values_through_args() {
        let config_expected = PolytectParams {
            auto_configure: AutoConfigure {
                exception_trace: rand::thread_rng().gen_bool(0.5),
                fatal_signals: rand::thread_rng().gen_bool(0.5),
            },
            console_config: Some(ConsoleConfig {
                format: match rand::thread_rng().gen_bool(0.5) {
                    true => ConsoleOutputFormat::JSON,
                    false => ConsoleOutputFormat::Text,
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
                flush_timeout: Duration::from_secs(rand::thread_rng().gen_range(0, 500)),
                flush_event_count: rand::thread_rng().gen_range(0, 500),
            }),
            verbosity: rand::thread_rng().gen_range(0, 250),
        };

        let toml_file = unique_temp_toml_file();
        let config_toml_string = toml::to_string_pretty(&config_expected).unwrap();
        println!("Writing TOML string to file: {}", &toml_file);
        fs::write(&toml_file, &config_toml_string).expect("Unable to write TOML test file.");

        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("--configfile"),
            OsString::from(&toml_file),
        ];

        let config_obtained = parse_args(Some(args)).unwrap();

        assert_eq!(
            config_expected, config_obtained,
            "The File contents are: \n\n{}",
            &config_toml_string
        );
    }

    #[test]
    fn toml_serialize_and_parse_optional_fields_through_args() {
        let config_expected = PolytectParams {
            auto_configure: AutoConfigure {
                exception_trace: rand::thread_rng().gen_bool(0.5),
                fatal_signals: rand::thread_rng().gen_bool(0.5),
            },
            console_config: match rand::thread_rng().gen_bool(0.5) {
                true => Some(ConsoleConfig {
                    format: match rand::thread_rng().gen_bool(0.5) {
                        true => ConsoleOutputFormat::JSON,
                        false => ConsoleOutputFormat::Text,
                    },
                }),
                false => None,
            },
            polycorder_config: match rand::thread_rng().gen_bool(0.5) {
                true => Some(PolycorderConfig {
                    auth_key: format!(
                        "AuthKeyFromAccountManagerRandom{}",
                        rand::thread_rng().gen_range(0, 32000)
                    ),
                    node_id: format!(
                        "NodeDiscriminatorRandom{}",
                        rand::thread_rng().gen_range(0, 32000)
                    ),
                    flush_timeout: Duration::from_secs(rand::thread_rng().gen_range(0, 500)),
                    flush_event_count: rand::thread_rng().gen_range(0, 500),
                }),
                false => None,
            },
            verbosity: rand::thread_rng().gen_range(0, 250),
        };

        let toml_file = unique_temp_toml_file();
        let config_toml_string = toml::to_string_pretty(&config_expected).unwrap();
        println!("Writing TOML string to file: {}", &toml_file);
        fs::write(&toml_file, &config_toml_string).expect("Unable to write TOML test file.");

        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("--configfile"),
            OsString::from(&toml_file),
        ];

        let config_obtained = parse_args(Some(args)).unwrap();

        assert_eq!(
            config_expected, config_obtained,
            "The File contents are: \n\n{}",
            &config_toml_string
        );
    }

    #[test]
    fn toml_parse_empty_file() {
        let tomlcontents = r#"
        "#;

        let toml_file = unique_temp_toml_file();
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
                e => assert!(
                    false,
                    "Unexpected error when parsing command-line config file flag: {:?}",
                    e
                ),
            }
        }
        let config = maybe_config.unwrap();

        assert_eq!(false, config.auto_configure.exception_trace);
        assert_eq!(false, config.auto_configure.fatal_signals);
        assert_eq!(false, config.console_config.is_some());
        assert_eq!(false, config.polycorder_config.is_some());
        assert_eq!(0, config.verbosity);
    }

    #[test]
    fn toml_parse_parse_partial_fields() {
        let tomlcontents = r#"
        verbosity = 5

        [polycorder_config]
        auth_key = "AuthKeyFromAccountManager5323552"

        [polycorder_config.flush_timeout]
        secs = 10
        nanos = 0
        "#;

        let toml_file = unique_temp_toml_file();
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
                e => assert!(
                    false,
                    "Unexpected error when parsing command-line config file flag: {:?}",
                    e
                ),
            }
        }
        let config = maybe_config.unwrap();

        assert_eq!(false, config.auto_configure.exception_trace);
        assert_eq!(false, config.auto_configure.fatal_signals);
        assert_eq!(false, config.console_config.is_some());
        assert_eq!(true, config.polycorder_config.is_some());
        assert_eq!(5, config.verbosity);

        let pc = config.polycorder_config.unwrap();
        assert_eq!("AuthKeyFromAccountManager5323552", pc.auth_key);
        assert_eq!(UNIDENTIFIED_NODE, pc.node_id);
        assert_eq!(DEFAULT_POLYCORDER_FLUSH_TIMEOUT, pc.flush_timeout);
        assert_eq!(DEFAULT_POLYCORDER_FLUSH_EVENT_COUNT, pc.flush_event_count);
    }

    #[test]
    fn toml_skip_polycorder_config_if_no_authkey() {
        let tomlcontents = r#"
        verbosity = 3

        [auto_configure]
        exception_trace = true
        fatal_signals = true

        [console_config]
        format = 'Text'

        [polycorder_config]
        node_id = 'UsefulNodeIdentifierToGroupEvents'
        flush_event_count = 10

        [polycorder_config.flush_timeout]
        secs = 10
        nanos = 0
        "#;

        let toml_file = unique_temp_toml_file();
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
                e => assert!(
                    false,
                    "Unexpected error when parsing command-line config file flag: {:?}",
                    e
                ),
            }
        }
        let config = maybe_config.unwrap();

        assert_eq!(true, config.auto_configure.exception_trace);
        assert_eq!(true, config.auto_configure.fatal_signals);
        assert_eq!(true, config.console_config.is_some());
        assert_eq!(false, config.polycorder_config.is_some());
        assert_eq!(3, config.verbosity);

        let cc = config.console_config.unwrap();
        assert_eq!(ConsoleOutputFormat::Text, cc.format);
    }

    #[test]
    fn toml_file_and_cli_options_dont_mix() {
        let tomlcontents = r#"
        verbosity = 3

        [auto_configure]
        exception_trace = true
        fatal_signals = true

        [console_config]
        format = 'tExt'

        [polycorder_config]
        node_id = "NodeDiscriminator"
        flush_event_count = 10

        [polycorder_config.flush_timeout]
        secs = 10
        nanos = 0
        "#;

        let toml_file = unique_temp_toml_file();
        println!("Writing TOML string to file: {}", &toml_file);
        fs::write(&toml_file, tomlcontents).expect("Unable to write TOML test file.");

        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from("--configfile"),
            OsString::from(&toml_file),
            OsString::from("-p"),
            OsString::from("PolycorderAuthKeyFromCLI"),
        ];

        let maybe_config = parse_args(Some(args));
        assert_eq!(true, maybe_config.is_err());
    }

    #[test]
    fn generate_reference_toml_config_file() {
        let config_expected = PolytectParams {
            auto_configure: AutoConfigure {
                exception_trace: true,
                fatal_signals: true,
            },
            console_config: Some(ConsoleConfig {
                format: ConsoleOutputFormat::Text,
            }),
            polycorder_config: Some(PolycorderConfig {
                auth_key: format!("AuthKeyFromPolyverseAccountManager"),
                node_id: "UsefulNodeIdentifierToGroupEvents".to_owned(),
                flush_timeout: DEFAULT_POLYCORDER_FLUSH_TIMEOUT,
                flush_event_count: DEFAULT_POLYCORDER_FLUSH_EVENT_COUNT,
            }),
            verbosity: 0,
        };

        let toml_file = format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/reference/polytect.toml"
        );
        let config_toml_string = toml::to_string_pretty(&config_expected).unwrap();
        println!("Writing TOML string to file: {}", &toml_file);
        fs::write(&toml_file, config_toml_string).expect("Unable to write TOML test file.");
    }
}
