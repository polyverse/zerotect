// Copyright (c) 2019 Polyverse Corporation

use crate::system::{EXCEPTION_TRACE_CTLNAME, KLOG_INCLUDE_TIMESTAMP, PRINT_FATAL_SIGNALS_CTLNAME};
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
use strum_macros::EnumString;

/// All configs may be loaded from a file (and overridden with any CLI flags)
const CONFIG_FILE_FLAG: &str = "configfile";

const AUTO_CONFIGURE: &str = "auto-configure";

const GOBBLE_OLD_EVENTS_FLAG: &str = "gobble-old-events";

/// Polycorder always takes the JSON log format
const POLYCORDER_OUTPUT_FLAG: &str = "polycorder";
const NODE_ID_FLAG: &str = "node";
const UNIDENTIFIED_NODE: &str = "unidentified";
const FLUSH_TIMEOUT_SECONDS_FLAG: &str = "flush-timeout-secs";
const FLUSH_EVENT_COUNT_FLAG: &str = "flush-event-count";

/// For all non-polycorder destinations, one of these formats may be selected
const POSSIBLE_FORMATS: &[&str] = &["text", "json", "cef"];

/// When set, log to console (with an optional format parameter)
const CONSOLE_OUTPUT_FLAG: &str = "console";

/// When set, log to syslog (with an optional format parameter)
const SYSLOG_OUTPUT_FLAG: &str = "syslog";

const SYSLOG_DESTINATION_FLAG: &str = "syslog-destination";
const SYSLOG_DESTINATION_UNIX: &str = "unix";
const SYSLOG_DESTINATION_TCP: &str = "tcp";
const SYSLOG_DESTINATION_UDP: &str = "udp";
const SYSLOG_POSSIBLE_DESTINATIONS: &[&str] = &[
    SYSLOG_DESTINATION_UNIX,
    SYSLOG_DESTINATION_TCP,
    SYSLOG_DESTINATION_UDP,
];

const SYSLOG_UNIX_SOCKET_PATH: &str = "syslog-unix-socket-path";
const SYSLOG_SERVER_ADDR: &str = "syslog-server";
const SYSLOG_LOCAL_ADDR: &str = "syslog-local";
const SYSLOG_HOSTNAME: &str = "syslog-hostname";

/// When set, log to a log file (with an optional format parameter)
const LOGFILE_PATH_FLAG: &str = "log-file-path";
const LOGFILE_FORMAT_FLAG: &str = "log-file-format";
const LOGFILE_ROTATION_COUNT_FLAG: &str = "log-file-rotation-count";
const LOGFILE_ROTATION_SIZE_FLAG: &str = "log-file-rotation-max-size";

// Analytics
const ANALYTICS_MODE_FLAG: &str = "analytics-mode";
const ANALYTICS_MODE_OFF: &str = "off";
const ANALYTICS_MODE_PASSTHROUGH: &str = "passthrough";
const ANALYTICS_MODE_DETECTED: &str = "detected";
const ANALYTICS_POSSIBLE_MODES: &[&str] = &[
    ANALYTICS_MODE_OFF,
    ANALYTICS_MODE_PASSTHROUGH,
    ANALYTICS_MODE_DETECTED,
];

const DETECTED_EVENT_JUSTIFICATION_FLAG: &str = "detected-event-details";
const DETECTED_EVENT_JUSTIFICATION_NONE: &str = "none";
const DETECTED_EVENT_JUSTIFICATION_SUMMARY: &str = "summary";
const DETECTED_EVENT_JUSTIFICATION_FULL: &str = "full";
const DETECTED_EVENT_JUSTIFICATIONS: &[&str] = &[
    DETECTED_EVENT_JUSTIFICATION_NONE,
    DETECTED_EVENT_JUSTIFICATION_SUMMARY,
    DETECTED_EVENT_JUSTIFICATION_FULL,
];

// Defaults
// Flush to polycorder when 10 events are collected
const DEFAULT_POLYCORDER_FLUSH_EVENT_COUNT: usize = 10;
// Flush to polycorder if no new events arrive for 10 seconds
const DEFAULT_POLYCORDER_FLUSH_TIMEOUT_SECONDS: u64 = 10;

// Perform analytics if no new events arrive for 10 seconds
const DEFAULT_ANALYTICS_COLLECTION_TIMEOUT_SECONDS: u64 = 10;
// Forget events older than 30 seconds
const DEFAULT_ANALYTICS_EVENT_LIFETIME_SECONDS: u64 = 30;
// if we can't tell a BROP from the last 20 segfaults, we never will.
const DEFAULT_ANALYTICS_MAX_EVENT_COUNT: usize = 20;
// when all 20 events are full, drop the oldest 5. It's okay.
const DEFAULT_ANALYTICS_EVENT_DROP_COUNT: usize = 5;

#[derive(Debug, Clone, Serialize, PartialEq, EnumString)]
pub enum OutputFormat {
    Text,

    JSON,

    // Microfocus ArcSight Common Event Format
    CEF,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ConsoleConfig {
    pub format: OutputFormat,
}

/// Acknowledged that this would be better as an Enum (with each destination variant containing
/// the fields relevant to it. The reason it is not, is so it may be easily serialized
/// to TOML (and thus, deserialized with equal ease.)
///
/// https://docs.rs/toml/0.5.6/toml/ser/fn.to_string.html
/// > Serialization can fail if T's implementation of Serialize decides to fail, if T contains a map with
/// > non-string keys, or if T attempts to serialize an unsupported datatype such as an enum, tuple, or tuple struct.
///
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SyslogConfig {
    pub format: OutputFormat,
    pub destination: SyslogDestination,
    pub path: Option<String>,
    pub server: Option<String>,
    pub local: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, EnumString)]
pub enum SyslogDestination {
    Default,

    Unix,

    Tcp,

    Udp,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LogFileConfig {
    pub format: OutputFormat,
    pub filepath: String,

    /// How many files to rotate over?
    /// $filepath.0, $filepath.1, ... upto $filepath.N
    pub rotation_file_count: Option<usize>,

    /// For each file, what is the maximum size (in bytes) at which to rotate to the next one?
    pub rotation_file_max_size: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PolycorderConfig {
    pub auth_key: String,
    pub node_id: String,

    // Flush after this number of items, even if more are arriving...
    pub flush_event_count: usize,

    // Flush all events if none arrive for this interval
    pub flush_timeout_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AutoConfigure {
    pub exception_trace: bool,
    pub fatal_signals: bool,
    pub klog_include_timestamp: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, EnumString)]
pub enum AnalyticsMode {
    /// No analytics
    #[strum(serialize = "off")]
    Off,

    /// Passthrough original events to the output stream, along with
    /// analytics-generated/detected events
    #[strum(serialize = "passthrough")]
    Passthrough,

    /// Only emit analyzed and detected events (suppress raw events from the system)
    #[strum(serialize = "detected")]
    Detected,
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, EnumString)]
pub enum DetectedEventJustification {
    /// No justification. At best a count of the number of events that justify it.
    #[strum(serialize = "none")]
    None,

    /// A summarized justification - relevant information from all events is included,
    /// but not the complete events.
    #[strum(serialize = "summary")]
    Summary,

    /// Every event that justifies this detection is included. This is verbose but
    /// comprehensive and useful for research.
    #[strum(serialize = "full")]
    Full,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AnalyticsConfig {
    /// What mode is the analyzer in?
    pub mode: AnalyticsMode,

    /// How much justification to include when an event is detected?
    pub justification: DetectedEventJustification,

    /// How long should analyzer wait for new events to arrive, before
    /// processing and making a decision on what's buffered.
    ///
    /// In the case of a Blind-ROP for instance, a lot of events may arrive
    /// milliseconds or seconds apart. It makes sense to process when
    /// no new events arrive for about 10 seconds or so.
    pub collection_timeout_seconds: u64,

    /// Maximum number of events to store
    /// Analysis is run when this count is reached, before older events are purged.
    pub max_event_count: usize,

    /// How long should an event be held -
    /// even if no new events arrive, older events will be expired
    /// and dropped when they cross this duration.
    pub event_lifetime_seconds: u64,

    /// How count of events to drop when buffer is full
    /// Must be less than max_event_count.
    pub event_drop_count: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MonitorConfig {
    pub gobble_old_events: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ZerotectParams {
    pub verbosity: u8,

    // auto-configure system
    pub auto_configure: AutoConfigure,

    // analytics configuration
    pub analytics: AnalyticsConfig,

    // only one monitor config
    pub monitor: MonitorConfig,

    // supported emitters
    pub console: Option<ConsoleConfig>,
    pub polycorder: Option<PolycorderConfig>,
    pub syslog: Option<SyslogConfig>,
    pub logfile: Option<LogFileConfig>,
}

// A proxy-structure to deserialize into
// really helps with TOML-deserialization to know
// what values were specified in TOML and which ones
// were not.
//
// TOML deserializer doesn't do defaulting - so all fields need to be captured
// as Option'al and then defaulted
//
// Secondly, TOML doesn't deserialize into Enums (even with EnumString),
// so those have to be parsed from String's.
#[derive(Deserialize)]
pub struct ZerotectParamOptions {
    pub verbosity: Option<u8>,

    pub auto_configure: Option<AutoConfigureOptions>,
    pub analytics: Option<AnalyticsConfigOptions>,
    pub monitor: Option<MonitorConfigOptions>,
    pub console: Option<ConsoleConfigOptions>,
    pub polycorder: Option<PolycorderConfigOptions>,
    pub syslog: Option<SyslogConfigOptions>,
    pub logfile: Option<LogFileConfigOptions>,
}

// A proxy-structure to deserialize into
// really helps with TOML-deserialization to know
// what values were specified in TOML and which ones
// were not.#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[derive(Deserialize)]
pub struct AutoConfigureOptions {
    pub exception_trace: Option<bool>,
    pub fatal_signals: Option<bool>,
    pub klog_include_timestamp: Option<bool>,
}

#[derive(Deserialize)]
pub struct AnalyticsConfigOptions {
    pub mode: Option<String>,
    pub justification: Option<String>,
    pub collection_timeout_seconds: Option<u64>,
    pub max_event_count: Option<usize>,
    pub event_lifetime_seconds: Option<u64>,
    pub event_drop_count: Option<usize>,
}

#[derive(Deserialize)]
pub struct MonitorConfigOptions {
    pub gobble_old_events: Option<bool>,
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
    pub flush_timeout_seconds: Option<u64>,

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

#[derive(Deserialize, PartialEq)]
pub struct SyslogConfigOptions {
    pub format: Option<String>,
    pub destination: Option<String>,
    pub path: Option<String>,
    pub server: Option<String>,
    pub local: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Deserialize, PartialEq)]
pub struct LogFileConfigOptions {
    pub format: Option<String>,
    pub filepath: Option<String>,
    pub rotation_file_count: Option<usize>,
    pub rotation_file_max_size: Option<usize>,
}

#[derive(Debug)]
pub enum InnerError {
    None,
    IoError(io::Error),
    ClapError(clap::Error),
    Utf8Error(str::Utf8Error),
    StrumParseError(strum::ParseError),
    TomlDeserializationError(toml::de::Error),
    ParseIntError(std::num::ParseIntError),
    TryFromIntError(std::num::TryFromIntError),
}

#[derive(Debug)]
pub struct ParsingError {
    pub message: String,
    pub inner_error: InnerError,
}
impl Error for ParsingError {}
impl Display for ParsingError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match &self.inner_error {
            InnerError::None => write!(f, "ParsingError:: {}", self.message),
            InnerError::IoError(e) => write!(f, "{} (ParsingError::IoError::{})", self.message, e),
            InnerError::ClapError(e) => {
                write!(f, "{} (ParsingError::ClapError::{})", self.message, e)
            }
            InnerError::Utf8Error(e) => {
                write!(f, "{} (ParsingError::Utf8Error::{})", self.message, e)
            }
            InnerError::StrumParseError(e) => {
                write!(f, "{} (ParsingError::StrumParseError::{})", self.message, e)
            }
            InnerError::TomlDeserializationError(e) => write!(
                f,
                "{} (ParsingError::TomlDeserializationError::{})",
                self.message, e
            ),
            InnerError::ParseIntError(e) => {
                write!(f, "{} (ParsingError::ParseIntError::{})", self.message, e)
            }
            InnerError::TryFromIntError(e) => {
                write!(f, "{} (ParsingError::TryFromIntError::{})", self.message, e)
            }
        }
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
impl From<std::num::TryFromIntError> for ParsingError {
    fn from(err: std::num::TryFromIntError) -> ParsingError {
        ParsingError {
            message: format!("Inner std::num::TryFromIntError :: {}", err),
            inner_error: InnerError::TryFromIntError(err),
        }
    }
}
impl From<strum::ParseError> for ParsingError {
    fn from(err: strum::ParseError) -> ParsingError {
        ParsingError {
            message: format!("Inner strum::ParseError :: {}", err),
            inner_error: InnerError::StrumParseError(err),
        }
    }
}

/// Parse command-line arguments
/// maybe_args - allows unit-testing of arguments. Use None to parse
///     arguments from the operating system.
pub fn parse_args(maybe_args: Option<Vec<OsString>>) -> Result<ZerotectParams, ParsingError> {
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

    let matches = App::new("zerotect")
                        .setting(AppSettings::DeriveDisplayOrder)
                        .version("1.0")
                        .author("Polyverse Corporation <support@polyverse.com>")
                        .about("Detect attempted (and ultimately failed) attacks and exploits using known and unknown vulnerabilities by observing side effects (segfaults, crashes, etc.)")

                        // config file
                        .arg(Arg::with_name(CONFIG_FILE_FLAG)
                            .long(CONFIG_FILE_FLAG)
                            .value_name("filepath")
                            .takes_value(true)
                            .conflicts_with_all(&[AUTO_CONFIGURE, CONSOLE_OUTPUT_FLAG, POLYCORDER_OUTPUT_FLAG, NODE_ID_FLAG, "verbose"])
                            .help("Read configuration from a TOML-formatted file. When specified, all other command-line arguments are ignored. (NOTE: Considerably more options can be configured in the file than through CLI arguments.)"))

                        // configure automatically
                        .arg(Arg::with_name(AUTO_CONFIGURE)
                            .long(AUTO_CONFIGURE)
                            .value_name("sysctl-flag-to-auto-configure")
                            .takes_value(true)
                            .possible_values(&[EXCEPTION_TRACE_CTLNAME, PRINT_FATAL_SIGNALS_CTLNAME, KLOG_INCLUDE_TIMESTAMP])
                            .multiple(true)
                            .help("Automatically configure the system on the user's behalf."))

                        // Start monitoring events right now or from the past?
                        .arg(Arg::with_name(GOBBLE_OLD_EVENTS_FLAG)
                            .long(GOBBLE_OLD_EVENTS_FLAG)
                            .help("When enabled, gobbles events from the past (if found) in logs. By default zerotect only captures events after it has started."))

                        // console output
                        .arg(Arg::with_name(CONSOLE_OUTPUT_FLAG)
                            .long(CONSOLE_OUTPUT_FLAG)
                            .value_name("format")
                            .possible_values(POSSIBLE_FORMATS)
                            .case_insensitive(true)
                            .help("Prints all monitored data to the console in the specified format."))

                        // polycorder output
                        .arg(Arg::with_name(POLYCORDER_OUTPUT_FLAG)
                            .long(POLYCORDER_OUTPUT_FLAG)
                            .value_name("authkey")
                            .takes_value(true)
                            .empty_values(false)
                            .help("Sends all monitored data to the polycorder service. When specified, must provide a Polyverse Account AuthKey which has an authorized scope to publish to Polyverse."))
                        .arg(Arg::with_name(NODE_ID_FLAG)
                            .long(NODE_ID_FLAG)
                            .value_name("node_identifier")
                            .empty_values(false)
                            .requires(POLYCORDER_OUTPUT_FLAG)
                            .help("All reported events are attributed to this 'node' within your overall organization, allowing for filtering, separation and more."))
                        .arg(Arg::with_name(FLUSH_TIMEOUT_SECONDS_FLAG)
                            .long(FLUSH_TIMEOUT_SECONDS_FLAG)
                            .value_name("seconds")
                            .empty_values(false)
                            .requires(POLYCORDER_OUTPUT_FLAG)
                            .help("After how many seconds should events be flushed to Polycorder, if no new events occur. This avoids chatty communication with Polycorder."))
                        .arg(Arg::with_name(FLUSH_EVENT_COUNT_FLAG)
                            .long(FLUSH_EVENT_COUNT_FLAG)
                            .value_name("count")
                            .empty_values(false)
                            .requires(POLYCORDER_OUTPUT_FLAG)
                            .help("The number of events, when buffered, are flushed to Polycorder. This allows batching of events. Make this too high, and upon failure, a large number of events may be lost. Make it too low, and connections will be chatty."))

                        // syslog output
                        .arg(Arg::with_name(SYSLOG_OUTPUT_FLAG)
                            .long(SYSLOG_OUTPUT_FLAG)
                            .value_name("format")
                            .possible_values(POSSIBLE_FORMATS)
                            .case_insensitive(true)
                            .help("Sends all monitored data to syslog in the specified format. Unless a destination is selected, tries to send to standard syslog destinations when in order of unix socket, tcp and udp. Since the UDP destination will almost never fail, if there is no listener, logs will be lost."))
                        // syslog destinations
                        .arg(Arg::with_name(SYSLOG_DESTINATION_FLAG)
                            .long(SYSLOG_DESTINATION_FLAG)
                            .value_name("destination")
                            .possible_values(SYSLOG_POSSIBLE_DESTINATIONS)
                            .case_insensitive(true)
                            .requires(SYSLOG_OUTPUT_FLAG)
                            .help("The syslog destination type. If a destination is selected, the destination configuration flags are explicitly required and defaults are not used."))
                        //syslog hostname (optional)
                        .arg(Arg::with_name(SYSLOG_HOSTNAME)
                            .long(SYSLOG_HOSTNAME)
                            .value_name("hostname")
                            .requires(SYSLOG_DESTINATION_FLAG)
                            .help("The syslog tcp server addr to send to. (usually ip:port)"))
                        // syslog tcp options
                        .arg(Arg::with_name(SYSLOG_SERVER_ADDR)
                            .long(SYSLOG_SERVER_ADDR)
                            .value_name("addr")
                            .requires(SYSLOG_DESTINATION_FLAG)
                            .required_ifs(&[
                                (SYSLOG_DESTINATION_FLAG, SYSLOG_DESTINATION_TCP),
                                (SYSLOG_DESTINATION_FLAG, SYSLOG_DESTINATION_UDP)
                            ])
                            .help("The syslog udp server addr to send to. (usually ip:port)"))
                        // syslog udp options
                        .arg(Arg::with_name(SYSLOG_LOCAL_ADDR)
                            .long(SYSLOG_LOCAL_ADDR)
                            .value_name("addr")
                            .requires(SYSLOG_DESTINATION_FLAG)
                            .required_ifs(&[
                                (SYSLOG_DESTINATION_FLAG, SYSLOG_DESTINATION_UDP)
                            ])
                            .help("The syslog udp local addr to bind to. (usually ip:port)"))
                        //syslog unix socket path
                        .arg(Arg::with_name(SYSLOG_UNIX_SOCKET_PATH)
                            .long(SYSLOG_UNIX_SOCKET_PATH)
                            .value_name("path")
                            .requires(SYSLOG_DESTINATION_FLAG)
                            .required_ifs(&[
                                (SYSLOG_DESTINATION_FLAG, SYSLOG_DESTINATION_UNIX)
                            ])
                            .help("The unix socket to send to. (usually /dev/log or /var/run/syslog)"))

                        // logfile output format
                        .arg(Arg::with_name(LOGFILE_FORMAT_FLAG)
                            .long(LOGFILE_FORMAT_FLAG)
                            .value_name("format")
                            .possible_values(POSSIBLE_FORMATS)
                            .case_insensitive(true)
                            .requires(LOGFILE_PATH_FLAG)
                            .help("Sends all monitored data to the log file in the specified format."))
                        // logfile path
                        .arg(Arg::with_name(LOGFILE_PATH_FLAG)
                            .long(LOGFILE_PATH_FLAG)
                            .value_name("path")
                            .requires(LOGFILE_FORMAT_FLAG)
                            .help("Sends all monitored data to a log file specified in the path."))
                        // log file rotation count
                        .arg(Arg::with_name(LOGFILE_ROTATION_COUNT_FLAG)
                            .long(LOGFILE_ROTATION_COUNT_FLAG)
                            .value_name("count")
                            .requires_all(&[LOGFILE_PATH_FLAG,LOGFILE_ROTATION_SIZE_FLAG])
                            .help("Setting this enables file rotation. Files are rotated as $path.0, $path.1.. etc. upto the number specified by this argument (and then starting back at $path.0 when the N'th file exceeds max size)."))
                        // log file rotation max size
                        .arg(Arg::with_name(LOGFILE_ROTATION_SIZE_FLAG)
                            .long(LOGFILE_ROTATION_SIZE_FLAG)
                            .value_name("size")
                            .requires_all(&[LOGFILE_PATH_FLAG, LOGFILE_ROTATION_COUNT_FLAG])
                            .help("Setting this enables file rotation. A new file is begin in the rotation sequence when the current file exceeds the size (in bytes) specified by this argument."))

                        // Built-in analytics
                        .arg(Arg::with_name(ANALYTICS_MODE_FLAG)
                            .long(ANALYTICS_MODE_FLAG)
                            .possible_values(ANALYTICS_POSSIBLE_MODES)
                            .case_insensitive(true)
                            .default_value(ANALYTICS_MODE_PASSTHROUGH)
                            .help("Enable or disable built-in analytics (looks for localized indicators of live attacks)"))
                        // How much detail when an event is detected?
                        .arg(Arg::with_name(DETECTED_EVENT_JUSTIFICATION_FLAG)
                            .long(DETECTED_EVENT_JUSTIFICATION_FLAG)
                            .possible_values(DETECTED_EVENT_JUSTIFICATIONS)
                            .case_insensitive(true)
                            .default_value(DETECTED_EVENT_JUSTIFICATION_SUMMARY)
                            .help("When an event is detected, how much justification (i.e. details on exactly why that event was detected) "))

                        // verbose internal logging?
                        .arg(Arg::with_name("verbose")
                            .short("v")
                            .long("verbose")
                            .multiple(true)
                            .help("Increase debug verbosity of zerotect."))
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
            klog_include_timestamp: auto_configure_flag(auto_conf_values, KLOG_INCLUDE_TIMESTAMP)?,
        },
        None => AutoConfigure {
            exception_trace: false,
            fatal_signals: false,
            klog_include_timestamp: false,
        },
    };

    let verbosity = u8::try_from(matches.occurrences_of("verbose"))?;

    let analytics = AnalyticsConfig {
        mode: match matches.value_of(ANALYTICS_MODE_FLAG) {
            Some(modestr) => match AnalyticsMode::from_str(modestr.trim().to_ascii_lowercase().as_str()) {
                Ok(mode) => mode,
                Err(e) => return Err(ParsingError{inner_error: InnerError::None, message: format!("Analytics mode value set to {} had a parsing error: {}. Since this is a system-level agent, it does not default to something saner. Aborting program", modestr, e)}),
            }
            None => AnalyticsMode::Passthrough,
        },
        justification: match matches.value_of(DETECTED_EVENT_JUSTIFICATION_FLAG) {
            Some(justificationstr) => match DetectedEventJustification::from_str(justificationstr.trim().to_ascii_lowercase().as_str()) {
                Ok(justification) => justification,
                Err(e) => return Err(ParsingError{inner_error: InnerError::None, message: format!("Detected event justification value set to {} had a parsing error: {}. Since this is a system-level agent, it does not default to something saner. Aborting program", justificationstr, e)}),
            }
            None => DetectedEventJustification::Summary,
        },
        collection_timeout_seconds: DEFAULT_ANALYTICS_COLLECTION_TIMEOUT_SECONDS,
        max_event_count: DEFAULT_ANALYTICS_MAX_EVENT_COUNT,
        event_lifetime_seconds: DEFAULT_ANALYTICS_EVENT_LIFETIME_SECONDS,
        event_drop_count: DEFAULT_ANALYTICS_EVENT_DROP_COUNT,
    };

    let monitor = match u8::try_from(matches.occurrences_of(GOBBLE_OLD_EVENTS_FLAG))? {
        0 => MonitorConfig {
            gobble_old_events: false,
        },
        _ => MonitorConfig {
            gobble_old_events: true,
        },
    };

    let console = match matches.value_of(CONSOLE_OUTPUT_FLAG) {
        Some(formatstr) => match OutputFormat::from_str(formatstr.trim().to_ascii_lowercase().as_str()) {
            Ok(format) => Some(ConsoleConfig{format}),
            Err(e) => {
                return Err(ParsingError{inner_error: InnerError::None, message: format!("Console configuration value set to {} had a parsing error: {}. Since this is a system-level agent, it does not default to something saner. Aborting program", formatstr, e)})
            },
        },
        None => None,
    };

    // First we need a polycorder auth key - either from CLI and then the file as
    // the secondary source.
    let polycorder = match matches.value_of(POLYCORDER_OUTPUT_FLAG) {
        None => None,
        Some(key) => {
            // Only construct Polycorder config if an auth key was found,
            // either on the CLI or from the config file.
            let auth_key = key.trim().to_owned();

            let node_id = match matches.value_of(NODE_ID_FLAG) {
                Some(n) => n.trim().to_owned(),
                None => UNIDENTIFIED_NODE.to_owned(),
            };

            let flush_timeout_seconds = match matches.value_of(FLUSH_TIMEOUT_SECONDS_FLAG) {
                Some(nstr) => nstr.parse::<u64>()?,
                None => DEFAULT_POLYCORDER_FLUSH_TIMEOUT_SECONDS,
            };

            let flush_event_count = match matches.value_of(FLUSH_EVENT_COUNT_FLAG) {
                Some(nstr) => nstr.parse::<usize>()?,
                None => DEFAULT_POLYCORDER_FLUSH_EVENT_COUNT,
            };

            Some(PolycorderConfig {
                auth_key,
                node_id,
                flush_timeout_seconds,
                flush_event_count,
            })
        }
    };

    let syslog = match matches.value_of(SYSLOG_OUTPUT_FLAG) {
        Some(formatstr) => match OutputFormat::from_str(formatstr.trim().to_ascii_lowercase().as_str()) {
            Ok(format) => match matches.value_of(SYSLOG_DESTINATION_FLAG) {
                // let's see if syslog destination is set
                Some(destinationstr) => match destinationstr.trim().to_ascii_lowercase().as_str() {
                    SYSLOG_DESTINATION_UNIX => match matches.value_of(SYSLOG_UNIX_SOCKET_PATH) {
                        None => return Err(ParsingError{inner_error: InnerError::None, message: format!("When {} is set to {}, the {} flag must be set.", SYSLOG_DESTINATION_FLAG, SYSLOG_DESTINATION_UNIX, SYSLOG_UNIX_SOCKET_PATH)}),
                        Some(pathstr) => Some(SyslogConfig{
                            format,
                            destination: SyslogDestination::Unix,
                            path: Some(pathstr.to_owned()),
                            local: None,
                            server: None,
                            hostname: matches.value_of(SYSLOG_HOSTNAME).map(ToOwned::to_owned),
                        }),
                    }
                    SYSLOG_DESTINATION_TCP => match matches.value_of(SYSLOG_SERVER_ADDR) {
                        None => return Err(ParsingError{inner_error: InnerError::None, message: format!("When {} is set to {}, the {} flag must be set.", SYSLOG_DESTINATION_FLAG, SYSLOG_DESTINATION_TCP, SYSLOG_SERVER_ADDR)}),
                        Some(server_addr) => Some(SyslogConfig{
                                format,
                                destination: SyslogDestination::Tcp,
                                path: None,
                                local: None,
                                server: Some(server_addr.to_owned()),
                                hostname: matches.value_of(SYSLOG_HOSTNAME).map(ToOwned::to_owned),
                        }),
                    }
                    SYSLOG_DESTINATION_UDP => match matches.value_of(SYSLOG_SERVER_ADDR) {
                        None => return Err(ParsingError{inner_error: InnerError::None, message: format!("When {} is set to {}, the {} flag must be set.", SYSLOG_DESTINATION_FLAG, SYSLOG_DESTINATION_UDP, SYSLOG_SERVER_ADDR)}),
                        Some(server_addr) => match matches.value_of(SYSLOG_LOCAL_ADDR) {
                            None => return Err(ParsingError{inner_error: InnerError::None, message: format!("When {} is set to {}, the {} flag must be set.", SYSLOG_DESTINATION_FLAG, SYSLOG_DESTINATION_UDP, SYSLOG_LOCAL_ADDR)}),
                            Some(local_addr) => Some(SyslogConfig{
                                    format,
                                    destination: SyslogDestination::Udp,
                                    path: None,
                                    local: Some(local_addr.to_owned()),
                                    server: Some(server_addr.to_owned()),
                                    hostname: matches.value_of(SYSLOG_HOSTNAME).map(ToOwned::to_owned),
                            }),
                        }
                    },
                    // any value not in the above
                    val => return Err(ParsingError{inner_error: InnerError::None, message: format!("{} set to {} which is not recognized. Supported values are: {}.", SYSLOG_DESTINATION_FLAG, val, SYSLOG_POSSIBLE_DESTINATIONS.join(","))}),
                },
                None => Some(SyslogConfig{
                    format,
                    destination: SyslogDestination::Default,
                    path: None,
                    local: None,
                    server: None,
                    hostname: matches.value_of(SYSLOG_HOSTNAME).map(ToOwned::to_owned),
                }),
            },
            Err(e) => {
                return Err(ParsingError{inner_error: InnerError::None, message: format!("Syslog format value set to {} had a parsing error: {}. Since this is a system-level agent, it does not default to something saner. Aborting program", formatstr, e)})
            },
        },
        None => None,
    };

    let logfile = match matches.value_of(LOGFILE_FORMAT_FLAG) {
        Some(formatstr) => match OutputFormat::from_str(formatstr.trim().to_ascii_lowercase().as_str()) {
            Ok(format) => match matches.value_of(LOGFILE_PATH_FLAG) {
                Some(path) => Some(LogFileConfig{
                    format,
                    filepath: path.to_owned(),
                    rotation_file_count: match matches.value_of(LOGFILE_ROTATION_COUNT_FLAG) {
                        None => None,
                        Some(rcfstr) => Some(rcfstr.parse::<usize>()?)
                    },
                    rotation_file_max_size: match matches.value_of(LOGFILE_ROTATION_SIZE_FLAG) {
                        None => None,
                        Some(rsfstr) => Some(rsfstr.parse::<usize>()?)
                    },
                }),
                None => None,
            },
            Err(e) => {
                return Err(ParsingError{inner_error: InnerError::None, message: format!("Log file format value set to {} had a parsing error: {}. Since this is a system-level agent, it does not default to something saner. Aborting program", formatstr, e)})
            },
        },
        None => None,
    };

    Ok(ZerotectParams {
        verbosity,
        auto_configure,
        analytics,
        monitor,
        console,
        polycorder,
        syslog,
        logfile,
    })
}

/// Parse params from config file if one was provided
/// https://github.com/clap-rs/clap/issues/748
pub fn parse_config_file(filepath: &str) -> Result<ZerotectParams, ParsingError> {
    let filecontents = fs::read(filepath)?;
    let zerotect_param_options: ZerotectParamOptions =
        toml::from_str(str::from_utf8(&filecontents)?)?;

    let params = ZerotectParams {
        verbosity: zerotect_param_options.verbosity.unwrap_or(0),
        auto_configure: match zerotect_param_options.auto_configure {
            Some(ac) => AutoConfigure {
                exception_trace: ac.exception_trace.unwrap_or(false),
                fatal_signals: ac.fatal_signals.unwrap_or(false),
                klog_include_timestamp: ac.klog_include_timestamp.unwrap_or(false),
            },
            None => AutoConfigure {
                exception_trace: false,
                fatal_signals: false,
                klog_include_timestamp: false,
            },
        },
        analytics: match zerotect_param_options.analytics {
            Some(aco) => AnalyticsConfig{
                mode: match aco.mode {
                    Some(modestr) => match AnalyticsMode::from_str(modestr.trim().to_ascii_lowercase().as_str()) {
                        Ok(mode) => mode,
                        Err(e) => return Err(ParsingError{message: format!("In config file, the analytics mode configuration key {} was not valid: {}. Please set it to one of [{}].", modestr, e, ANALYTICS_POSSIBLE_MODES.join("|")), inner_error: InnerError::None}),
                    },
                    None => AnalyticsMode::Passthrough,
                },
                justification: match aco.justification {
                    Some(justificationstr) => match DetectedEventJustification::from_str(justificationstr.trim().to_ascii_lowercase().as_str()) {
                        Ok(mode) => mode,
                        Err(e) => return Err(ParsingError{message: format!("In config file, the detected event justification configuration key {} was not valid: {}. Please set it to one of [{}].", justificationstr, e, DETECTED_EVENT_JUSTIFICATIONS.join("|")), inner_error: InnerError::None}),
                    },
                    None => DetectedEventJustification::Summary,
                },
                collection_timeout_seconds: aco.collection_timeout_seconds.unwrap_or(DEFAULT_ANALYTICS_COLLECTION_TIMEOUT_SECONDS),
                event_lifetime_seconds: aco.event_lifetime_seconds.unwrap_or(DEFAULT_ANALYTICS_EVENT_LIFETIME_SECONDS),
                max_event_count: aco.max_event_count.unwrap_or(DEFAULT_ANALYTICS_MAX_EVENT_COUNT),
                event_drop_count: aco.event_drop_count.unwrap_or(DEFAULT_ANALYTICS_EVENT_DROP_COUNT),
            },
            None => AnalyticsConfig{
                mode: AnalyticsMode::Passthrough,
                justification: DetectedEventJustification::Summary,
                collection_timeout_seconds: DEFAULT_ANALYTICS_COLLECTION_TIMEOUT_SECONDS,
                event_lifetime_seconds: DEFAULT_ANALYTICS_EVENT_LIFETIME_SECONDS,
                max_event_count: DEFAULT_ANALYTICS_MAX_EVENT_COUNT,
                event_drop_count: DEFAULT_ANALYTICS_EVENT_DROP_COUNT,
            },
        },
        monitor: match zerotect_param_options.monitor {
            Some(mc) => MonitorConfig {
                gobble_old_events: mc.gobble_old_events.unwrap_or(false),
            },
            None => MonitorConfig {
                gobble_old_events: false,
            },
        },
        console: match zerotect_param_options.console {
            Some(cco) => match cco.format {
                Some(formatstr) => Some(ConsoleConfig {
                    format: OutputFormat::from_str(formatstr.to_ascii_lowercase().as_str())?,
                }),
                None => return Err(ParsingError{message: "In config file, the console configuration key was specified without a format. Please remove console configuration entirely, or provide a valid format to format events in.".to_owned(), inner_error: InnerError::None}),
            },
            None => None,
        },
        polycorder: match zerotect_param_options.polycorder {
            None => None,
            Some(pco) => match pco.auth_key {
                None => return Err(ParsingError{message: "In config file, the polycorder configuration key was specified without an authkey. Please remove polycorder configuration entirely, or provide a valid authkey to publish events with.".to_owned(), inner_error: InnerError::None}),
                Some(ak) => Some(PolycorderConfig {
                    auth_key: ak.trim().to_owned(),
                    node_id: pco.node_id.unwrap_or_else(|| UNIDENTIFIED_NODE.to_owned()),
                    flush_event_count: pco
                        .flush_event_count
                        .unwrap_or(DEFAULT_POLYCORDER_FLUSH_EVENT_COUNT),
                    flush_timeout_seconds: pco
                        .flush_timeout_seconds
                        .unwrap_or(DEFAULT_POLYCORDER_FLUSH_TIMEOUT_SECONDS),
                }),
            },
        },
        syslog: match zerotect_param_options.syslog {
            None => None,
            Some(sco) => Some(SyslogConfig{
                format: match sco.format {
                    None => return Err(ParsingError{message: "In config file, the syslog configuration key was specified without a format. Please remove syslog configuration entirely, or provide a valid format to format events in.".to_owned(), inner_error: InnerError::None}),
                    Some(formatstr) => OutputFormat::from_str(formatstr.to_ascii_lowercase().as_str())?,
                },
                destination: match sco.destination {
                    None => SyslogDestination::Default,
                    Some(formatstr) => SyslogDestination::from_str(formatstr.to_ascii_lowercase().as_str())?,
                },
                hostname: sco.hostname,
                server: sco.server,
                local: sco.local,
                path: sco.path,
            }),
        },
        logfile: match zerotect_param_options.logfile {
            None => None,
            Some(lfc) => Some(LogFileConfig{
                format: match lfc.format {
                    None => return Err(ParsingError{message: "In config file, the log file configuration key was specified without a format. Please remove log file configuration entirely, or provide a valid format to format events in.".to_owned(), inner_error: InnerError::None}),
                    Some(formatstr) => OutputFormat::from_str(formatstr.to_ascii_lowercase().as_str())?,
                },
                filepath: match lfc.filepath {
                    None => return Err(ParsingError{message: "In config file, the log file configuration key was specified without a file path. Please remove log file configuration entirely, or provide a valid path to a while where events should be logged.".to_owned(), inner_error: InnerError::None}),
                    Some(pathstr) => pathstr,
                },
                rotation_file_count: lfc.rotation_file_count,
                rotation_file_max_size: lfc.rotation_file_max_size,
            })
        },
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
    Ok(seen_before)
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
            OsString::from("--syslog"),
            OsString::from("cef"),
            OsString::from("--syslog-destination"),
            OsString::from("udp"),
            OsString::from("--syslog-hostname"),
            OsString::from("testhost"),
            OsString::from("--syslog-server"),
            OsString::from("127.0.0.1:5"),
            OsString::from("--syslog-local"),
            OsString::from("127.0.0.1:2"),
            OsString::from("--log-file-format"),
            OsString::from("cef"),
            OsString::from("--log-file-path"),
            OsString::from("/tmp/zerotect/zerotect.log"),
            OsString::from("--log-file-rotation-count"),
            OsString::from("1"),
            OsString::from("--log-file-rotation-max-size"),
            OsString::from("10"),
        ];

        let config = parse_args(Some(args)).unwrap();

        assert_eq!(true, config.auto_configure.exception_trace);
        assert_eq!(true, config.auto_configure.fatal_signals);
        assert_eq!(true, config.console.is_some());
        assert_eq!(true, config.polycorder.is_some());
        assert_eq!(1, config.verbosity);

        let cc = config.console.unwrap();
        assert_eq!(OutputFormat::Text, cc.format);

        let pc = config.polycorder.unwrap();
        assert_eq!("authkey", pc.auth_key);
        assert_eq!("nodeid34235", pc.node_id);
        assert_eq!(89, pc.flush_timeout_seconds);
        assert_eq!(53, pc.flush_event_count);

        let sc = config.syslog.unwrap();
        assert_eq!(SyslogDestination::Udp, sc.destination);
        assert_eq!(Some("testhost".to_owned()), sc.hostname);
        assert_eq!(Some("127.0.0.1:5".to_owned()), sc.server);
        assert_eq!(Some("127.0.0.1:2".to_owned()), sc.local);

        let lfc = config.logfile.unwrap();
        assert_eq!("/tmp/zerotect/zerotect.log", lfc.filepath);
        assert_eq!(OutputFormat::CEF, lfc.format);
        assert_eq!(Some(1), lfc.rotation_file_count);
        assert_eq!(Some(10), lfc.rotation_file_max_size);

        // analytics should be enabled by default
        assert_eq!(AnalyticsMode::Passthrough, config.analytics.mode);
    }

    #[test]
    fn commandline_args_parse_space_within_param() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. Also test words aren't split"),
            OsString::from(format!("--auto-configure {}", EXCEPTION_TRACE_CTLNAME)),
            OsString::from(format!("--auto-configure {}", PRINT_FATAL_SIGNALS_CTLNAME)),
            OsString::from(format!("--auto-configure {}", KLOG_INCLUDE_TIMESTAMP)),
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
            assert_eq!(OutputFormat::Text, pc.unwrap().console.unwrap().format)
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
            assert_eq!(OutputFormat::JSON, pc.unwrap().console.unwrap().format);
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
        assert!(config.polycorder.is_some());

        let pc = config.polycorder.unwrap();
        assert_eq!("authkey97097", pc.auth_key);
        assert_eq!(UNIDENTIFIED_NODE, pc.node_id);
        assert_eq!(
            DEFAULT_POLYCORDER_FLUSH_TIMEOUT_SECONDS,
            pc.flush_timeout_seconds
        );
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
            OsString::from(KLOG_INCLUDE_TIMESTAMP),
            OsString::from(EXCEPTION_TRACE_CTLNAME),
        ];

        let config = parse_args(Some(args));
        assert!(config.is_err());
    }

    #[test]
    fn commandline_args_parse_syslog_tcp() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. First param ignored."),
            OsString::from("--syslog"),
            OsString::from("cef"),
            OsString::from("--syslog-destination"),
            OsString::from("tcp"),
            OsString::from("--syslog-hostname"),
            OsString::from("testhost"),
            OsString::from("--syslog-server"),
            OsString::from("127.0.0.1:5"),
        ];

        let config = parse_args(Some(args)).unwrap();

        let sc = config.syslog.unwrap();
        assert_eq!(SyslogDestination::Tcp, sc.destination);
        assert_eq!(Some("testhost".to_owned()), sc.hostname);
        assert_eq!(Some("127.0.0.1:5".to_owned()), sc.server);
        assert_eq!(None, sc.local);
    }

    #[test]
    fn commandline_args_parse_syslog_unix() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. First param ignored."),
            OsString::from("--syslog"),
            OsString::from("cef"),
            OsString::from("--syslog-destination"),
            OsString::from("unix"),
            OsString::from("--syslog-unix-socket-path"),
            OsString::from("/some/socket/path"),
        ];

        let config = parse_args(Some(args)).unwrap();

        let sc = config.syslog.unwrap();
        assert_eq!(SyslogDestination::Unix, sc.destination);
        assert_eq!(Some("/some/socket/path".to_owned()), sc.path);
        assert_eq!(None, sc.hostname);
        assert_eq!(None, sc.local);
    }

    #[test]
    fn commandline_args_parse_logfile_no_rotation() {
        let args: Vec<OsString> = vec![
            OsString::from("programname"),
            OsString::from("--log-file-format"),
            OsString::from("text"),
            OsString::from("--log-file-path"),
            OsString::from("/tmp/zerotect/zerotect.log"),
        ];

        let config = parse_args(Some(args)).unwrap();

        let lfc = config.logfile.unwrap();
        assert_eq!(OutputFormat::Text, lfc.format);
        assert_eq!("/tmp/zerotect/zerotect.log", lfc.filepath);
        assert_eq!(None, lfc.rotation_file_count);
        assert_eq!(None, lfc.rotation_file_max_size);
    }

    #[test]
    fn commandline_args_parse_logfile_require_both_basic_params() {
        let args: Vec<OsString> = vec![OsString::from("--log-file-format"), OsString::from("json")];

        let config = parse_args(Some(args));
        assert!(config.is_err())
    }

    #[test]
    fn commandline_args_parse_logfile_optional_params_require_basic_params() {
        let args: Vec<OsString> = vec![
            OsString::from("--log-file-rotation-count"),
            OsString::from("1"),
            OsString::from("--log-file-rotation-max-size"),
            OsString::from("10"),
        ];

        let config = parse_args(Some(args));
        assert!(config.is_err())
    }

    #[test]
    fn commandline_args_parse_logfile_require_both_optional_params() {
        let args: Vec<OsString> = vec![
            OsString::from("--log-file-format"),
            OsString::from("json"),
            OsString::from("--log-file-path"),
            OsString::from("/tmp/zerotect/zerotect.log"),
            OsString::from("--log-file-rotation-count"),
            OsString::from("1"),
        ];

        let config = parse_args(Some(args));
        assert!(config.is_err())
    }

    #[test]
    fn commandline_args_parse_syslog_default() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. First param ignored."),
            OsString::from("--syslog"),
            OsString::from("cef"),
        ];

        let config = parse_args(Some(args)).unwrap();

        let sc = config.syslog.unwrap();
        assert_eq!(SyslogDestination::Default, sc.destination);
        assert_eq!(None, sc.path);
        assert_eq!(None, sc.server);
        assert_eq!(None, sc.hostname);
        assert_eq!(None, sc.local);
    }

    #[test]
    fn commandline_args_analytics_disable() {
        let args: Vec<OsString> = vec![
            OsString::from("burner program name. First param ignored."),
            OsString::from("--analytics-mode"),
            OsString::from("off"),
        ];

        let config = parse_args(Some(args)).unwrap();

        assert_eq!(AnalyticsMode::Off, config.analytics.mode);
    }

    #[test]
    fn toml_parse_all_direct() {
        let tomlcontents = r#"
        verbosity = 40

        [auto_configure]
        exception_trace = true
        fatal_signals = true

        [console]
        format = 'Text'

        [polycorder]
        auth_key = 'AuthKeyFromAccountManager3700793'
        node_id = 'NodeDiscriminator5462654'
        flush_event_count = 23
        flush_timeout_seconds = 39

        [syslog]
        format = 'CeF'
        destination = 'TCP'
        path = '/dev/log'
        server = '127.0.0.1:834'
        local = '127.0.0.1:342'
        hostname = 'ohi;afs'

        [logfile]
        format = 'tExT'
        filepath = '/tmp/test/path'
        rotation_file_count = 3
        rotation_file_max_size = 21

        [analytics]
        mode = 'detected'
        justification = 'full'

        "#;

        let toml_file = unique_temp_toml_file();
        println!("Writing TOML string to file: {}", &toml_file);
        fs::write(&toml_file, tomlcontents).expect("Unable to write TOML test file.");

        let config = parse_config_file(&toml_file).unwrap();

        assert_eq!(40, config.verbosity);

        //enabled by default always
        assert_eq!(AnalyticsMode::Detected, config.analytics.mode);
        assert_eq!(
            DetectedEventJustification::Full,
            config.analytics.justification
        );

        assert_eq!(true, config.auto_configure.exception_trace);
        assert_eq!(true, config.auto_configure.fatal_signals);

        assert_eq!(true, config.console.is_some());
        let cc = config.console.unwrap();
        assert_eq!(OutputFormat::Text, cc.format);

        assert_eq!(true, config.polycorder.is_some());
        let pc = config.polycorder.unwrap();
        assert_eq!("AuthKeyFromAccountManager3700793", pc.auth_key);
        assert_eq!("NodeDiscriminator5462654", pc.node_id);
        assert_eq!(39, pc.flush_timeout_seconds);
        assert_eq!(23, pc.flush_event_count);

        let sc = config.syslog.unwrap();
        assert_eq!(OutputFormat::CEF, sc.format);
        assert_eq!(SyslogDestination::Tcp, sc.destination);
        assert_eq!(Some("/dev/log".to_owned()), sc.path);
        assert_eq!(Some("127.0.0.1:834".to_owned()), sc.server);
        assert_eq!(Some("127.0.0.1:342".to_owned()), sc.local);
        assert_eq!(Some("ohi;afs".to_owned()), sc.hostname);

        let lfc = config.logfile.unwrap();
        assert_eq!(OutputFormat::Text, lfc.format);
        assert_eq!("/tmp/test/path".to_owned(), lfc.filepath);
        assert_eq!(Some(3), lfc.rotation_file_count);
        assert_eq!(Some(21), lfc.rotation_file_max_size);
    }

    #[test]
    fn toml_serialize_and_parse_random_values_direct() {
        for _i in 1..100 {
            // test this 100 times
            let config_expected = random_config_format();

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

            assert_eq!(
                config_expected, config_options_obtained,
                "The File contents are: \n\n{}",
                &config_toml_string
            );
        }
    }

    #[test]
    fn toml_parse_all_through_args() {
        let tomlcontents = r#"
        verbosity = 7

        [auto_configure]
        exception_trace = true
        fatal_signals = true

        [analytics]
        enabled = false

        [console]
        format = 'Text'

        [polycorder]
        auth_key = 'AuthKeyFromPolyverseAccountManager97439'
        node_id = 'UsefulNodeIdentifierToGroupEvents903439'
        flush_event_count = 10

        [polycorder.flush_timeout]
        secs = 10
        nanos = 0

        [syslog]
        format = 'jsoN'
        destination = 'uDp'
        path = '/dev/log/something/else'
        server = '127.0.0.1:345'
        local = '127.0.0.1:468'
        hostname = '.kndv;afs'

        [logfile]
        format = 'JSon'
        filepath = '/tmp/other/path'
        rotation_file_count = 92
        rotation_file_max_size = 107

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
        assert_eq!(true, config.console.is_some());
        assert_eq!(true, config.polycorder.is_some());
        assert_eq!(7, config.verbosity);

        let cc = config.console.unwrap();
        assert_eq!(OutputFormat::Text, cc.format);

        let pc = config.polycorder.unwrap();
        assert_eq!("AuthKeyFromPolyverseAccountManager97439", pc.auth_key);
        assert_eq!("UsefulNodeIdentifierToGroupEvents903439", pc.node_id);
        assert_eq!(10, pc.flush_timeout_seconds);
        assert_eq!(10, pc.flush_event_count);

        let sc = config.syslog.unwrap();
        assert_eq!(OutputFormat::JSON, sc.format);
        assert_eq!(SyslogDestination::Udp, sc.destination);
        assert_eq!(Some("/dev/log/something/else".to_owned()), sc.path);
        assert_eq!(Some("127.0.0.1:345".to_owned()), sc.server);
        assert_eq!(Some("127.0.0.1:468".to_owned()), sc.local);
        assert_eq!(Some(".kndv;afs".to_owned()), sc.hostname);

        let lfc = config.logfile.unwrap();
        assert_eq!(OutputFormat::JSON, lfc.format);
        assert_eq!("/tmp/other/path".to_owned(), lfc.filepath);
        assert_eq!(Some(92), lfc.rotation_file_count);
        assert_eq!(Some(107), lfc.rotation_file_max_size);
    }

    #[test]
    fn toml_serialize_and_parse_random_values_through_args() {
        for _i in 1..100 {
            // test this 100 times
            let config_expected = random_config_format();

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
        assert_eq!(false, config.console.is_some());
        assert_eq!(false, config.polycorder.is_some());
        assert_eq!(0, config.verbosity);
    }

    #[test]
    fn toml_parse_parse_partial_fields() {
        let tomlcontents = r#"
        verbosity = 5

        [polycorder]
        auth_key = "AuthKeyFromAccountManager5323552"

        [polycorder.flush_timeout]
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
        assert_eq!(false, config.console.is_some());
        assert_eq!(true, config.polycorder.is_some());
        assert_eq!(5, config.verbosity);

        let pc = config.polycorder.unwrap();
        assert_eq!("AuthKeyFromAccountManager5323552", pc.auth_key);
        assert_eq!(UNIDENTIFIED_NODE, pc.node_id);
        assert_eq!(
            DEFAULT_POLYCORDER_FLUSH_TIMEOUT_SECONDS,
            pc.flush_timeout_seconds
        );
        assert_eq!(DEFAULT_POLYCORDER_FLUSH_EVENT_COUNT, pc.flush_event_count);
    }

    #[test]
    fn toml_parse_parse_case_insensitive_enums() {
        let tomlcontents = r#"
        [console]
        format = 'tExT'

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

        assert!(config.console.is_some());
        assert_eq!(OutputFormat::Text, config.console.unwrap().format);
    }

    #[test]
    fn toml_error_polycorder_config_if_no_authkey() {
        let tomlcontents = r#"
        verbosity = 3

        [auto_configure]
        exception_trace = true
        fatal_signals = true

        [console]
        format = 'Text'

        [polycorder]
        node_id = 'UsefulNodeIdentifierToGroupEvents'
        flush_event_count = 10

        [polycorder.flush_timeout]
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
        assert!(maybe_config.is_err());
    }

    #[test]
    fn toml_file_and_cli_options_dont_mix() {
        let tomlcontents = r#"
        verbosity = 3

        [auto_configure]
        exception_trace = true
        fatal_signals = true

        [console]
        format = 'tExt'

        [polycorder]
        node_id = "NodeDiscriminator"
        flush_event_count = 10

        [polycorder.flush_timeout]
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
        let config_expected = ZerotectParams {
            auto_configure: AutoConfigure {
                exception_trace: true,
                fatal_signals: true,
                klog_include_timestamp: true,
            },
            analytics: AnalyticsConfig{
                mode: AnalyticsMode::Passthrough,
                justification: DetectedEventJustification::Summary,
                collection_timeout_seconds: DEFAULT_ANALYTICS_COLLECTION_TIMEOUT_SECONDS,
                event_lifetime_seconds: DEFAULT_ANALYTICS_EVENT_LIFETIME_SECONDS,
                max_event_count: DEFAULT_ANALYTICS_MAX_EVENT_COUNT,
                event_drop_count: DEFAULT_ANALYTICS_EVENT_DROP_COUNT,
            },
            monitor: MonitorConfig {
                gobble_old_events: false,
            },
            console: Some(ConsoleConfig {
                format: OutputFormat::Text,
            }),
            polycorder: Some(PolycorderConfig {
                auth_key: format!("AuthKeyFromPolyverseAccountManager"),
                node_id: "UsefulNodeIdentifierToGroupEvents".to_owned(),
                flush_timeout_seconds: DEFAULT_POLYCORDER_FLUSH_TIMEOUT_SECONDS,
                flush_event_count: DEFAULT_POLYCORDER_FLUSH_EVENT_COUNT,
            }),
            syslog: Some(SyslogConfig{
                format: OutputFormat::CEF,
                destination: SyslogDestination::Udp,
                local: Some("# only applicable to udp - the host:port to bind sender to (i.e. 127.0.0.1:0)".to_owned()),
                server: Some("# applicable to tcp and udp - the host:port to send syslog to (i.e. 127.0.0.1:601 or 127.0.0.1:514)".to_owned()),
                hostname: Some("# applicable to tcp and udp hostname for long entries".to_owned()),
                path: Some("# only applicable to unix - path to unix socket to connect to syslog (i.e. /dev/log or /var/run/syslog)".to_owned()),
            }),
            logfile: Some(LogFileConfig{
                filepath: "/test/path".to_owned(),
                format: OutputFormat::CEF,
                rotation_file_count: Some(1),
                rotation_file_max_size: Some(20),
            }),
            verbosity: 0,
        };

        let toml_file = format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/reference/zerotect.toml"
        );
        let config_toml_string = toml::to_string_pretty(&config_expected).unwrap();
        println!("Writing TOML string to file: {}", &toml_file);
        fs::write(&toml_file, config_toml_string).expect("Unable to write TOML test file.");
    }

    fn random_config_format() -> ZerotectParams {
        ZerotectParams {
            auto_configure: AutoConfigure {
                exception_trace: rand::thread_rng().gen_bool(0.5),
                fatal_signals: rand::thread_rng().gen_bool(0.5),
                klog_include_timestamp: rand::thread_rng().gen_bool(0.5),
            },
            analytics: AnalyticsConfig {
                mode: match rand::thread_rng().gen_range(0, 3) {
                    0 => AnalyticsMode::Off,
                    1 => AnalyticsMode::Passthrough,
                    _ => AnalyticsMode::Detected,
                },
                justification: match rand::thread_rng().gen_range(0, 3) {
                    0 => DetectedEventJustification::None,
                    1 => DetectedEventJustification::Summary,
                    _ => DetectedEventJustification::Full,
                },
                collection_timeout_seconds: rand::thread_rng().gen_range(1, 100),
                max_event_count: rand::thread_rng().gen_range(1, 100),
                event_drop_count: rand::thread_rng().gen_range(1, 100),
                event_lifetime_seconds: rand::thread_rng().gen_range(1, 100),
            },
            monitor: MonitorConfig {
                gobble_old_events: rand::thread_rng().gen_bool(0.5),
            },
            console: match rand::thread_rng().gen_bool(0.5) {
                true => Some(ConsoleConfig {
                    format: match rand::thread_rng().gen_bool(0.5) {
                        true => OutputFormat::JSON,
                        false => OutputFormat::Text,
                    },
                }),
                false => None,
            },
            polycorder: match rand::thread_rng().gen_bool(0.5) {
                true => Some(PolycorderConfig {
                    auth_key: format!(
                        "AuthKeyFromAccountManagerRandom{}",
                        rand::thread_rng().gen_range(0, 32000)
                    ),
                    node_id: format!(
                        "NodeDiscriminatorRandom{}",
                        rand::thread_rng().gen_range(0, 32000)
                    ),
                    flush_timeout_seconds: rand::thread_rng().gen_range(0, 500),
                    flush_event_count: rand::thread_rng().gen_range(0, 500),
                }),
                false => None,
            },
            syslog: match rand::thread_rng().gen_bool(0.5) {
                true => Some(SyslogConfig {
                    format: match rand::thread_rng().gen_bool(0.5) {
                        true => OutputFormat::JSON,
                        false => OutputFormat::CEF,
                    },
                    destination: match rand::thread_rng().gen_bool(0.5) {
                        true => SyslogDestination::Udp,
                        false => SyslogDestination::Unix,
                    },
                    path: match rand::thread_rng().gen_bool(0.5) {
                        true => Some(format!(
                            "RandomPath{}",
                            rand::thread_rng().gen_range(0, 32000)
                        )),
                        false => None,
                    },
                    server: match rand::thread_rng().gen_bool(0.5) {
                        true => Some(format!(
                            "RandomServer{}",
                            rand::thread_rng().gen_range(0, 32000)
                        )),
                        false => None,
                    },
                    local: match rand::thread_rng().gen_bool(0.5) {
                        true => Some(format!(
                            "RandomLocal{}",
                            rand::thread_rng().gen_range(0, 32000)
                        )),
                        false => None,
                    },
                    hostname: match rand::thread_rng().gen_bool(0.5) {
                        true => Some(format!(
                            "RandomHostname{}",
                            rand::thread_rng().gen_range(0, 32000)
                        )),
                        false => None,
                    },
                }),
                false => None,
            },
            logfile: match rand::thread_rng().gen_bool(0.5) {
                true => Some(LogFileConfig {
                    format: match rand::thread_rng().gen_bool(0.5) {
                        true => OutputFormat::JSON,
                        false => OutputFormat::CEF,
                    },
                    filepath: format!("RandomFilePath{}", rand::thread_rng().gen_range(0, 32000)),
                    rotation_file_count: match rand::thread_rng().gen_bool(0.5) {
                        true => Some(rand::thread_rng().gen_range(0, 32000)),
                        false => None,
                    },
                    rotation_file_max_size: match rand::thread_rng().gen_bool(0.5) {
                        true => Some(rand::thread_rng().gen_range(0, 32000)),
                        false => None,
                    },
                }),
                false => None,
            },
            verbosity: rand::thread_rng().gen_range(0, 250),
        }
    }
}
