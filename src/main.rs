// Copyright (c) 2019 Polyverse Corporation

mod analyzer;
mod common;
mod emitter;
mod events;
mod formatter;
mod params;
mod raw_event_stream;
mod system;

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::process;
use std::time::Duration;
use tokio_stream::StreamExt;

#[derive(Debug)]
pub struct MainError(String);
impl Error for MainError {}
impl Display for MainError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "MainError:: {}", self.0)
    }
}
impl From<system::SystemConfigError> for MainError {
    fn from(err: system::SystemConfigError) -> Self {
        Self(format!("Inner system::SystemConfigError :: {}", err))
    }
}
impl From<raw_event_stream::RawEventStreamError> for MainError {
    fn from(err: raw_event_stream::RawEventStreamError) -> Self {
        Self(format!(
            "Inner raw_event_stream::RawEventStreamError :: {}",
            err
        ))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    if let Err(e) = system::ensure_linux() {
        eprintln!(
            "Error ensuring the operating system we're running on is Linux: {}",
            e
        );
        process::exit(1);
    }

    let zerotect_config = match params::parse_args(None) {
        Ok(pc) => pc,
        Err(e) => match e.inner_error {
            params::InnerError::ClapError(ce) => ce.exit(),
            _ => {
                eprintln!("Error when parsing configuration parameters (whether from CLI or from config file): {}", e);
                process::exit(1);
            }
        },
    };

    let auto_configure_env = zerotect_config.auto_configure;
    let chostname = zerotect_config.hostname.clone();
    // ensure environment is kept stable every 5 minutes (in case something or someone disables the settings)
    let mut config_events_stream =
        system::EnvironmentConfigurator::create_environment_configrator_stream(
            auto_configure_env,
            chostname,
        );

    // enforce config before we create raw event stream,
    // since the config affects how it works
    if let Err(e) = config_events_stream.enforce_config() {
        panic!("Error in Environment Configurator. Panicking. {}", e);
    }

    let resc = raw_event_stream::RawEventStreamConfig {
        verbosity: zerotect_config.verbosity,
        hostname: zerotect_config.hostname.clone(),
        gobble_old_events: zerotect_config.monitor.gobble_old_events,
        flush_timeout: Duration::from_secs(1),
    };
    let os_event_stream =
        raw_event_stream::RawEventStream::<rmesg::EntriesStream>::create_raw_event_stream(resc)
            .await?;

    // get a unified stream of all incoming events...
    let merged_events_stream = os_event_stream.merge(config_events_stream);

    let analyzed_stream = Box::pin(
        analyzer::Analyzer::analyzer_over_stream(
            zerotect_config.verbosity,
            zerotect_config.analytics,
            merged_events_stream,
        )
        .await?,
    );

    // split these up before a move
    let ec = emitter::EmitterConfig {
        verbosity: zerotect_config.verbosity,
        console: zerotect_config.console,
        polycorder: zerotect_config.polycorder,
        syslog: zerotect_config.syslog,
        logfile: zerotect_config.logfile,
        pagerduty_routing_key: zerotect_config.pagerduty_routing_key,
    };

    emitter::emit_forever(ec, analyzed_stream, zerotect_config.hostname).await?;

    Ok(())
}
