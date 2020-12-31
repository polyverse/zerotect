// Copyright (c) 2019 Polyverse Corporation

#[macro_use]
extern crate enum_display_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate rust_cef_derive;
#[macro_use]
extern crate num_derive;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

mod analyzer;
mod common;
//mod emitter;
mod events;
mod formatter;
mod params;
mod raw_event_stream;
mod system;

use core::pin::Pin;
use futures::stream::Stream;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::{process, thread, time::Duration};
use tokio::{
    sync::mpsc::{error::SendError, unbounded_channel, UnboundedReceiver, UnboundedSender},
    time::sleep,
};
use tokio_stream::StreamExt;

#[derive(Debug)]
pub struct MainError(String);
impl Error for MainError {}
impl Display for MainError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "MainError:: {}", self.0)
    }
}
impl From<SendError<events::Event>> for MainError {
    fn from(err: SendError<events::Event>) -> Self {
        Self(format!("Inner SendError<events::Event> :: {}", err))
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

#[tokio::main]
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
    let config_events_stream = system::EnvironmentConfigurator::new(auto_configure_env, chostname);

    let resc = raw_event_stream::RawEventStreamConfig {
        verbosity: zerotect_config.verbosity,
        hostname: zerotect_config.hostname.clone(),
        gobble_old_events: zerotect_config.monitor.gobble_old_events,
    };
    let os_event_stream = raw_event_stream::new(resc).await?;

    // get a unified stream of all incoming events...
    let events_stream = Box::pin(os_event_stream.merge(config_events_stream));

    let analyzed_stream: Pin<Box<dyn Stream<Item = events::Event>>> =
        match zerotect_config.analytics.mode {
            params::AnalyticsMode::Off => events_stream,
            _ => Box::pin(
                analyzer::new(
                    zerotect_config.verbosity,
                    zerotect_config.analytics,
                    events_stream,
                )
                .await?,
            ),
        };

    /*
    // split these up before a move
    let everbosity = zerotect_config.verbosity;
    let console = zerotect_config.console;
    let polycorder = zerotect_config.polycorder;
    let syslog = zerotect_config.syslog;
    let logfile = zerotect_config.logfile;
    let ehostname = zerotect_config.hostname;
    let pagerduty_routing_key = zerotect_config.pagerduty_routing_key;

    let emitter_thread_result = thread::Builder::new()
        .name("Event Emitter Thread".to_owned())
        .spawn(move || {
            let ec = emitter::EmitterConfig {
                verbosity: everbosity,
                console,
                polycorder,
                syslog,
                logfile,
                pagerduty_routing_key,
            };
            if let Err(e) = emitter::emit(ec, emitter_source, ehostname) {
                eprintln!("Error launching Emitter: {}", e);
                process::exit(1);
            }
        });

    let emitter_handle = match emitter_thread_result {
        Ok(eh) => eh,
        Err(e) => {
            eprintln!("An error occurred spawning the emitter thread: {}", e);
            process::exit(1);
        }
    };

    eprintln!("Waiting indefinitely until environment monitor, event monitor, analyzer and emitter exit....");
    tokio::try_join!(env_future, monitor_future);

    emitter_handle
        .join()
        .expect("Unable to join on the emitter thread");
    if let Some(analyzer_handle) = maybe_analyzer_handle {
        analyzer_handle
            .join()
            .expect("Unable to join on the analyzer thread");
    }
    */

    Ok(())
}

/*
fn optional_analyzer(
    verbosity: u8,
    ac: params::AnalyticsConfig,
) -> (
    UnboundedSender<events::Event>,
    UnboundedReceiver<events::Event>,
    Option<thread::JoinHandle<()>>,
) {
    let (monitor_sink, analyzer_source): (UnboundedSender<events::Event>, UnboundedReceiver<events::Event>) =
        unbounded_channel();

    if ac.mode == params::AnalyticsMode::Off {
        // if analytics is disabled, short-circuit the first channel between monitor and emitter
        return (monitor_sink, analyzer_source, None);
    }

    let (analyzer_sink, emitter_source): (UnboundedSender<events::Event>, UnboundedReceiver<events::Event>) =
        unbounded_channel();

    let analyzer_thread_result = thread::Builder::new()
        .name("Event Analyzer Thread".to_owned())
        .spawn(move || {
            if let Err(e) = analyzer::analyze(verbosity, ac, analyzer_source, analyzer_sink) {
                eprintln!("Error launching Analyzer: {}", e);
                process::exit(1);
            }
        });

    let analyzer_handle = match analyzer_thread_result {
        Ok(ah) => ah,
        Err(e) => {
            eprintln!("An error occurred spawning the analyzer thread: {}", e);
            process::exit(1);
        }
    };

    (monitor_sink, emitter_source, Some(analyzer_handle))
}
*/
