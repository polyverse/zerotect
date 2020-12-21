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
mod emitter;
mod events;
mod formatter;
mod monitor;
mod params;
mod system;

use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;
use std::error::Error;
use std::process;

use tokio::time::sleep;


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

    let (monitor_sink, emitter_source, maybe_analyzer_handle) =
        optional_analyzer(zerotect_config.verbosity, zerotect_config.analytics);

    let auto_configure_env = zerotect_config.auto_configure;
    let config_event_sink = monitor_sink.clone();
    let chostname = zerotect_config.hostname.clone();
    // ensure environment is kept stable every 5 minutes (in case something or someone disables the settings)
    let env_future = configure_environment(auto_configure_env, chostname, config_event_sink);

    let mc = monitor::MonitorConfig {
        verbosity: zerotect_config.verbosity,
        hostname: zerotect_config.hostname.clone(),
        gobble_old_events: zerotect_config.monitor.gobble_old_events,
    };
    let monitor_future = monitor::monitor(mc, monitor_sink);

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

    Ok(())
}

fn optional_analyzer(
    verbosity: u8,
    ac: params::AnalyticsConfig,
) -> (
    Sender<events::Event>,
    Receiver<events::Event>,
    Option<thread::JoinHandle<()>>,
) {
    let (monitor_sink, analyzer_source): (Sender<events::Event>, Receiver<events::Event>) =
        mpsc::channel();

    if ac.mode == params::AnalyticsMode::Off {
        // if analytics is disabled, short-circuit the first channel between monitor and emitter
        return (monitor_sink, analyzer_source, None);
    }

    let (analyzer_sink, emitter_source): (Sender<events::Event>, Receiver<events::Event>) =
        mpsc::channel();

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

async fn configure_environment(
    auto_config: params::AutoConfigure,
    hostname: Option<String>,
    config_event_sink: Sender<events::Event>,
) -> Result<()> {
    // initialize the system with config
    system::modify_environment(&auto_config, &hostname).await?

    // let the first time go from config-mismatch event reporting
    loop {
        // reinforce the system with config
        let events = system::modify_environment(&auto_config, &hostname).await?
        for event in events.into_iter() {
            eprintln!(
                "System Configuration Thread: Configuration not stable. {}",
                &event
            );
            config_event_sink.send(event)?
        }

        // ensure configuratione very five minutes.
        sleep(Duration::from_secs(300)).await;
    }
}
