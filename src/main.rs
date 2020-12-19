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
    let _env_joinhandle = tokio::spawn(async move {configure_environment(auto_configure_env, chostname, config_event_sink).await});

    let mverbosity = zerotect_config.verbosity;
    let mc = zerotect_config.monitor;
    let mhostname = zerotect_config.hostname.clone();
    let monitor_joinhandle = tokio::spawn(async move || {
        let mc = monitor::MonitorConfig {
            verbosity: mverbosity,
            hostname: mhostname,
            gobble_old_events: mc.gobble_old_events,
        };
        if let Err(e) = monitor::monitor(mc, monitor_sink).await {
            eprintln!("Error launching Monitor: {}", e);
            process::exit(1);
        }
    });

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

    eprintln!("Waiting indefinitely until monitor and emitter exit....");
    monitor_handle
        .join()
        .expect("Unable to join on the monitoring thread");
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
) {
    // initialize the system with config
    if let Err(e) = system::modify_environment(&auto_config, &hostname).await {
        eprintln!(
            "Error modifying the system settings to enable monitoring (as commanded): {}",
            e
        );
        process::exit(1);
    }

    // let the first time go from config-mismatch event reporting
    loop {
        // reinforce the system with config
        match system::modify_environment(&auto_config, &hostname).await {
            Err(e) => {
                eprintln!(
                    "Error modifying the system settings to enable monitoring (as commanded): {}",
                    e
                );
                process::exit(1);
            }
            Ok(events) => {
                for event in events.into_iter() {
                    eprintln!(
                        "System Configuration Thread: Configuration not stable. {}",
                        &event
                    );
                    if let Err(e) = config_event_sink.send(event) {
                        eprintln!("System Configuration Thread: Unable to send config event to the event emitter. This should never fail. Thread aborting. {}", e);
                        process::exit(1);
                    }
                }
            }
        }

        // ensure configuratione very five minutes.
        sleep(Duration::from_secs(300)).await;
    }
}
