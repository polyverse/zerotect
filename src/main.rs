// Copyright (c) 2019 Polyverse Corporation

#[macro_use]
extern crate enum_display_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate rust_cef_derive;

mod analyzer;
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

use std::process;

fn main() {
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

    let (monitor_sink, analyzer_source): (Sender<events::Event>, Receiver<events::Event>) =
        mpsc::channel();
    let (analyzer_sink, emitter_source): (Sender<events::Event>, Receiver<events::Event>) =
        mpsc::channel();

    let auto_configure_env = zerotect_config.auto_configure;
    let config_event_sink = monitor_sink.clone();
    // ensure environment is kept stable every 5 minutes (in case something or someone disables the settings)
    let env_thread_result = thread::Builder::new()
        .name("Environment Configuration Thread".to_owned())
        .spawn(move || configure_environment(auto_configure_env, config_event_sink));

    if let Err(e) = env_thread_result {
        eprintln!("An error occurred spawning the thread to continually ensure configuration settings/flags: {}", e);
        process::exit(1);
    }

    let mverbosity = zerotect_config.verbosity;
    let mc = zerotect_config.monitor_config;
    let monitor_thread_result = thread::Builder::new()
        .name("Event Monitoring Thread".to_owned())
        .spawn(move || {
            let mc = monitor::MonitorConfig {
                verbosity: mverbosity,
                gobble_old_events: mc.gobble_old_events,
            };
            if let Err(e) = monitor::monitor(mc, monitor_sink) {
                eprintln!("Error launching Monitor: {}", e);
                process::exit(1);
            }
        });

    let monitor_handle = match monitor_thread_result {
        Ok(mh) => mh,
        Err(e) => {
            eprintln!("An error occurred spawning the monitoring thread: {}", e);
            process::exit(1);
        }
    };

    let averbosity = zerotect_config.verbosity;
    let analyzer_thread_result = thread::Builder::new()
        .name("Event Analyzer Thread".to_owned())
        .spawn(move || {
            let ac = analyzer::AnalyzerConfig {
                verbosity: averbosity,
            };
            if let Err(e) = analyzer::analyze(ac, analyzer_source, analyzer_sink) {
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

    // split these up before a move
    let everbosity = zerotect_config.verbosity;
    let console_config = zerotect_config.console_config;
    let polycorder_config = zerotect_config.polycorder_config;
    let syslog_config = zerotect_config.syslog_config;
    let logfile_config = zerotect_config.logfile_config;

    let emitter_thread_result = thread::Builder::new()
        .name("Event Emitter Thread".to_owned())
        .spawn(move || {
            let ec = emitter::EmitterConfig {
                verbosity: everbosity,
                console_config,
                polycorder_config,
                syslog_config,
                logfile_config,
            };
            if let Err(e) = emitter::emit(ec, emitter_source) {
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
    analyzer_handle
        .join()
        .expect("Unable to join on the analyzer thread");
    emitter_handle
        .join()
        .expect("Unable to join on the emitter thread");
}

fn configure_environment(
    auto_config: params::AutoConfigure,
    config_event_sink: Sender<events::Event>,
) {
    // initialize the system with config
    if let Err(e) = system::modify_environment(&auto_config) {
        eprintln!(
            "Error modifying the system settings to enable monitoring (as commanded): {}",
            e
        );
        process::exit(1);
    }

    // let the first time go from config-mismatch event reporting
    loop {
        // reinforce the system with config
        match system::modify_environment(&auto_config) {
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
        thread::sleep(Duration::from_secs(300));
    }
}
