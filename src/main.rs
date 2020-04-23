// Copyright (c) 2019 Polyverse Corporation

#[macro_use]
extern crate enum_display_derive;
#[macro_use]
extern crate lazy_static;

mod emitter;
mod events;
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

    let polytect_config = match params::parse_args(None) {
        Ok(pc) => pc,
        Err(e) => match e.inner_error {
            params::InnerError::ClapError(ce) => ce.exit(),
            _ => {
                eprintln!("Error when parsing configuration parameters (whether from CLI or from config file): {}", e);
                process::exit(1);
            }
        },
    };

    let (monitor_sink, emitter_source): (Sender<events::Event>, Receiver<events::Event>) =
        mpsc::channel();

    let env_config_copy = polytect_config.clone();
    let config_event_sink = monitor_sink.clone();
    // ensure environment is kept stable every 5 minutes (in case something or someone disables the settings)
    thread::spawn(move || {
        // initialize the system with config
        if let Err(e) = system::modify_environment(&env_config_copy.auto_configure) {
            eprintln!(
                "Error modifying the system settings to enable monitoring (as commanded): {}",
                e
            );
            process::exit(1);
        }

        // let the first time go from config-mismatch event reporting
        loop {
            // reinforce the system with config
            match system::modify_environment(&env_config_copy.auto_configure) {
                Err(e) => {
                    eprintln!("Error modifying the system settings to enable monitoring (as commanded): {}", e);
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
    });

    let mverbosity = polytect_config.verbosity;
    let monitor_handle = thread::spawn(move || {
        let mc = monitor::MonitorConfig {
            verbosity: mverbosity,
        };
        if let Err(e) = monitor::monitor(mc, monitor_sink) {
            eprintln!("{}", e);
            process::exit(1);
        }
    });

    let everbosity = polytect_config.verbosity;
    let console_config = polytect_config.console_config;
    let polycorder_config = polytect_config.polycorder_config;
    let emitter_handle = thread::spawn(move || {
        let ec = emitter::EmitterConfig {
            verbosity: everbosity,
            console_config,
            polycorder_config,
        };
        emitter::emit(ec, emitter_source);
    });

    eprintln!("Waiting indefinitely until monitor and emitter exit....");
    monitor_handle
        .join()
        .expect("Unable to join on the monitoring thread");
    emitter_handle
        .join()
        .expect("Unable to join on the emitter thread");
}
