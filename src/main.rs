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

fn main() {
    system::ensure_linux();
    let polytect_config = params::parse_args();

    let (monitor_sink, emitter_source): (Sender<events::Event>, Receiver<events::Event>) =
        mpsc::channel();

    let env_config_copy = polytect_config.clone();
    let config_event_sink = monitor_sink.clone();
    // ensure environment is kept stable every 5 minutes (in case something or someone disables the settings)
    thread::spawn(move || {
        let mut first: bool = true;
        loop {
            // initialize the system with config
            let events = system::modify_environment(&env_config_copy);
            if !first { // let the first time go
                for event in events.into_iter() {
                    eprintln!("System Configuration Thread: Configuration not stable. {}", &event);
                    if let Err(e) = config_event_sink.send(event) {
                        eprintln!("System Configuration Thread: Unable to send config event to the event emitter. This should never fail. Thread aborting. {}", e);
                    }
                }
            }

            first = false;
        }
    });

    let mverbosity = polytect_config.verbosity;
    let monitor_type = polytect_config.monitor_type;
    let monitor_handle = thread::spawn(move || {
        let mc = monitor::MonitorConfig {
            verbosity: mverbosity,
            monitor_type,
        };
        monitor::monitor(mc, monitor_sink);
    });

    let everbosity = polytect_config.verbosity;
    let console_config = polytect_config.console_config;
    let tricorder_config = polytect_config.tricorder_config;
    let emitter_handle = thread::spawn(move || {
        let ec = emitter::EmitterConfig {
            verbosity: everbosity,
            console_config,
            tricorder_config,
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
