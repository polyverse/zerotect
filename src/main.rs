#[macro_use]
extern crate enum_display_derive;
#[macro_use]
extern crate lazy_static;

mod init;
mod events;
mod emitter;
mod monitor;

use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread;


fn main() {
    let polytect_config = init::initialize();

    let (monitor_sink, emitter_source): (Sender<events::Event>, Receiver<events::Event>) = mpsc::channel();

    let mverbosity = polytect_config.verbosity;
    let monitor_type = polytect_config.monitor_type;
    let monitor_handle = thread::spawn(move || {
        let mc = monitor::MonitorConfig{
            verbosity: mverbosity,
            monitor_type,
        };
        monitor::monitor(mc, monitor_sink);
    });

    let everbosity = polytect_config.verbosity;
    let console_config =  polytect_config.console_config;
    let tricorder_config = polytect_config.tricorder_config;
    let emitter_handle = thread::spawn(move || {
        let ec = emitter::EmitterConfig{
            verbosity: everbosity,
            console_config,
            tricorder_config,
        };
        emitter::emit(ec, emitter_source);
    });

    eprintln!("Waiting indefinitely until monitor and emitter exit....");
    monitor_handle.join().expect("Unable to join on the monitoring thread");
    emitter_handle.join().expect("Unable to join on the emitter thread");
}

