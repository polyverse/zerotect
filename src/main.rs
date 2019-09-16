mod init;
mod events;
mod emitter;
mod monitor;

use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread;


fn main() {
    init::initialize();

    let (monitor_sink, emitter_source): (Sender<events::Event>, Receiver<events::Event>) = mpsc::channel();

    let monitor_handle = thread::spawn(|| {
        let mc = monitor::MonitorConfig{
            dmesg_location: None,
            poll_interval: None,
            args: None,
        };
        monitor::monitor(mc, monitor_sink);
    });

    let emitter_handle = thread::spawn(|| {
        let ec = emitter::EmitterConfig{

        };
        emitter::emit(ec, emitter_source);
    });

    eprintln!("Waiting indefinitely under monitor and emitter exit....");
    monitor_handle.join().expect("Unable to join on the monitoring thread");
    emitter_handle.join().expect("Unable to join on the emitter thread");
}

