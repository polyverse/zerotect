// Copyright (c) 2019 Polyverse Corporation

use crate::emitter;
use crate::events;
use crate::formatter::new as new_formatter;
use crate::params;
use tokio::sync::broadcast;

pub async fn emit_forever(
    config: params::ConsoleConfig,
    mut source: broadcast::Receiver<events::Event>,
) -> Result<(), emitter::EmitterError> {
    let formatter = new_formatter(&config.format);

    loop {
        match source.recv().await {
            Ok(event) => match formatter.format(&event) {
                Ok(formattedstr) => println!("{}", formattedstr),
                Err(e) => eprintln!(
                    "Console Logger: Ignoring error formatting event to {:?}: {}",
                    config.format, e
                ),
            },
            Err(broadcast::error::RecvError::Lagged(count)) => eprintln!(
                "Console emitter is lagging behind generated events. {} events have been dropped.",
                count
            ),
            Err(broadcast::error::RecvError::Closed) => {
                panic!("Console emitter event source closed. Panicking and exiting.")
            }
        }
    }
}
