use reqwest;
use serde::Serialize;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::thread;

use crate::emitter;
use crate::events;
use crate::params;

// `block_on` blocks the current thread until the provided future has run to
// completion. Other executors provide more complex behavior, like scheduling
// multiple futures onto the same thread.
use futures::executor::block_on;

const POLYCORDER_PUBLISH_ENDPOINT: &str = "https://polycorder.polyverse.com/v1/events";

pub struct Polycorder {
    sender: Sender<events::Event>,
}

// The structure to send data to Polycorder in...
#[derive(Serialize)]
struct Report<'l> {
    node_id: &'l str,
    events: &'l Vec<events::Event>,
}

impl emitter::Emitter for Polycorder {
    fn emit(&self, event: &events::Event) {
        let movable_copy = (*event).clone();
        if let Err(e) = self.sender.send(movable_copy) {
            eprintln!("Error queing event to Polycorder: {}", e);
        }
    }
}

pub fn new(config: params::PolycorderConfig) -> Polycorder {
    let (sender, receiver): (Sender<events::Event>, Receiver<events::Event>) = channel();

    thread::spawn(move || {
        eprintln!("Emitter to Polycorder initialized.");
        let client = reqwest::Client::new();

        // This live-tests the built-in URL early.
        if let Err(e) = reqwest::Url::parse(POLYCORDER_PUBLISH_ENDPOINT) {
            eprintln!("Polycorder: Aborting. Unable to parse built-in Polycorder URL into a reqwest library url: {}", e);
            return;
        };

        let mut events: Vec<events::Event> = vec![];

        loop {
            let flush = match receiver.recv_timeout(config.flush_timeout) {
                Ok(event) => {
                    events.push(event);
                    if events.len() >= config.flush_event_count {
                        true
                    } else {
                        false
                    }
                }
                Err(e) => match e {
                    RecvTimeoutError::Timeout => true,
                    _ => {
                        eprintln!("Polycorder: Error receiving message from monitor: {}", e);
                        false
                    }
                },
            };

            if flush && events.len() > 0 {
                let report = Report {
                    node_id: config.node_id.as_str(),
                    events: &events,
                };

                let res = block_on(
                    client
                        .post(POLYCORDER_PUBLISH_ENDPOINT)
                        .bearer_auth(&config.auth_key)
                        .json(&report)
                        .send(),
                );

                match res {
                    Ok(r) => eprintln!(
                        "Published {} events. Response from Polycorder: {:?}",
                        events.len(),
                        r
                    ),
                    Err(e) => eprintln!(
                        "Polycorder: error publishing event to service {}: {}",
                        POLYCORDER_PUBLISH_ENDPOINT, e
                    ),
                }

                events.clear();
            }
        }
    });

    Polycorder { sender }
}
