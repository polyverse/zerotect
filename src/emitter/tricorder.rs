
use std::sync::mpsc::{channel, Sender, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;
use serde::{Serialize};
use reqwest;

use crate::emitter;
use crate::events;


const TRICORDER_PUBLISH_ENDPOINT: &str = "https://tricorder.polyverse.com/v1/events";

pub struct TricorderConfig {
    pub auth_key: String,
    pub node_id: String,

    // Flush all events if none arrive for this interval
    pub flush_timeout: Duration,

    // Flush after this number of items, even if more are arriving...
    pub flush_event_count: usize,
}

pub struct Tricorder {
    sender: Sender<events::Event>,
}

// The structure to send data to tricorder in...
#[derive(Serialize)]
struct Report<'l> {
    node_id: &'l str,
    events: &'l Vec<events::Event>,
}

impl emitter::Emitter for Tricorder {
    fn emit(&self, event: &events::Event) {
        let movable_copy = (*event).clone();
        if let Err(e) = self.sender.send(movable_copy) {
            eprintln!("Error queing event to tricorder: {}", e);
        }
    }
}

pub fn new(config: TricorderConfig) -> Tricorder {
    let (sender, receiver) : (Sender<events::Event>, Receiver<events::Event>) = channel();

    thread::spawn(move || {
        eprintln!("Emitter to Tricorder initialized.");
        let client = reqwest::Client::new();

        // This live-tests the built-in URL early.
        if let Err(e) = reqwest::Url::parse(TRICORDER_PUBLISH_ENDPOINT) {
            eprintln!("Tricorder: Aborting. Unable to parse built-in tricorder URL into a reqwest library url: {}", e);
            return;
        };

        let mut events: Vec<events::Event> = vec!();

        loop {
            let flush = match receiver.recv_timeout(config.flush_timeout) {
                Ok(event) => {
                    events.push(event);
                    if events.len() >= config.flush_event_count {
                        true
                    } else {
                        false
                    }
                },
                Err(e) => match e {
                    RecvTimeoutError::Timeout => true,
                    _ => {
                        eprintln!("Tricorder: Error receiving message from monitor: {}", e);
                        false
                    }
                }
            };

            if flush && events.len() > 0 {
                let report = Report{
                    node_id: config.node_id.as_str(),
                    events: &events,
                };

                let res = client.post(TRICORDER_PUBLISH_ENDPOINT)
                    .bearer_auth(&config.auth_key)
                    .json(&report)
                    .send();

                match res {
                    Ok(r) => eprintln!("Published {} events. Response from tricorder: {:?}", events.len(), r),
                    Err(e) => eprintln!("Tricorder: error publishing event to service {}: {}", TRICORDER_PUBLISH_ENDPOINT, e)
                }

                events.clear();
            }

        }
    });
    
    Tricorder{
        sender,
    }
}