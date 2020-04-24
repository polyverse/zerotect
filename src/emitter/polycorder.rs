// Copyright (c) 2019 Polyverse Corporation

use http::StatusCode;
use reqwest;
use serde::Serialize;
use std::convert::From;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::thread;

use crate::emitter;
use crate::events;
use crate::params;

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

#[derive(Debug)]
pub struct PolycorderError(String);
impl error::Error for PolycorderError {}
impl Display for PolycorderError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "PolycorderError:: {}", &self.0)
    }
}
impl From<std::io::Error> for PolycorderError {
    fn from(err: std::io::Error) -> PolycorderError {
        PolycorderError(format!("Inner std::io::Error: {}", err))
    }
}

pub fn new(config: params::PolycorderConfig) -> Result<Polycorder, PolycorderError> {
    let (sender, receiver): (Sender<events::Event>, Receiver<events::Event>) = channel();

    thread::Builder::new().name("Emit to Polycorder Thread".to_owned()).spawn(move || {
        eprintln!("Emitter to Polycorder initialized.");
        let client = reqwest::blocking::Client::new();

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

                let response_result = client
                    .post(POLYCORDER_PUBLISH_ENDPOINT)
                    .bearer_auth(&config.auth_key)
                    .json(&report)
                    .send();
                match response_result {
                    Ok(response) => {
                        let status = response.status();
                        // explain common statuses a bit more...
                        if status.is_success() {
                            if status == StatusCode::OK {
                                eprintln!(
                                    "Successfully published {} events. Clearing buffer. Response from Polycorder: {:?}",
                                    events.len(),
                                    response
                                );
                            } else {
                                eprintln!("The HTTP request was successful, but returned a non-OK status: {}", status)
                            }
                            events.clear();
                        } else if status.is_server_error() {
                            eprintln!(
                                "Unable to publish {} events due to a server-side error. Response from Polycorder: {:?}",
                                events.len(),
                                response
                            );
                        } else if status == StatusCode::UNAUTHORIZED {
                            eprintln!(
                                "Unable to publish {} events due to a failure to authenticate using the polycorder authkey {}. Response from Polycorder: {:?}",
                                events.len(),
                                &config.auth_key,
                                response
                            );
                        } else {
                            eprintln!(
                                "Failed to publish {} events to Polycorder due to an unexpected error. Response from Polycorder: {:?}",
                                events.len(),
                                response
                            );
                        }
                    },
                    Err(e) => eprintln!(
                        "Polycorder: error making POST request to Polycorder service {}: {}",
                        POLYCORDER_PUBLISH_ENDPOINT, e
                    ),
                }
            }
        }
    })?;

    Ok(Polycorder { sender })
}
