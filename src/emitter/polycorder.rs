// Copyright (c) 2019 Polyverse Corporation

use http::StatusCode;
use libflate::gzip::Encoder;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use serde::Serialize;
use serde_json;
use std::convert::From;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::Write;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::thread;

use crate::emitter;
use crate::events;
use crate::params;

const POLYCORDER_PUBLISH_ENDPOINT: &str = "https://polycorder.polyverse.com/v1/events";
const GZIP_THRESHOLD_BYTES: usize = 512;
const CONTENT_ENCODING_GZIP: &str = "gzip";
const CONTENT_ENCODING_IDENTITY: &str = "identity";
const CONTENT_TYPE_JSON: &str = "application/json";
const USER_AGENT: &str = "polytect";

pub struct Polycorder {
    sender: Sender<events::Version>,
}

// The structure to send data to Polycorder in...
#[derive(Serialize)]
struct Report<'l> {
    node_id: &'l str,
    events: &'l Vec<events::Version>,
}

impl emitter::Emitter for Polycorder {
    fn emit(&self, event: &events::Version) {
        let movable_copy = (*event).clone();
        if let Err(e) = self.sender.send(movable_copy) {
            eprintln!("Polycorder: Error queing event to Polycorder: {}", e);
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

pub fn new(config: params::PolycorderConfig, verbosity: u8) -> Result<Polycorder, PolycorderError> {
    let (sender, receiver): (Sender<events::Version>, Receiver<events::Version>) = channel();

    let bearer_token = match HeaderValue::from_str(format!("Bearer {}", config.auth_key).as_str()) {
        Ok(b) => b,
        Err(e) => {
            return Err(PolycorderError(format!(
                "Polycorder: Aborting. Unable to create the bearer auth token due to error: {}",
                e
            )))
        }
    };
    let content_type_json = match HeaderValue::from_str(CONTENT_TYPE_JSON) {
        Ok(c) => c,
        Err(e) => {
            return Err(PolycorderError(format!(
            "Polycorder: Aborting. Unable to create the content type json header due to error: {}",
            e
        )))
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, bearer_token);
    headers.insert(CONTENT_TYPE, content_type_json);

    let client = match Client::builder()
        .user_agent(USER_AGENT)
        .default_headers(headers)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return Err(PolycorderError(format!(
                "Polycorder: Aborting. Unable to create reqwest client: {}",
                e
            )))
        }
    };

    // This live-tests the built-in URL early.
    if let Err(e) = reqwest::Url::parse(POLYCORDER_PUBLISH_ENDPOINT) {
        return Err(PolycorderError(format!("Polycorder: Aborting. Unable to parse built-in Polycorder URL into a reqwest library url: {}", e)));
    };

    thread::Builder::new().name("Emit to Polycorder Thread".to_owned()).spawn(move || {
        eprintln!("Polycorder: Emitter to Polycorder initialized.");

        let mut events: Vec<events::Version> = vec![];

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
                let json_serialized_report = match serde_json::to_vec(&report) {
                    Ok(serialized_report) => serialized_report,
                    Err(e) => {
                        eprintln!("Polycorder: error serializing report to JSON. This shouldn't happen. Clearing buffer so future events can continue being sent. Error: {:?}", e);
                        events.clear();
                        continue; // keep going on the loop
                    }
                };

                let (body, content_encoding) = encode_payload(json_serialized_report, verbosity);

                let response_result = client
                    .post(POLYCORDER_PUBLISH_ENDPOINT)
                    .header(CONTENT_ENCODING, content_encoding)
                    .body(body)
                    .send();
                match response_result {
                    Ok(response) => {
                        let status = response.status();
                        // explain common statuses a bit more...
                        if status.is_success() {
                            if status == StatusCode::OK {
                                eprintln!(
                                    "Polycorder: Successfully published {} events. Clearing buffer. Response from Polycorder: {:?}",
                                    events.len(),
                                    response
                                );
                            } else {
                                eprintln!("Polycorder: The HTTP request was successful, but returned a non-OK status: {}", status)
                            }
                            events.clear();
                        } else if status.is_server_error() {
                            eprintln!(
                                "Polycorder: Unable to publish {} events due to a server-side error. Response from Polycorder: {:?}",
                                events.len(),
                                response
                            );
                        } else if status == StatusCode::UNAUTHORIZED {
                            eprintln!(
                                "Polycorder: Unable to publish {} events due to a failure to authenticate using the polycorder authkey {}. Response from Polycorder: {:?}",
                                events.len(),
                                &config.auth_key,
                                response
                            );
                        } else {
                            eprintln!(
                                "Polycorder: Failed to publish {} events to Polycorder due to an unexpected error. Response from Polycorder: {:?}",
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

fn encode_payload(raw_payload: Vec<u8>, verbosity: u8) -> (Vec<u8>, &'static str) {
    match raw_payload.len() > GZIP_THRESHOLD_BYTES {
        true => {
            if verbosity > 0 {
                eprintln!("Polycorder: Compressing payload because it is {} bytes, thus greater than than threshold of {} bytes", raw_payload.len(), GZIP_THRESHOLD_BYTES);
            }

            // Encoding
            let mut encoder = match Encoder::new(Vec::new()) {
                Ok(encoder) => encoder,
                Err(e) => {
                    eprintln!("Unable to create a GZIP Encoder. Defaulting to uncompressed payload. Error: {:?}", e);
                    return (raw_payload, CONTENT_ENCODING_IDENTITY);
                }
            };

            if let Err(e) = encoder.write_all(&raw_payload) {
                eprintln!("Unable to write the serialized raw payload to GZIP encoder. Defaulting to uncompressed payload. Error: {:?}", e);
                return (raw_payload, CONTENT_ENCODING_IDENTITY);
            };

            let compressed_payload = match encoder.finish().into_result() {
                Ok(compressed) => compressed,
                Err(e) => {
                    eprintln!("Unable to GZIP the contents. Defaulting to uncompressed payload. Error: {:?}", e);
                    return (raw_payload, CONTENT_ENCODING_IDENTITY);
                }
            };

            if verbosity > 1 {
                eprintln!(
                    "GZIPed down to {} bytes from original {} bytes.",
                    compressed_payload.len(),
                    raw_payload.len()
                );
            }

            (compressed_payload, CONTENT_ENCODING_GZIP)
        }
        false => {
            if verbosity > 0 {
                eprintln!("Polycorder: Not compressing upload payload because it is {} bytes, thus smaller than (or equal to) threshold of {} bytes", raw_payload.len(), GZIP_THRESHOLD_BYTES);
            }
            (raw_payload, CONTENT_ENCODING_IDENTITY)
        }
    }
}
