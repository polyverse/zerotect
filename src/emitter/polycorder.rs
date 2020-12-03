// Copyright (c) 2019 Polyverse Corporation

use http::StatusCode;
use libflate::gzip::Encoder;
use serde::Serialize;
use std::convert::From;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::Write;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use crate::emitter;
use crate::events;
use crate::params;

const AUTHORIZATION: &str = "authorization";
const CONTENT_TYPE: &str = "content-type";
const USER_AGENT: &str = "user-agent";
const CONTENT_ENCODING: &str = "content-encoding";

const POLYCORDER_PUBLISH_ENDPOINT: &str = "https://polycorder.polyverse.com/v1/events";
const GZIP_THRESHOLD_BYTES: usize = 512;
const CONTENT_ENCODING_GZIP: &str = "gzip";
const CONTENT_ENCODING_IDENTITY: &str = "identity";
const CONTENT_TYPE_JSON: &str = "application/json";
const USER_AGENT_ZEROTECT: &str = "zerotect";

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
    fn emit(&mut self, event: &events::Event) {
        if let Err(e) = self.sender.send(event.clone()) {
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
    let (sender, receiver): (Sender<events::Event>, Receiver<events::Event>) = channel();
    thread::Builder::new()
        .name("Emit to Polycorder Thread".to_owned())
        .spawn(move || publish_to_polycorder_forever(config, receiver, verbosity))?;

    Ok(Polycorder { sender })
}

fn publish_to_polycorder_forever(
    config: params::PolycorderConfig,
    receiver: Receiver<events::Event>,
    verbosity: u8,
) {
    eprintln!("Polycorder: Emitter to Polycorder initialized.");

    let mut events: Vec<events::Event> = vec![];

    let timeout_duration = Duration::from_secs(config.flush_timeout_seconds);

    let bearer_token = format!("Bearer {}", config.auth_key);
    let bearer_token_str = bearer_token.as_str();

    loop {
        let flush = match receiver.recv_timeout(timeout_duration) {
            Ok(event) => {
                events.push(event);
                events.len() >= config.flush_event_count
            }
            Err(e) => match e {
                RecvTimeoutError::Timeout => true,
                _ => {
                    eprintln!("Polycorder: Error receiving message from monitor: {}", e);
                    false
                }
            },
        };

        if flush && !events.is_empty() {
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

            // sync post request of some json.
            // requires feature:
            // `ureq = { version = "*", features = ["json"] }`
            let resp = ureq::post(POLYCORDER_PUBLISH_ENDPOINT)
                .set(AUTHORIZATION, bearer_token_str)
                .set(CONTENT_TYPE, CONTENT_TYPE_JSON)
                .set(CONTENT_ENCODING, content_encoding)
                .set(USER_AGENT, USER_AGENT_ZEROTECT)
                // 10 seconds should be plenty to post to polycorder
                .timeout(Duration::from_secs(10))
                .send_bytes(body.as_slice());

            //ok if response is 200-299.
            if resp.ok() {
                if resp.status() == StatusCode::OK {
                    eprintln!(
                        "Polycorder: Successfully published {} events. Clearing buffer. Response from Polycorder: {:?}",
                        events.len(),
                        resp
                    );
                } else {
                    eprintln!("Polycorder: The HTTP request was successful, but returned a non-OK status: {}", resp.status_line());
                }
                events.clear();
            } else if resp.server_error() {
                eprintln!(
                    "Polycorder: Unable to publish {} events due to a server-side error. Response from Polycorder: {:?}",
                    events.len(),
                    resp
                );
            } else if resp.client_error() {
                if resp.status() == StatusCode::UNAUTHORIZED {
                    eprintln!(
                        "Polycorder: Unable to publish {} events due to a failure to authenticate using the polycorder authkey {}. Response from Polycorder: {:?}",
                        events.len(),
                        &config.auth_key,
                        resp
                    );
                } else {
                    eprintln!(
                        "Polycorder: Failed to publish {} events to Polycorder due to an unexpected client-side error. Response from Polycorder: {:?}",
                        events.len(),
                        resp
                    );
                }
            }
        }
    }
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
