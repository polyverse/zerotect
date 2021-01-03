// Copyright (c) 2019 Polyverse Corporation

use http::StatusCode;
use libflate::gzip::Encoder;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use reqwest::Client;
use serde::Serialize;
use std::convert::From;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::Write;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::timeout;

use crate::emitter;
use crate::events;
use crate::params;

const POLYCORDER_PUBLISH_ENDPOINT: &str = "https://polycorder.polyverse.com/v1/events";
const GZIP_THRESHOLD_BYTES: usize = 512;
const CONTENT_ENCODING_GZIP: &str = "gzip";
const CONTENT_ENCODING_IDENTITY: &str = "identity";
const CONTENT_TYPE_JSON: &str = "application/json";
const USER_AGENT_ZEROTECT: &str = "zerotect";

#[derive(Debug)]
pub enum PolycorderError {
    IoError(std::io::Error),
    InvalidHeaderValue(reqwest::header::InvalidHeaderValue),
    ReqwestError(reqwest::Error),
    SerdeJson(serde_json::Error),
}
impl error::Error for PolycorderError {}
impl Display for PolycorderError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::IoError(e) => write!(f, "PolycorderError::IoError {}", e),
            Self::InvalidHeaderValue(e) => write!(f, "PolycorderError::InvalidHeaderValue {}", e),
            Self::ReqwestError(e) => write!(f, "PolycorderError::ReqwestError {}", e),
            Self::SerdeJson(e) => write!(f, "PolycorderError::SerdeJsonError {}", e),
        }
    }
}
impl From<std::io::Error> for PolycorderError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}
impl From<reqwest::header::InvalidHeaderValue> for PolycorderError {
    fn from(err: reqwest::header::InvalidHeaderValue) -> Self {
        Self::InvalidHeaderValue(err)
    }
}
impl From<reqwest::Error> for PolycorderError {
    fn from(err: reqwest::Error) -> Self {
        Self::ReqwestError(err)
    }
}
impl From<serde_json::Error> for PolycorderError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerdeJson(err)
    }
}

// The structure to send data to Polycorder in...
#[derive(Serialize)]
struct Report<'l> {
    node_id: &'l str,
    events: &'l Vec<events::Event>,
}

pub async fn emit_forever(
    verbosity: u8,
    config: params::PolycorderConfig,
    source: broadcast::Receiver<events::Event>,
) -> Result<(), emitter::EmitterError> {
    // It helps to keep a localized error implementation without exposing a lot of
    // dependency and interpretation in upper emitter
    Ok(emit_forever_polycorder_error(verbosity, config, source).await?)
}

async fn emit_forever_polycorder_error(
    verbosity: u8,
    config: params::PolycorderConfig,
    mut source: broadcast::Receiver<events::Event>,
) -> Result<(), PolycorderError> {
    let bearer_token = HeaderValue::from_str(format!("Bearer {}", config.auth_key).as_str())?;
    let content_type_json = HeaderValue::from_str(CONTENT_TYPE_JSON)?;

    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, bearer_token);
    headers.insert(CONTENT_TYPE, content_type_json);

    let client = Client::builder()
        .user_agent(USER_AGENT_ZEROTECT)
        .default_headers(headers)
        .build()?;

    let mut events: Vec<events::Event> = vec![];

    let timeout_duration = Duration::from_secs(config.flush_timeout_seconds);

    loop {
        let flush = match timeout(timeout_duration, source.recv()).await {
            Ok(recv_result) => match recv_result {
                Ok(event) => {
                    events.push(event);
                    if events.len() >= config.flush_event_count {
                        true
                    } else {
                        false
                    }
                }
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    eprintln!(
                        "Polycorder is lagging behind generated events. {} events have been dropped.",
                        count
                    );
                    false
                }
                Err(broadcast::error::RecvError::Closed) => {
                    eprintln!("Polycorder event source closed. Exiting.");
                    return Ok(());
                }
            },
            Err(_) => true,
        };

        if flush {
            publish_to_polycorder(verbosity, &config, &client, &events).await?;
            events.clear();
        }
    }
}

async fn publish_to_polycorder(
    verbosity: u8,
    config: &params::PolycorderConfig,
    client: &Client,
    events: &Vec<events::Event>,
) -> Result<(), PolycorderError> {
    let report = Report {
        node_id: config.node_id.as_str(),
        events: &events,
    };

    let json_serialized_report = serde_json::to_vec(&report)?;

    let (body, content_encoding) = encode_payload(json_serialized_report, verbosity);

    let response_result = client
        .post(POLYCORDER_PUBLISH_ENDPOINT)
        .header(CONTENT_ENCODING, content_encoding)
        .body(body)
        .send()
        .await;

    match response_result {
        Ok(response) => {
            let status = response.status();
            // explain common statuses a bit more...
            if verbosity > 0 && status.is_success() && status == StatusCode::OK {
                eprintln!(
                    "Polycorder: Successfully published {} events. Clearing buffer. Response from Polycorder: {:?}",
                    events.len(),
                    response
                );
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
                "Polycorder: Unexpected error when publishing {} events to Polycorder due to an unexpected error. Response from Polycorder: {:?}",
                events.len(),
                response
                );
            }
        }
        Err(e) => eprintln!(
            "Polycorder: Client error making POST request to Polycorder service {}: {}",
            POLYCORDER_PUBLISH_ENDPOINT, e
        ),
    }

    Ok(())
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
