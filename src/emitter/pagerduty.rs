// Copyright (c) 2019 Polyverse Corporation

use crate::emitter;
use crate::events;
use pagerduty_rs::{eventsv2async::*, types::*};
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use time::OffsetDateTime;
use tokio::sync::broadcast;

#[derive(Debug)]
pub enum PagerDutyError {
    EventsV2Error(EventsV2Error),
}
impl error::Error for PagerDutyError {}
impl Display for PagerDutyError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::EventsV2Error(e) => write!(f, "PagerDutyError::EventsV2Error: {}", e),
        }
    }
}
impl From<EventsV2Error> for PagerDutyError {
    fn from(err: EventsV2Error) -> PagerDutyError {
        PagerDutyError::EventsV2Error(err)
    }
}

pub async fn emit_forever(
    routing_key: String,
    source: broadcast::Receiver<events::Event>,
) -> Result<(), emitter::EmitterError> {
    // It helps to keep a localized error implementation without exposing a lot of
    // dependency and interpretation in upper emitter
    Ok(emit_forever_pagerduty_error(routing_key, source).await?)
}

pub async fn emit_forever_pagerduty_error(
    routing_key: String,
    mut source: broadcast::Receiver<events::Event>,
) -> Result<(), PagerDutyError> {
    let eventsv2 = EventsV2::new(routing_key, Some("zerotect".to_owned()))?;

    loop {
        match source.recv().await {
            Ok(event) => {
                if !event.as_ref().is_analyzed() {
                    continue;
                };

                let source = match event.as_ref().get_hostname() {
                    Some(h) => h.to_owned(),
                    None => "unknown".to_owned(),
                };

                let result = eventsv2
                    .event(Event::AlertTrigger(AlertTrigger {
                        payload: AlertTriggerPayload {
                            summary: "Zerotect detected anomaly".to_owned(),
                            source,
                            timestamp: Some(OffsetDateTime::now_utc()),
                            severity: Severity::Warning,
                            component: None,
                            group: None,
                            class: None,
                            custom_details: Some(event.as_ref()),
                        },
                        images: None,
                        links: None,
                        dedup_key: None,
                        client: Some("Zerotect".to_owned()),
                        client_url: Some("https://github.com/polyverse/zerotect".to_owned()),
                    }))
                    .await;

                if let Err(err) = result {
                    eprintln!(
                        "Error when writing event to pager duty. Not retrying. {}",
                        err
                    );
                }
            }
            Err(broadcast::error::RecvError::Lagged(count)) => {
                eprintln!(
                    "PagerDuty is lagging behind generated events. {} events have been dropped.",
                    count
                )
            }
            Err(broadcast::error::RecvError::Closed) => {
                eprintln!("PagerDuty event source closed. Exiting.");
                return Ok(());
            }
        }
    }
}
