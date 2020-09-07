use crate::common;
use crate::events;
use crate::params;

use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::sync::Arc;

pub fn close_by_register_detect(
    eventslist: &VecDeque<(DateTime<Utc>, events::Event)>,
    register: &str,
    register_max_distance: usize,
    justification_threshold: usize,
    justification_kind: params::DetectedEventJustification,
    message: &str,
) -> Option<(events::Event, Vec<events::Event>)> {
    // collect events with close-IPs (Instruction Pointer)
    let mut close_by_register: Vec<events::Event> = vec![];

    // go over the event list and calculate ip diffs
    // a primitive sliding-window for events
    let mut prev_added: bool = false;
    let mut maybe_prev_event: Option<&events::Event> = None;
    for (_, event) in eventslist.iter() {
        if let events::Version::V1 {
            timestamp: _,
            event: events::EventType::LinuxFatalSignal(lfs),
        } = event.as_ref()
        {
            if let Some(events::Version::V1 {
                timestamp: _,
                event: events::EventType::LinuxFatalSignal(prev_lfs),
            }) = maybe_prev_event.map(|x| &(**x))
            {
                if let (Some(prev_register_val), Some(register_val)) = (
                    prev_lfs
                        .stack_dump
                        .get(register)
                        .map(|v| common::parse_hex_usize(v))
                        .flatten(),
                    lfs.stack_dump
                        .get(register)
                        .map(|v| common::parse_hex_usize(v))
                        .flatten(),
                ) {
                    // analytics only works if there is a prevous event
                    let ad = abs_diff(prev_register_val, register_val);

                    // we have winner events
                    // ignore when IP is identical across events - it may just be a legit crash.
                    if ad != 0 && ad <= register_max_distance {
                        if !prev_added {
                            // if close_by_ip is empty, add the previous event too
                            // we can unwrap safely - we're already inside a destructure of it
                            close_by_register.push(maybe_prev_event.unwrap().clone())
                        }
                        prev_added = true;
                        close_by_register.push(event.clone());
                    } else {
                        prev_added = false;
                    }
                }
            }

            // Make current event the previous event
            maybe_prev_event = Some(event);
        }
    }

    // if we found a sufficient number of close_by_ip events (i.e. 2 or more), we detect an event
    if close_by_register.len() > justification_threshold {
        return Some((
            Arc::new(events::Version::V1 {
                timestamp: Utc::now(),
                event: events::EventType::RegisterProbe(events::RegisterProbe {
                    register: register.to_owned(),
                    message: message.to_owned(),
                    justification: justify(close_by_register.clone(), register, justification_kind),
                }),
            }),
            close_by_register,
        ));
    }

    None
}

// This will go away after this: https://github.com/rust-lang/rust/issues/62111
fn abs_diff(u1: usize, u2: usize) -> usize {
    if u1 > u2 {
        u1 - u2
    } else {
        u2 - u1
    }
}

fn justify(
    justifying_events: Vec<events::Event>,
    register: &str,
    justification_kind: params::DetectedEventJustification,
) -> events::RegisterProbeJustification {
    match justification_kind {
        params::DetectedEventJustification::Full => events::RegisterProbeJustification::FullEvents(
            justifying_events,
        ),
        params::DetectedEventJustification::Summary => events::RegisterProbeJustification::RegisterValues(
            justifying_events.iter().filter_map(|e| {
                match e.as_ref() {
                    events::Version::V1 {
                        timestamp: _,
                        event: events::EventType::LinuxFatalSignal(lfs),
                    } => lfs.stack_dump.get(register).cloned(),

                    _ => {
                        eprintln!("Analyzer:: close_by_register_detect::justify: Unsupported event found when summarizing: {}", e);
                        None
                    },
                }
            }).collect(),
        ),
        params::DetectedEventJustification::None => events::RegisterProbeJustification::EventCount(justifying_events.len()),
    }
}
