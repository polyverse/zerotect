use crate::events;
use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::sync::Arc;

pub fn close_by_ip_detect(
    eventslist: &VecDeque<(DateTime<Utc>, events::Event)>,
    ip_max_distance: usize,
    justification_count: usize,
) -> Option<(events::Event, Vec<events::Event>)> {
    // collect events with close-IPs (Instruction Pointer)
    let mut close_by_ip: Vec<events::Event> = vec![];

    // go over the event list and calculate ip diffs
    // a primitive sliding-window for events
    let mut prev_added: bool = false;
    let mut maybe_prev_event: Option<&events::Event> = None;
    for (_, event) in eventslist.iter() {
        match event.as_ref() {
            events::Version::V1 {
                timestamp: _,
                event: events::EventType::LinuxKernelTrap(lkt),
            } => {
                if let Some(events::Version::V1 {
                    timestamp: _,
                    event: events::EventType::LinuxKernelTrap(prev_lkt),
                }) = maybe_prev_event.map(|x| &(**x))
                {
                    // analytics only works if there is a prevous event
                    let ad = abs_diff(prev_lkt.ip, lkt.ip);

                    // we have winner events
                    // ignore when IP is identical across events - it may just be a legit crash.
                    if ad != 0 && ad <= ip_max_distance {
                        if !prev_added {
                            // if close_by_ip is empty, add the previous event too
                            // we can unwrap safely - we're already inside a destructure of it
                            close_by_ip.push(maybe_prev_event.unwrap().clone())
                        }
                        prev_added = true;
                        close_by_ip.push(event.clone());
                    } else {
                        prev_added = false;
                    }
                }

                // Make current event the previous event
                maybe_prev_event = Some(event);
            }

            // ignore everything else
            _ => {}
        }
    }

    // if we found a sufficient number of close_by_ip events (i.e. 2 or more), we detect an event
    if close_by_ip.len() > justification_count {
        return Some((
            Arc::new(events::Version::V1 {
                timestamp: Utc::now(),
                event: events::EventType::InstructionPointerProbe(
                    events::InstructionPointerProbe {
                        justifying_events: close_by_ip.clone(),
                    },
                ),
            }),
            close_by_ip,
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
