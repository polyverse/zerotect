// Copyright (c) 2019 Polyverse Corporation

mod eventbuffer;

use crate::events;
use crate::params;

use chrono::{Duration as ChronoDuration, Utc};
use eventbuffer::EventBuffer;
use std::convert::TryInto;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::mem::size_of;
use std::process;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub struct AnalyzerError(String);
impl error::Error for AnalyzerError {}
impl Display for AnalyzerError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "AnalyzerError: {}", self.0)
    }
}
impl From<std::num::TryFromIntError> for AnalyzerError {
    fn from(tryerr: std::num::TryFromIntError) -> AnalyzerError {
        AnalyzerError(format!("AnalyzerError::TryFromIntError: Error converting between integers. Probably a bounds/fit violation: {}", tryerr))
    }
}

/// A struct with fields/associated functions
/// to perform analysis.
struct Analyzer {
    verbosity: u8,

    collection_timeout: Duration,

    // how close can the instruction pointer be for it to be an event?
    ip_max_distance: usize,

    event_source: Receiver<events::Event>,
    detected_event_sink: Sender<events::Event>,
    event_buffer: EventBuffer,

    detected_since_last_add: bool,
}

/// Implements a Collection (backed bu an inner buffer), but
/// use those wrapper methods because they can do some useful things.
impl Analyzer {
    /// Runs a detection on currently buffered events
    /// If successful, generates a confirmed detection event
    /// and sends it to the emitter channel. It also clears the buffer
    /// as the buffer is now considered used up
    ///
    /// Also cleans up expired events (older than allowed lifetime)
    ///
    fn detect(&mut self) {
        if self.verbosity > 0 {
            eprintln!("Analyzer: Running detection on buffered events")
        }

        // exit on the most trivial case
        if self.event_buffer.len() == 0 {
            if self.verbosity > 1 {
                eprintln!("Analyzer: Skipping detection since event buffer is empty")
            }
            return;
        }

        // if not analyzed since last event add,
        if !self.detected_since_last_add {
            self.detected_since_last_add = true;

            // store events here to send after all detection is complete
            // this avoids mutabling borrowing self twice in one block
            let mut detected_events: Vec<events::Event> = vec![];

            for (_, eventslist) in self.event_buffer.iter_mut() {
                // do we have at least 2 events?
                if eventslist.len() <= 1 {
                    continue; // not enough to do anything reasonable
                }

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
                                let ad = Analyzer::abs_diff(prev_lkt.ip, lkt.ip);

                                // we have winner events
                                // ignore when IP is identical across events - it may just be a legit crash.
                                if ad != 0 && ad <= self.ip_max_distance {
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

                // retain unused events
                eventslist.retain(|(_, e)| !Analyzer::used(e, &close_by_ip));

                // if we found a sufficient number of close_by_ip events (i.e. 2 or more), we detect an event
                if close_by_ip.len() > 1 {
                    detected_events.push(Arc::new(events::Version::V1 {
                        timestamp: Utc::now(),
                        event: events::EventType::InstructionPointerProbe(
                            events::InstructionPointerProbe {
                                justifying_events: close_by_ip,
                            },
                        ),
                    }));
                }
            }

            // send all detected events
            for detected_event in detected_events.into_iter() {
                self.send_event(detected_event);
            }
        }

        self.event_buffer.cleanup();
    }

    fn send_event(&mut self, event: events::Event) {
        // send this event
        match self.detected_event_sink.send(event) {
            Err(e) => eprintln!(
                "Analyzer: Detector unable to send detection event to output channel: {}",
                e
            ),
            _ => {}
        }
    }

    fn buffer_event(&mut self, event: events::Event) {
        // Append event to to end of buffer
        self.event_buffer.insert(event);
        self.detected_since_last_add = false;

        // If we're at max events we can store,
        if self.event_buffer.is_full() {
            // we analyze what we have - see if there's already an event there
            // Detect will cleanup events.
            self.detect();
        }
    }

    fn analyze_forever(&mut self) -> Result<(), RecvTimeoutError> {
        loop {
            match self.event_source.recv_timeout(self.collection_timeout) {
                Ok(event) => match event.as_ref() {
                    events::Version::V1 {
                        timestamp: _,
                        event: events::EventType::LinuxKernelTrap(_),
                    } => self.buffer_event(event),

                    // ignore other event types for detection
                    _ => {}
                },
                Err(RecvTimeoutError::Timeout) => {
                    self.detect();
                }
                Err(RecvTimeoutError::Disconnected) => {
                    eprintln!(
                        "Analyzer: Analysis channel disconnected. Aborting the analyzer thread."
                    );
                    return Err(RecvTimeoutError::Disconnected);
                }
            }
        }
    }

    // This will go away after this: https://github.com/rust-lang/rust/issues/62111
    fn abs_diff(u1: usize, u2: usize) -> usize {
        if u1 > u2 {
            u1 - u2
        } else {
            u2 - u1
        }
    }

    fn used(e: &events::Event, used_events: &Vec<events::Event>) -> bool {
        for used_event in used_events {
            if e == used_event {
                return true;
            }
        }

        false
    }
}

pub fn analyze(
    verbosity: u8,
    config: params::AnalyticsConfig,
    source: Receiver<events::Event>,
    passthrough_sink: Sender<events::Event>,
) -> Result<(), AnalyzerError> {
    eprintln!("Analyzer: Initializing...");

    if config.max_event_count <= 1 {
        return Err(AnalyzerError(format!("Analyzer's 'max_event_count'({}) must be at least 2. If we cannot store at least 2 events, we cannot detect even the simplest attack. You should turn off analytics altogether. Aboring Analyzer due to misconfiguration.", config.max_event_count)));
    }
    if config.event_drop_count <= 0 {
        return Err(AnalyzerError(format!("Analyzer's 'event_drop_count'({}) must be at least 1. If we cannot drop at least 1 event when the buffer is full, we cannot add new events. Aboring Analyzer due to misconfiguration.", config.event_drop_count)));
    }
    if config.max_event_count < config.event_drop_count {
        return Err(AnalyzerError(format!("Analyzer's 'max_event_count'({}) is less than 'event_drop_count'({}). Cannot drop more events at cleanup, than number of events we store. Aboring Analyzer due to misconfiguration.", config.max_event_count, config.event_drop_count)));
    }

    let (inner_analyzer_sink, inner_analyzer_source): (
        Sender<events::Event>,
        Receiver<events::Event>,
    ) = channel();

    // fork off the analytics thread
    let detected_events_sink = passthrough_sink.clone();
    let collection_timeout = Duration::from_secs(config.collection_timeout_seconds);
    let max_event_count = config.max_event_count;
    let event_drop_count = config.event_drop_count;
    let event_lifetime = ChronoDuration::seconds(config.event_lifetime_seconds.try_into()?);

    if let Err(e) = thread::Builder::new()
        .name("Realtime Analytics Thread".to_owned())
        .spawn(move || {
            let mut analyzer = Analyzer {
                verbosity,

                collection_timeout,

                // if IP is within usize then someone's jumping within the size of an instruction.
                // segfaults usually don't happen that close to each other.
                ip_max_distance: size_of::<usize>(),

                event_source: inner_analyzer_source,
                detected_event_sink: detected_events_sink,

                // let's not make this reallocate
                event_buffer: EventBuffer::new(
                    verbosity,
                    max_event_count,
                    event_drop_count,
                    event_lifetime,
                ),

                detected_since_last_add: true,
            };
            if let Err(_) = analyzer.analyze_forever() {
                eprintln!("Analyzer: Background analysis thread exited. Aborting program.");
                process::exit(1)
            }
        })
    {
        eprintln!(
            "An error occurred spawning the realtime analytics thread: {}",
            e
        );
        process::exit(1);
    }

    loop {
        match source.recv() {
            Ok(event) => match passthrough_sink.send(event.clone()) {
                Err(e) => return Err(AnalyzerError(format!("Analyzer: Error occurred passing through events. Receipent is dead. Closing analyzer. Error: {}", e))),
                Ok(_) => match inner_analyzer_sink.send(event) {
                    Err(e) => return Err(AnalyzerError(format!("Analyzer: Error occurred sending events to analyzer. Analytics loop is dead. Closing analyzer. Error: {}", e))),
                    Ok(_) => {},
                },
            },
            Err(e) => {
                return Err(AnalyzerError(format!("Analyzer: Received an error from messages channel. No more possibility of messages coming in. Closing thread. Error: {}", e)));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::{from_str, from_value};
    use std::time::Duration;

    #[test]
    fn test_ip_probe() {
        let (test_events_out, analyzer_in): (Sender<events::Event>, Receiver<events::Event>) =
            channel();

        let (analyzer_out, detected_events_in): (Sender<events::Event>, Receiver<events::Event>) =
            channel();

        thread::spawn(move || {
            let mut analyzer = Analyzer {
                verbosity: 0,

                // analyze after 2 seconds of no events
                collection_timeout: Duration::from_secs(2),

                // if IP is within usize then someone's jumping within the size of an instruction.
                // segfaults usually don't happen that close to each other.
                ip_max_distance: size_of::<usize>(),

                event_source: analyzer_in,
                detected_event_sink: analyzer_out,

                // let's not make this reallocate
                event_buffer: EventBuffer::new(
                    0,
                    20,
                    5,
                    ChronoDuration::from_std(Duration::from_secs(5)).unwrap(),
                ),

                detected_since_last_add: true,
            };

            // ignore result
            match analyzer.analyze_forever() {
                _ => {}
            }
        });

        let raw_events = get_close_ip_events();
        for event in raw_events.iter() {
            assert!(test_events_out.send(event.clone()).is_ok());
        }

        // sleep 3 seconds for analytics to happen
        thread::sleep(Duration::from_secs(3));

        // expect raw_events+1 detected
        let er = detected_events_in.recv_timeout(Duration::from_secs(1));
        assert!(
            er.is_ok(),
            "Reception timed out before a detected events was generated"
        );
        assert_matches!(er.unwrap().as_ref(), events::Version::V1{timestamp: _, event: events::EventType::InstructionPointerProbe(_)});
    }

    fn get_close_ip_events() -> Vec<events::Event> {
        vec![
            Arc::new(
                from_value(
                    from_str::<serde_json::Value>(
                        r#"{
                    "version":"V1",
                    "timestamp":"2020-08-31T16:21:34.078978600Z",
                    "event":{
                        "type":"LinuxKernelTrap",
                        "level":"Info",
                        "facility":"Kern",
                        "trap":{
                            "type":"InvalidOpcode"
                        },
                        "procname":"nginx",
                        "pid":38653,
                        "ip":4392210,
                        "sp":140732453045232,
                        "errcode":{
                            "reason":"NoPageFound",
                            "access_type":"Read",
                            "access_mode":"Kernel",
                            "use_of_reserved_bit":false,
                            "instruction_fetch":false,
                            "protection_keys_block_access":false
                        },
                        "file":"nginx",
                        "vmastart":4194304,
                        "vmasize":774144
                    }
                }"#,
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            Arc::new(
                from_value(
                    from_str::<serde_json::Value>(
                        r#"{
                    "version":"V1",
                    "timestamp":"2020-08-31T16:21:34.100803600Z",
                    "event":{
                        "type":"LinuxKernelTrap",
                        "level":"Info",
                        "facility":"Kern",
                        "trap":{
                            "type":"Segfault",
                            "location":18446744073709551614
                        },
                        "procname":"nginx",
                        "pid":38656,
                        "ip":4392218,
                        "sp":140732453045232,
                        "errcode":{
                            "reason":"ProtectionFault",
                            "access_type":"Write",
                            "access_mode":"User",
                            "use_of_reserved_bit":false,
                            "instruction_fetch":false,
                            "protection_keys_block_access":false
                        },
                        "file":"nginx",
                        "vmastart":4194304,
                        "vmasize":774144
                    }
            }"#,
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            Arc::new(
                from_value(
                    from_str::<serde_json::Value>(
                        r#"{
                        "version":"V1",
                        "timestamp":"2020-08-31T16:21:34.122534600Z",
                        "event":{
                            "type":"LinuxKernelTrap",
                            "level":"Info",
                            "facility":"Kern",
                            "trap":{
                                "type":"InvalidOpcode"
                            },
                            "procname":"nginx",
                            "pid":38659,
                            "ip":4392224,
                            "sp":140732453045232,
                            "errcode":{
                                "reason":"NoPageFound",
                                "access_type":"Read",
                                "access_mode":"Kernel",
                                "use_of_reserved_bit":false,
                                "instruction_fetch":false,
                                "protection_keys_block_access":false
                            },
                            "file":"nginx",
                            "vmastart":4194304,
                            "vmasize":774144
                        }
                }"#,
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            Arc::new(
                from_value(
                    from_str::<serde_json::Value>(
                        r#"{
                        "version":"V1",
                        "timestamp":"2020-08-31T16:21:34.144860600Z",
                        "event":{
                            "type":"LinuxKernelTrap",
                            "level":"Info",
                            "facility":"Kern",
                            "trap":{
                                "type":"Segfault",
                                "location":18446744073709551614
                            },
                            "procname":"nginx",
                            "pid":38662,
                            "ip":4392234,
                            "sp":140732453045232,
                            "errcode":{
                                "reason":"ProtectionFault",
                                "access_type":"Write",
                                "access_mode":"User",
                                "use_of_reserved_bit":false,
                                "instruction_fetch":false,
                                "protection_keys_block_access":false
                            },
                            "file":"nginx",
                            "vmastart":4194304,
                            "vmasize":774144
                        }
                }"#,
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            Arc::new(
                from_value(
                    from_str::<serde_json::Value>(
                        r#"{
                        "version":"V1",
                        "timestamp":"2020-08-31T16:21:34.166785600Z",
                        "event":{
                            "type":"LinuxKernelTrap",
                            "level":"Info","facility":"Kern",
                            "trap":{
                                "type":"Segfault",
                                "location":4518893
                            },
                            "procname":"nginx",
                            "pid":38665,
                            "ip":4392240,
                            "sp":140732453045232,
                            "errcode":{
                                "reason":"ProtectionFault",
                                "access_type":"Write",
                                "access_mode":"User",
                                "use_of_reserved_bit":false,
                                "instruction_fetch":false,
                                "protection_keys_block_access":false
                            },
                            "file":"nginx",
                            "vmastart":4194304,
                            "vmasize":774144
                        }
                }"#,
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
        ]
    }
}
