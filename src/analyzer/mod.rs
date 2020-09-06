// Copyright (c) 2019 Polyverse Corporation

mod close_by_ip_detect;
mod close_by_register_detect;
mod eventbuffer;

use crate::events;
use crate::params;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use eventbuffer::EventBuffer;
use std::convert::TryInto;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::mem::size_of;
use std::process;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use close_by_ip_detect::close_by_ip_detect;
use close_by_register_detect::close_by_register_detect;

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

    /// how close can the instruction pointer be for it to be an event?
    ip_max_distance: usize,

    /// How detailed a justification do we want?
    justification_kind: params::DetectedEventJustification,

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
            let mut used_events: Vec<events::Event> = vec![];

            for (_, eventslist) in self.event_buffer.iter_mut() {
                // do we have at least 2 events?
                if eventslist.len() <= 1 {
                    continue; // not enough to do anything reasonable
                }

                if let Some((detected_event, mut events_used_for_detection)) =
                    close_by_ip_detect(eventslist, self.ip_max_distance, 1, self.justification_kind)
                {
                    eprintln!("Close_by_ip detected: {}", detected_event);
                    detected_events.push(detected_event);
                    used_events.append(&mut events_used_for_detection)
                }

                if let Some((detected_event, mut events_used_for_detection)) =
                    close_by_register_detect(
                        eventslist,
                        "RDI",
                        1,
                        8,
                        self.justification_kind,
                        "An RDI probe would be an attempt to discover the Stack Canary",
                    )
                {
                    detected_events.push(detected_event);
                    used_events.append(&mut events_used_for_detection)
                }

                if let Some((detected_event, mut events_used_for_detection)) =
                    close_by_register_detect(
                        eventslist,
                        "RSI",
                        1,
                        8,
                        self.justification_kind,
                        "An RSI probe would be an attempt to discover the Stack Canary",
                    )
                {
                    detected_events.push(detected_event);
                    used_events.append(&mut events_used_for_detection)
                }

                if let Some((detected_event, mut events_used_for_detection)) =
                close_by_register_detect(
                    eventslist,
                    "RIP",
                    1,
                    8,
                    self.justification_kind,
                    "An InstructionPointer Probe - someone's systematically moving the instruction pointer by a few bytes to find desirable jump locations.",
                )
            {
                detected_events.push(detected_event);
                used_events.append(&mut events_used_for_detection)
            }

                // retain unused events
                eventslist.retain(|(_, e)| !Analyzer::used(e, &used_events));
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

    fn buffer_event(&mut self, timestamp: DateTime<Utc>, procname: String, event: events::Event) {
        // Append event to to end of buffer
        self.event_buffer.insert(timestamp, procname, event);
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
                        timestamp,
                        event: events::EventType::LinuxKernelTrap(lkt),
                    } => {
                        self.buffer_event(timestamp.clone(), lkt.procname.clone(), event)
                    }
                    events::Version::V1 {
                        timestamp,
                        event: events::EventType::LinuxFatalSignal(lfs),
                    } => match lfs.stack_dump.get("Comm") {
                        // comm is process name
                        Some(comm) => self.buffer_event(timestamp.clone(), comm.clone(), event),
                        // Ignore event without a command
                        None => {}
                    },

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
    let detected_event_sink = passthrough_sink.clone();
    let collection_timeout = Duration::from_secs(config.collection_timeout_seconds);
    let max_event_count = config.max_event_count;
    let event_drop_count = config.event_drop_count;
    let event_lifetime = ChronoDuration::seconds(config.event_lifetime_seconds.try_into()?);
    let justification_kind = config.justification;

    if let Err(e) = thread::Builder::new()
        .name("Realtime Analytics Thread".to_owned())
        .spawn(move || {
            let mut analyzer = Analyzer {
                verbosity,

                collection_timeout,

                // if IP is within usize then someone's jumping within the size of an instruction.
                // segfaults usually don't happen that close to each other.
                ip_max_distance: size_of::<usize>(),

                justification_kind,

                event_source: inner_analyzer_source,
                detected_event_sink,

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
            Ok(event) => match inner_analyzer_sink.send(event.clone()) {
                Err(e) => return Err(AnalyzerError(format!("Analyzer: Error occurred sending events to analyzer. Analytics loop is dead. Closing analyzer. Error: {}", e))),
                Ok(_) => if config.mode == params::AnalyticsMode::Passthrough {
                    match passthrough_sink.send(event) {
                        Err(e) => return Err(AnalyzerError(format!("Analyzer: Error occurred passing through events. Receipent is dead. Closing analyzer. Error: {}", e))),
                        Ok(_) => {},
                    }
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
    use chrono::Utc;
    use rand::Rng;
    use serde_json::{from_str, from_value};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    macro_rules! map(
        { $($key:expr => $value:expr),+ } => {
            {
                let mut m = ::std::collections::BTreeMap::<String, String>::new();
                $(
                    m.insert(String::from($key), String::from($value));
                )+
                m
            }
         };
    );

    #[test]
    fn test_ip_probe_full() {
        let er = run_analytics(
            get_close_ip_events(),
            params::DetectedEventJustification::Full,
            1,
        );

        assert!(
            er.is_ok(),
            "Reception timed out before a detected events was generated"
        );
        let events = er.unwrap();
        let event = events.first().unwrap();
        assert_matches!(event.as_ref(),
            events::Version::V1{
                timestamp: _,
                event: events::EventType::RegisterProbe(events::RegisterProbe{
                    register: _,
                    message: _,
                    justification: events::RegisterProbeJustification::FullEvents(_)
                })
            }
        );

        // get length of events
        match event.as_ref() {
            events::Version::V1 {
                timestamp: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        justification: events::RegisterProbeJustification::FullEvents(full_events),
                    }),
            } => {
                assert_eq!(register, "ip");
                assert_eq!(5, full_events.len());
            }
            _ => panic!("An unexpected event occurred."),
        }
    }

    #[test]
    fn test_ip_probe_summary() {
        let er = run_analytics(
            get_close_ip_events(),
            params::DetectedEventJustification::Summary,
            1,
        );

        assert!(
            er.is_ok(),
            "Reception timed out before a detected events was generated"
        );
        let events = er.unwrap();
        let event = events.first().unwrap();
        assert_matches!(event.as_ref(),
            events::Version::V1{
                timestamp: _,
                event: events::EventType::RegisterProbe(events::RegisterProbe{
                    register: _,
                    message: _,
                    justification: events::RegisterProbeJustification::RegisterValues(_)
                })
            }
        );

        // get length of events
        match event.as_ref() {
            events::Version::V1 {
                timestamp: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        justification: events::RegisterProbeJustification::RegisterValues(values),
                    }),
            } => {
                assert_eq!(register, "ip");
                assert_eq!(5, values.len());
            }
            _ => panic!("An unexpected event occurred."),
        }
    }

    #[test]
    fn test_register_probe_summary() {
        // give it some very close RDI values - increment by 1
        let mut close_rdi_events = Vec::<events::Event>::new();
        for rdi in 0x0000000000000889..0x0000000000000b65 {
            close_rdi_events.push(fatal_with_registers(
                map! {"RDI" => format!("{:016x}", rdi)},
            ));
        }

        let er = run_analytics(
            close_rdi_events,
            params::DetectedEventJustification::Summary,
            1,
        );

        assert!(
            er.is_ok(),
            "Reception timed out before a detected events was generated"
        );
        let events = er.unwrap();
        let event = events.first().unwrap();
        assert_matches!(event.as_ref(),
            events::Version::V1{
                timestamp: _,
                event: events::EventType::RegisterProbe(events::RegisterProbe{
                    register: _,
                    message: _,
                    justification: events::RegisterProbeJustification::RegisterValues(_)
                })
            }
        );

        // get length of events
        match event.as_ref() {
            events::Version::V1 {
                timestamp: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        justification: events::RegisterProbeJustification::RegisterValues(values),
                    }),
            } => {
                assert_eq!(register, "RDI");
                assert_eq!(20, values.len());
            }
            _ => panic!("An unexpected event occurred."),
        }
    }

    #[test]
    fn test_multiple_detections_from_interleaved_raw_events() {
        // give it some very close RDI values - increment by 1
        let mut raw_events = Vec::<events::Event>::new();
        for rdi in 0x0000000000000889..0x0000000000000899 {
            raw_events.push(fatal_with_registers(map! {
                "RDI" => format!("{:016x}", rdi),
                "RSI" => format!("{:016x}", rdi)
            }));
        }

        // interleave some close_ip_events
        interleave(&mut raw_events, get_close_ip_events());

        let er = run_analytics(raw_events, params::DetectedEventJustification::Summary, 3);

        assert!(
            er.is_ok(),
            "Reception timed out before a detected events was generated"
        );

        let events = er.unwrap();
        let mut events_iter = events.iter();

        // Get register for event1
        let register1 = match events_iter.next().unwrap().as_ref() {
            events::Version::V1 {
                timestamp: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        justification: events::RegisterProbeJustification::RegisterValues(_),
                    }),
            } => register,
            _ => panic!("An unexpected event occurred."),
        };
        assert_eq!(register1, "ip");

        // get register for event2
        let register2 = match events_iter.next().unwrap().as_ref() {
            events::Version::V1 {
                timestamp: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        justification: events::RegisterProbeJustification::RegisterValues(_),
                    }),
            } => register,
            _ => panic!("An unexpected event occurred."),
        };
        assert_eq!(register2, "RDI");

        // get register for event2
        let register3 = match events_iter.next().unwrap().as_ref() {
            events::Version::V1 {
                timestamp: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        justification: events::RegisterProbeJustification::RegisterValues(_),
                    }),
            } => register,
            _ => panic!("An unexpected event occurred."),
        };
        assert_eq!(register3, "RSI");
    }

    #[test]
    fn test_register_probe_none() {
        // give it some very close RDI values - increment by 1
        let mut close_rdi_events = Vec::<events::Event>::new();
        for rdi in 0x0000000000000889..0x0000000000000b65 {
            close_rdi_events.push(fatal_with_registers(
                map! {"RSI" => format!("{:016x}", rdi)},
            ));
        }

        let er = run_analytics(
            close_rdi_events,
            params::DetectedEventJustification::None,
            1,
        );

        assert!(
            er.is_ok(),
            "Reception timed out before a detected events was generated"
        );
        let events = er.unwrap();
        let event = events.first().unwrap();
        assert_matches!(event.as_ref(),
            events::Version::V1{
                timestamp: _,
                event: events::EventType::RegisterProbe(events::RegisterProbe{
                    register: _,
                    message: _,
                    justification: events::RegisterProbeJustification::EventCount(_)
                })
            }
        );

        // get length of events
        match event.as_ref() {
            events::Version::V1 {
                timestamp: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        justification: events::RegisterProbeJustification::EventCount(c),
                    }),
            } => {
                assert_eq!(register, "RSI");
                assert_eq!(&20, c);
            }
            _ => panic!("An unexpected event occurred."),
        }
    }

    fn run_analytics(
        events: Vec<events::Event>,
        justification_kind: params::DetectedEventJustification,
        num_detections: usize,
    ) -> Result<Vec<events::Event>, RecvTimeoutError> {
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

                justification_kind,

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

        for event in events {
            assert!(test_events_out.send(event.clone()).is_ok());
        }

        // sleep 3 seconds for analytics to happen
        thread::sleep(Duration::from_secs(3));

        // expect raw_events+1 detected
        let mut detections = vec![];
        for _ in 0..num_detections {
            match detected_events_in.recv_timeout(Duration::from_secs(1)) {
                Ok(e) => detections.push(e),
                Err(e) => return Err(e),
            }
        }

        Ok(detections)
    }

    fn interleave(accumulator: &mut Vec<events::Event>, mut events_to_insert: Vec<events::Event>) {
        // go highest to lowest (so we can interleave)
        events_to_insert.reverse();

        //first generate locations in range
        let mut locations = vec![];
        for _ in 0..events_to_insert.len() {
            // pick a random locations within range
            locations.push(rand::thread_rng().gen_range(0, accumulator.len()));
        }

        // then sort them
        locations.sort();
        // in descending order...
        locations.reverse();

        let mut lociter = locations.into_iter();

        // by inserting them from highest location to back, we insert at the proper
        // locations since all locations higher than insertion point will change/move
        for event_to_insert in events_to_insert.into_iter() {
            accumulator.insert(lociter.next().unwrap(), event_to_insert)
        }
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

    fn fatal_with_registers(map: BTreeMap<String, String>) -> events::Event {
        let mut stack_dump: BTreeMap<String,String> = from_value(
            from_str::<serde_json::Value>(
            r#"{
                "CPU":"0",
                "Code":"00 00 48 63 f0 85 f6 75 31 b8 ba 00 00 00 0f 05 89 c1 64 89 04 25 d0 02 00 00 48 63 f0 48 63 d7 b8 ea 00 00 00 48 63 f9 0f 05 <48> 3d 00 f0 ff ff 77 20 f3 c3 66 0f 1f 44 00 00 85 c9 7f df 89 ca",
                "Comm":"nginx",
                "EFLAGS":"00000206",
                "Hardware name":"BHYVE, BIOS 1.00 03/14/2014",
                "ORIG_RAX":"00000000000000ea",
                "PID":"87631",
                "R08":"737365636f727020",
                "R09":"0000000000000000",
                "R10":"0000000000000008",
                "R11":"0000000000000206",
                "R12":"0000000000000042",
                "R13":"00007ffc91444818",
                "R14":"00007ffc91444818",
                "R15":"0000000000000001",
                "RAX":"0000000000000000",
                "RBP":"00007ffc914449a0",
                "RBX":"0000000000000042",
                "RCX":"00007f883e3ad438",
                "RDI":"0000000000000b66",
                "RDX":"0000000000000006",
                "RIP":"0033:0x7f883e3ad438",
                "RSI":"0000000000000b66",
                "RSP":"002b:00007ffc91444688",
                "Tainted":"G                T 4.19.76-linuxkit #1"
            }"#,
        ).unwrap()).unwrap();

        for (k, v) in map.into_iter() {
            stack_dump.insert(k, v);
        }

        Arc::new(events::Version::V1 {
            timestamp: Utc::now(),
            event: events::EventType::LinuxFatalSignal(events::LinuxFatalSignal {
                level: events::LogLevel::Info,
                facility: events::LogFacility::Kern,
                signal: events::FatalSignalType::SIGIOT,
                stack_dump,
            }),
        })
    }
}
