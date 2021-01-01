// Copyright (c) 2019 Polyverse Corporation

mod close_by_ip_detect;
mod close_by_register_detect;
mod eventbuffer;

use crate::events;
use crate::params;

use eventbuffer::EventBuffer;
use futures::stream;
use futures::Stream;
use std::collections::VecDeque;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::mem::size_of;
use std::time::Duration;
use time::OffsetDateTime;
use timeout_iterator::asynchronous::TimeoutStream;

use close_by_ip_detect::close_by_ip_detect;
use close_by_register_detect::close_by_register_detect;

pub async fn new(
    verbosity: u8,
    config: params::AnalyticsConfig,
    raw_incoming_stream: impl Stream<Item = events::Event> + Unpin,
) -> Result<impl Stream<Item = events::Event>, AnalyzerError> {
    eprintln!("Analyzer: Initializing...");
    let event_buffer = EventBuffer::new(
        verbosity,
        config.max_event_count,
        config.event_drop_count,
        Duration::from_secs(config.event_lifetime_seconds),
    );

    let analyzer = Analyzer {
        verbosity,
        mode: config.mode,
        incoming_events_stream: TimeoutStream::with_stream(raw_incoming_stream).await?,
        collection_timeout: Duration::from_secs(config.collection_timeout_seconds),
        // if IP is within usize then someone's jumping within the size of an instruction.
        // segfaults usually don't happen that close to each other.
        ip_max_distance: size_of::<usize>(),
        justification_kind: config.justification,
        // let's not make this reallocate
        event_buffer,
        detected_since_last_add: true,
        detected_events_buffer: VecDeque::new(),
    };

    let s = stream::unfold(analyzer, |mut analyzer| async move {
        match analyzer.next_event().await {
            Some(next_event) => Some((next_event, analyzer)),
            None => None,
        }
    });

    Ok(s)
}

#[derive(Debug)]
pub struct AnalyzerError(String);
impl error::Error for AnalyzerError {}
impl Display for AnalyzerError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "AnalyzerError: {}", self.0)
    }
}
impl From<std::num::TryFromIntError> for AnalyzerError {
    fn from(tryerr: std::num::TryFromIntError) -> Self {
        Self(format!("AnalyzerError::TryFromIntError: Error converting between integers. Probably a bounds/fit violation: {}", tryerr))
    }
}
impl From<timeout_iterator::error::Error> for AnalyzerError {
    fn from(timeouterr: timeout_iterator::error::Error) -> Self {
        Self(format!(
            "AnalyzerError::TimeoutIterator::Error: Error from the TimeoutIterator: {}",
            timeouterr
        ))
    }
}

/// A struct with fields/associated functions
/// to perform analysis.
struct Analyzer<I>
where
    I: Stream<Item = events::Event> + Unpin,
{
    verbosity: u8,
    incoming_events_stream: TimeoutStream<events::Event, I>,
    mode: params::AnalyticsMode,
    collection_timeout: Duration,
    /// how close can the instruction pointer be for it to be an event?
    ip_max_distance: usize,
    /// How detailed a justification do we want?
    justification_kind: params::DetectedEventJustification,
    event_buffer: EventBuffer,
    detected_since_last_add: bool,
    detected_events_buffer: VecDeque<events::Event>,
}

/// Implements a Collection (backed bu an inner buffer), but
/// use those wrapper methods because they can do some useful things.
impl<I> Analyzer<I>
where
    I: Stream<Item = events::Event> + Unpin,
{
    async fn next_event(&mut self) -> Option<events::Event> {
        loop {
            if let Some(detected_event) = self.detected_events_buffer.pop_front() {
                return Some(detected_event);
            }

            match self
                .incoming_events_stream
                .next_timeout(self.collection_timeout)
                .await
            {
                Ok(event) => {
                    match event.as_ref() {
                        events::Version::V1 {
                            timestamp,
                            hostname: _,
                            event: events::EventType::LinuxKernelTrap(lkt),
                        } => self.buffer_incoming_event(
                            *timestamp,
                            lkt.procname.clone(),
                            event.clone(),
                        ),
                        events::Version::V1 {
                            timestamp,
                            hostname: _,
                            event: events::EventType::LinuxFatalSignal(lfs),
                        } => {
                            if let Some(comm) = lfs.stack_dump.get("Comm") {
                                // comm is process name
                                self.buffer_incoming_event(*timestamp, comm.clone(), event.clone())
                            }
                        }

                        // ignore other event types for detection
                        _ => {}
                    }

                    // if passthrough, send the event out...
                    if let params::AnalyticsMode::Passthrough = self.mode {
                        return Some(event);
                    }
                }
                Err(timeout_iterator::error::Error::TimedOut) => {
                    self.detect();
                }
                Err(timeout_iterator::error::Error::Disconnected) => {
                    eprintln!(
                        "Analyzer: Analysis channel disconnected. Aborting the analyzer thread."
                    );
                    return None;
                }
            }
        }
    }

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

            for (procname, eventslist) in self.event_buffer.iter_mut() {
                // do we have at least 2 events?
                if eventslist.len() <= 1 {
                    continue; // not enough to do anything reasonable
                }

                if let Some((detected_event, mut events_used_for_detection)) = close_by_ip_detect(
                    procname,
                    eventslist,
                    self.ip_max_distance,
                    1,
                    self.justification_kind,
                ) {
                    detected_events.push(detected_event);
                    used_events.append(&mut events_used_for_detection)
                }

                if let Some((detected_event, mut events_used_for_detection)) =
                    close_by_register_detect(
                        procname,
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
                        procname,
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
                    procname,
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
                eventslist.retain(|(_, e)| !used_events.contains(e));
            }

            // send all detected events
            for detected_event in detected_events.into_iter() {
                self.detected_events_buffer.push_back(detected_event);
            }
        }

        self.event_buffer.cleanup();
    }

    fn buffer_incoming_event(
        &mut self,
        timestamp: OffsetDateTime,
        procname: String,
        event: events::Event,
    ) {
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
}

#[cfg(test)]
mod test {
    use super::*;
    use futures::stream::iter;
    use serde_json::{from_str, from_value};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tokio_stream::StreamExt;

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

    #[tokio::test]
    async fn test_ip_probe_full() {
        let mut events = run_analytics(
            iter(get_close_ip_events()),
            params::DetectedEventJustification::Full,
        )
        .await;

        let event = events.next().await.unwrap();
        assert_matches!(event.as_ref(),
            events::Version::V1{
                timestamp: _,
                hostname: _,
                event: events::EventType::RegisterProbe(events::RegisterProbe{
                    register: _,
                    message: _,
                    procname: _,
                    justification: events::RegisterProbeJustification::FullEvents(_)
                })
            }
        );

        // get length of events
        match event.as_ref() {
            events::Version::V1 {
                timestamp: _,
                hostname: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        procname,
                        justification: events::RegisterProbeJustification::FullEvents(full_events),
                    }),
            } => {
                assert_eq!(register, "ip");
                assert_eq!(5, full_events.len());
                assert_eq!(procname, "nginx");
            }
            _ => panic!("An unexpected event occurred."),
        }
    }

    #[tokio::test]
    async fn test_ip_probe_summary() {
        let mut events = run_analytics(
            iter(get_close_ip_events()),
            params::DetectedEventJustification::Summary,
        )
        .await;

        let event = events.next().await.unwrap();
        assert_matches!(event.as_ref(),
            events::Version::V1{
                timestamp: _,
                hostname: _,
                event: events::EventType::RegisterProbe(events::RegisterProbe{
                    register: _,
                    message: _,
                    procname: _,
                    justification: events::RegisterProbeJustification::RegisterValues(_)
                })
            }
        );

        // get length of events
        match event.as_ref() {
            events::Version::V1 {
                timestamp: _,
                hostname: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        procname,
                        justification: events::RegisterProbeJustification::RegisterValues(values),
                    }),
            } => {
                assert_eq!(register, "ip");
                assert_eq!(5, values.len());
                assert_eq!(procname, "nginx");
            }
            _ => panic!("An unexpected event occurred."),
        }
    }

    #[tokio::test]
    async fn test_register_probe_summary() {
        // give it some very close RDI values - increment by 1
        let mut close_rdi_events = Vec::<events::Event>::new();
        for rdi in 0x0000000000000889..0x0000000000000b65 {
            close_rdi_events.push(fatal_with_registers(
                map! {"RDI" => format!("{:016x}", rdi)},
            ));
        }

        let mut events = run_analytics(
            iter(close_rdi_events),
            params::DetectedEventJustification::Summary,
        )
        .await;

        let event = events.next().await.unwrap();
        assert_matches!(event.as_ref(),
            events::Version::V1{
                timestamp: _,
                hostname: _,
                event: events::EventType::RegisterProbe(events::RegisterProbe{
                    register: _,
                    message: _,
                    procname: _,
                    justification: events::RegisterProbeJustification::RegisterValues(_)
                })
            }
        );

        // get length of events
        match event.as_ref() {
            events::Version::V1 {
                timestamp: _,
                hostname: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        procname,
                        justification: events::RegisterProbeJustification::RegisterValues(values),
                    }),
            } => {
                assert_eq!(register, "RDI");
                assert_eq!(20, values.len());
                assert_eq!(procname, "nginx");
            }
            _ => panic!("An unexpected event occurred."),
        }
    }

    #[tokio::test]
    async fn test_multiple_detections_from_interleaved_raw_events() {
        // give it some very close RDI values - increment by 1
        let mut raw_events = Vec::<events::Event>::new();
        for rdi in 0x0000000000000889..0x0000000000000899 {
            raw_events.push(fatal_with_registers(map! {
                "RDI" => format!("{:016x}", rdi),
                "RSI" => format!("{:016x}", rdi)
            }));
        }

        // interleave some close_ip_events
        let interleaved_streams = iter(raw_events).merge(iter(get_close_ip_events()));

        let mut events = run_analytics(
            interleaved_streams,
            params::DetectedEventJustification::Summary,
        )
        .await;

        // Get register for event1
        let event1 = events.next().await.unwrap();
        let register1 = match event1.as_ref() {
            events::Version::V1 {
                timestamp: _,
                hostname: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        procname: _,
                        justification: events::RegisterProbeJustification::RegisterValues(_),
                    }),
            } => register,
            _ => panic!("An unexpected event occurred."),
        };
        assert_eq!(register1, "ip");

        // get register for event2
        let event2 = events.next().await.unwrap();
        let register2 = match event2.as_ref() {
            events::Version::V1 {
                timestamp: _,
                hostname: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        procname: _,
                        justification: events::RegisterProbeJustification::RegisterValues(_),
                    }),
            } => register,
            _ => panic!("An unexpected event occurred."),
        };
        assert_eq!(register2, "RDI");

        // get register for event3
        let event3 = events.next().await.unwrap();
        let register3 = match event3.as_ref() {
            events::Version::V1 {
                timestamp: _,
                hostname: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        procname: _,
                        justification: events::RegisterProbeJustification::RegisterValues(_),
                    }),
            } => register,
            _ => panic!("An unexpected event occurred."),
        };
        assert_eq!(register3, "RSI");
    }

    #[tokio::test]
    async fn test_register_probe_none() {
        // give it some very close RDI values - increment by 1
        let mut close_rdi_events = Vec::<events::Event>::new();
        for rdi in 0x0000000000000889..0x0000000000000b65 {
            close_rdi_events.push(fatal_with_registers(
                map! {"RSI" => format!("{:016x}", rdi)},
            ));
        }

        let mut events = run_analytics(
            iter(close_rdi_events),
            params::DetectedEventJustification::None,
        )
        .await;

        let event = events.next().await.unwrap();
        assert_matches!(event.as_ref(),
            events::Version::V1{
                timestamp: _,
                hostname: _,
                event: events::EventType::RegisterProbe(events::RegisterProbe{
                    register: _,
                    message: _,
                    procname: _,
                    justification: events::RegisterProbeJustification::EventCount(_)
                })
            }
        );

        // get length of events
        match event.as_ref() {
            events::Version::V1 {
                timestamp: _,
                hostname: _,
                event:
                    events::EventType::RegisterProbe(events::RegisterProbe {
                        register,
                        message: _,
                        procname,
                        justification: events::RegisterProbeJustification::EventCount(c),
                    }),
            } => {
                assert_eq!(register, "RSI");
                assert_eq!(&20, c);
                assert_eq!(procname, "nginx");
            }
            _ => panic!("An unexpected event occurred."),
        }
    }

    async fn run_analytics(
        events: impl Stream<Item = events::Event> + Unpin,
        justification_kind: params::DetectedEventJustification,
    ) -> impl Stream<Item = events::Event> + Unpin {
        Box::pin(
            new(
                0,
                params::AnalyticsConfig {
                    mode: params::AnalyticsMode::Detected,
                    justification: justification_kind,
                    collection_timeout_seconds: 2,
                    max_event_count: 20,
                    event_drop_count: 5,
                    event_lifetime_seconds: 5,
                },
                events,
            )
            .await
            .unwrap(),
        )
    }

    fn get_close_ip_events() -> Vec<events::Event> {
        vec![
            Arc::new(
                from_value(
                    from_str::<serde_json::Value>(
                        r#"{
                    "version":"V1",
                    "timestamp":"2020-08-31T16:21:34.078978600Z",
                    "hostname":"nonexistent",
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
                    "hostname":"nonexistent",
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
                        "hostname":"nonexistent",
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
                        "hostname":"nonexistent",
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
                        "hostname":"nonexistent",
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
            timestamp: OffsetDateTime::now_utc(),
            hostname: Some("nonexistent".to_owned()),
            event: events::EventType::LinuxFatalSignal(events::LinuxFatalSignal {
                level: rmesg::entry::LogLevel::Info,
                facility: rmesg::entry::LogFacility::Kern,
                signal: events::FatalSignalType::SIGIOT,
                stack_dump,
            }),
        })
    }
}
