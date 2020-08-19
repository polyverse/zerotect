// Copyright (c) 2019 Polyverse Corporation

use crate::events;
use crate::params;

use chrono::{Duration as ChronoDuration, Utc};
use std::collections::{HashMap, VecDeque};
use std::convert::TryInto;
use std::error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::ops::Sub;
use std::process;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
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

/// A Hash(procname)->List(events) so we can look for closely-spaced events in the same procname
struct HashList {
    hashlist: HashMap<String, Vec<events::Event>>,
}

impl HashList {
    fn insert(&mut self, event: events::Event) {
        // what do we hash on? For now procname
    }
}

/// A struct with fields/associated functions
/// to perform analysis.
struct Analyzer {
    verbosity: u8,

    collection_timeout: Duration,
    max_event_count: usize,
    event_lifetime: ChronoDuration,
    event_drop_count: usize,

    event_source: Receiver<events::Event>,
    detected_event_sink: Sender<events::Event>,
    events_buffer: VecDeque<events::Event>,

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
        if self.events_buffer.len() == 0 {
            if self.verbosity > 1 {
                eprintln!("Analyzer: Skipping detection since event buffer is empty")
            }
            return;
        }

        // What's the oldest event we allow to exist?
        let oldest_allowed_instant = &Utc::now().sub(self.event_lifetime);

        let mut removal_count: usize = 0;
        for event in &self.events_buffer {
            match event.as_ref() {
                events::Version::V1 {
                    timestamp,
                    event: _,
                } => {
                    // if event expired, mark it for removal
                    if oldest_allowed_instant > timestamp {
                        // remove this event from buffer - since only front-most events (oldest events)
                        // would end up being removed, we remove the 0th element
                        removal_count = removal_count + 1;
                    }
                }
            }
        }

        // if N elements need to be removed (they had expired)
        // drain them
        if removal_count > 0 {
            // mutable borrow to modify
            let buffer: &mut VecDeque<events::Event> = &mut self.events_buffer;
            // now remove `removal_count` number of events from the front
            buffer.drain(0..removal_count);

            if self.verbosity > 1 {
                eprintln!("Analyzer: During detection, {} events had expired past lifetime. Dropped them (after consideration for analytics) and down to {}.", removal_count, self.events_buffer.len())
            }
        }
    }

    fn buffer_event(&mut self, event: events::Event) {
        // Step 1: Append event to to end of buffer
        self.events_buffer.push_back(event);
        self.detected_since_last_add = false;

        // If we're at max events we can store,
        if self.events_buffer.len() >= self.max_event_count {
            // 1. we analyze what we have - see if there's already an event there
            // if an event is detected, the detect function will clear out the buffer.
            self.detect();

            // 2. if the buffer wasn't cleared out (an attack wasn't detected?)
            if self.events_buffer.len() >= self.max_event_count {
                // drop a chunk of older events
                self.events_buffer.drain(0..self.event_drop_count);
                if self.verbosity > 1 {
                    eprintln!("Analyzer: Event buffer was at full capacity of {}. Dropped {} events (after analytics) and down to {}.", self.max_event_count, self.event_drop_count, self.events_buffer.len())
                }
            }
        }
    }

    fn analyze_forever(&mut self) -> Result<(), RecvTimeoutError> {
        loop {
            match self.event_source.recv_timeout(self.collection_timeout) {
                Ok(event) => match event.as_ref() {
                    events::Version::V1 {
                        timestamp: _,
                        event: event_type,
                    } => match event_type {
                        events::EventType::LinuxKernelTrap(_) => self.buffer_event(event),

                        // ignore other event types for detection
                        _ => {}
                    },
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
                max_event_count,
                event_lifetime,
                event_drop_count,

                event_source: inner_analyzer_source,
                detected_event_sink: detected_events_sink,

                // let's not make this reallocate
                events_buffer: VecDeque::with_capacity(config.max_event_count),

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
