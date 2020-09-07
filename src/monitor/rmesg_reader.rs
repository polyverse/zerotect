// Copyright (c) 2019 Polyverse Corporation

use crate::common;
use crate::events;
use crate::monitor::kmsg::{KMsg, KMsgParserError, KMsgParsingError, KMsgPtr};
use crate::system;
use num::FromPrimitive;
use timeout_iterator::TimeoutIterator;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use regex::Regex;
use rmesg::{kernel_log_timestamps_enabled, RMesgLinesIterator};
use std::ops::Add;
use std::time::Duration;

type RMesgResult = std::result::Result<std::string::String, rmesg::error::RMesgError>;
type LinesIterator = Box<dyn Iterator<Item = RMesgResult> + Send>;

#[derive(Clone)]
pub struct RMesgReaderConfig {
    pub poll_interval: Duration,
    pub gobble_old_events: bool,
}

pub struct RMesgReader {
    _verbosity: u8,
    rmesg_line_reader: TimeoutIterator<RMesgResult>,
    system_start_time: DateTime<Utc>,

    // only read events from this time on
    event_stream_start_time: DateTime<Utc>,
}

impl RMesgReader {
    pub fn with_config(
        config: RMesgReaderConfig,
        verbosity: u8,
    ) -> Result<RMesgReader, KMsgParserError> {
        // ensure timestamps in logs
        if !kernel_log_timestamps_enabled()? {
            eprintln!("WARNING: Timestamps are disabled but tailing/following logs (as for detection) requires them.");
            eprintln!("Events may be ignored or missed until they are enabled.");
            eprintln!("You can enable timestamps by running the following: ");
            eprintln!("  echo Y > /sys/module/printk/parameters/time");
            eprintln!("Or you may tell zerotect to auto-configure the flag on the command-line or config file.");
        }

        let system_start_time = system::system_start_time()?;

        let event_stream_start_time = match config.gobble_old_events {
            true => system_start_time,
            false => Utc::now(),
        };

        let rmesg_reader = Box::new(RMesgLinesIterator::with_options(
            false,
            config.poll_interval,
        )?);
        RMesgReader::with_lines_iterator(
            rmesg_reader,
            system_start_time,
            event_stream_start_time,
            verbosity,
        )
    }

    fn with_lines_iterator(
        reader: LinesIterator,
        system_start_time: DateTime<Utc>,
        event_stream_start_time: DateTime<Utc>,
        verbosity: u8,
    ) -> Result<RMesgReader, KMsgParserError> {
        let mut rmesg_line_reader = TimeoutIterator::from_item_iterator(reader)?;
        match rmesg_line_reader.peek() {
            None => {
                return Err(KMsgParserError::BadSource(
                    "Couldn't peek a single line from source. Source seems to be closed."
                        .to_owned(),
                ))
            }
            Some(Err(e)) => {
                return Err(KMsgParserError::BadSource(format!(
                    "Couldn't peek a single line from source due to error: {:?}",
                    e
                )))
            }
            _ => {}
        }

        Ok(RMesgReader {
            _verbosity: verbosity,
            rmesg_line_reader,
            system_start_time,
            event_stream_start_time,
        })
    }

    // Message spec: https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/dev-kmsg
    // Parses a kernel log line that looks like this:
    // <5>a.out[4054]: segfault at 7ffd5503d358 ip 00007ffd5503d358 sp 00007ffd5503d258 error 15
    // OR
    // <5>[   233434.343533] a.out[4054]: segfault at 7ffd5503d358 ip 00007ffd5503d358 sp 00007ffd5503d258 error 15
    fn parse_next_rmesg(&mut self) -> Result<KMsgPtr, KMsgParsingError> {
        lazy_static! {
            static ref RE_RMESG_WITH_TIMESTAMP: Regex = Regex::new(
                r"(?x)^
                [[:space:]]*<(?P<faclevstr>[[:xdigit:]]*)>
                [[:space:]]*[\[][[:space:]]*(?P<timestampstr>[[:xdigit:]]*\.[[:xdigit:]]*)[\]]
                (?P<message>.*)$"
            )
            .unwrap();
        }

        let line_str = self.next_rmesg_record()?;

        if line_str.trim() == "" {
            return Err(KMsgParsingError::EmptyLine);
        }

        if let Some(rmesgparts) = RE_RMESG_WITH_TIMESTAMP.captures(&line_str) {
            let (facility, level) = match common::parse_fragment::<u32>(&rmesgparts["faclevstr"]) {
                Some(faclev) => {
                    // facility is top 28 bits, log level is bottom 3 bits
                    match (events::LogFacility::from_u32(faclev >> 3), events::LogLevel::from_u32(faclev >> 3)) {
                            (Some(facility), Some(level)) => (facility, level),
                            _ => return Err(KMsgParsingError::Generic(format!("Unable to parse {} into log facility and level. Line: {}", faclev, line_str)))
                    }
                },
                None => return Err(KMsgParsingError::Generic(format!("Unable to parse facility/level {} into a base-10 32-bit unsigned integer. Line: {}", &rmesgparts["faclevstr"], line_str)))
            };

            let timestamp = match common::parse_fragment::<f64>(&rmesgparts["timestampstr"]) {
                Some(timesecs) => {
                    match ChronoDuration::from_std(Duration::from_secs_f64(timesecs)) {
                        Ok(d) => self.system_start_time.add(d),
                        Err(e) => {
                            return Err(KMsgParsingError::Generic(format!(
                                "Unable to parse {} into a time duration: {:?}",
                                timesecs, e
                            )))
                        }
                    }
                }
                None => {
                    return Err(KMsgParsingError::Generic(format!(
                        "Unable to parse {} into a floating point number.",
                        &rmesgparts["timestampstr"]
                    )))
                }
            };

            // exit if timestamp is less than event stream start time
            if timestamp < self.event_stream_start_time {
                return Err(KMsgParsingError::EventTooOld);
            }

            let message = rmesgparts["message"].to_owned();

            Ok(Box::new(KMsg {
                facility,
                level,
                timestamp,
                message,
            }))
        } else {
            Err(KMsgParsingError::Generic(format!(
                "Invalid line: {}",
                &line_str
            )))
        }
    }

    fn next_rmesg_record(&mut self) -> Result<String, KMsgParsingError> {
        // read next line
        match self.rmesg_line_reader.next() {
            Some(maybe_line) => match maybe_line {
                Ok(line) => Ok(line),
                Err(e) => Err(KMsgParsingError::Generic(format!(
                    "Error from underlying iterator: {:?}",
                    e
                ))),
            },
            None => Err(KMsgParsingError::Completed),
        }
    }
}

impl Iterator for RMesgReader {
    // we will be counting with usize
    type Item = KMsgPtr;

    // next() is the only required method
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.parse_next_rmesg() {
                Ok(kmptr) => return Some(kmptr),
                Err(e) => match e {
                    KMsgParsingError::Completed => {
                        eprintln!("Iterator completed. No more messages expected");
                        return None;
                    }
                    KMsgParsingError::EventTooOld => {
                        // keep looking until there's an error, or some message is returned
                        // Not sure about Rust's tail recursion, so looping to avoid stack overflows.
                        continue;
                    }
                    KMsgParsingError::EmptyLine => {
                        // keep looking until there's an error, or some message is returned
                        // Not sure about Rust's tail recursion, so looping to avoid stack overflows.
                        continue;
                    }
                    KMsgParsingError::Generic(msg) => {
                        // don't exit because there may be bad lines...
                        eprintln!("Error parsing kmsg line due to error: {}", msg);
                        continue;
                    }
                },
            }
        }
    }
}

/**********************************************************************************/
// Tests! Tests! Tests!

#[cfg(test)]
mod test {
    use super::*;
    use chrono::TimeZone;
    use pretty_assertions::assert_eq;

    struct LinesIterMock {
        lines_iter: Vec<String>,
    }
    impl LinesIterMock {
        fn from_message(message: &str) -> LinesIterMock {
            let mut owned_lines: Vec<String> = vec![];
            for line in message.lines() {
                owned_lines.push(line.to_owned());
            }

            LinesIterMock {
                lines_iter: owned_lines,
            }
        }
    }
    impl Iterator for LinesIterMock {
        type Item = RMesgResult;
        fn next(&mut self) -> Option<Self::Item> {
            Some(Ok(self.lines_iter.remove(0)))
        }
    }

    #[test]
    fn can_ignore_untimestamped_entries() {
        let realistic_message = r"
<4>Call Trace:
<25>a.out[26692]: segfault at 70 ip 000000000040059d sp 00007ffe334959e0 error 6 in a.out[400000+1000]
<4>a.out/26692: potentially unexpected fatal signal 11.";

        let peekable_line_iter = LinesIterMock::from_message(realistic_message);
        let mut iter = RMesgReader::with_lines_iterator(
            Box::new(peekable_line_iter),
            Utc.timestamp_millis(4624626262),
            Utc.timestamp_millis(0),
            3,
        )
        .unwrap();

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_none());
    }

    #[test]
    fn can_parse_modern_timestamped_entries() {
        let realistic_message = r"
<2>[111310.984259] a.out[14685]: segfault at 5556f7707004 ip 00005556f7707004 sp 00007ffec6c34d78 error 15 in a.out[5556f7707000+1000]
<1>[111310.986286] Code: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 02 00 <68> 65 6c 6c 6f 20 77 6f 72 6c 64 20 72 61 6e 64 6f 6d 20 64 61 74";

        let peekable_line_iter = LinesIterMock::from_message(realistic_message);
        let mut iter = RMesgReader::with_lines_iterator(
            Box::new(peekable_line_iter),
            Utc.timestamp_millis(4624626262),
            Utc.timestamp_millis(0),
            3,
        )
        .unwrap();

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(entry, Box::new(KMsg{
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Emergency,
            timestamp: iter.system_start_time.add(ChronoDuration::from_std(Duration::from_secs_f64(111310.984259)).unwrap()),
            message: String::from(" a.out[14685]: segfault at 5556f7707004 ip 00005556f7707004 sp 00007ffec6c34d78 error 15 in a.out[5556f7707000+1000]"),
        }));

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(entry, Box::new(KMsg{
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Emergency,
            timestamp: iter.system_start_time.add(ChronoDuration::from_std(Duration::from_secs_f64(111310.986286)).unwrap()),
            message: String::from(" Code: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 02 00 <68> 65 6c 6c 6f 20 77 6f 72 6c 64 20 72 61 6e 64 6f 6d 20 64 61 74"),
        }));
    }

    #[test]
    fn can_parse_entries_from_timestamp() {
        let realistic_message = r"
<2>[111310.984259] a.out[14685]: segfault at 5556f7707004 ip 00005556f7707004 sp 00007ffec6c34d78 error 15 in a.out[5556f7707000+1000]
<1>[111310.986286] Code: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 02 00 <68> 65 6c 6c 6f 20 77 6f 72 6c 64 20 72 61 6e 64 6f 6d 20 64 61 74";

        let peekable_line_iter = LinesIterMock::from_message(realistic_message);
        let mut iter = RMesgReader::with_lines_iterator(
            Box::new(peekable_line_iter),
            Utc.timestamp_nanos(4624626262000000),
            Utc.timestamp_nanos(4624626262000000 + 111310986286000),
            3,
        )
        .unwrap();

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(entry, Box::new(KMsg{
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Emergency,
            timestamp: iter.system_start_time.add(ChronoDuration::from_std(Duration::from_secs_f64(111310.986286)).unwrap()),
            message: String::from(" Code: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 02 00 <68> 65 6c 6c 6f 20 77 6f 72 6c 64 20 72 61 6e 64 6f 6d 20 64 61 74"),
        }));
    }

    #[test]
    fn can_parse_mixed_rmesg_entries_with_bad_line() {
        let realistic_message = r"
<2>Call Trace:
<never closea.out[26692]: segfault at 70 ip 000000000040059d sp 00007ffe334959e0 error 6 in a.out[400000+1000]
<6>a.out[26692]: segfault at 70 ip 000000000040059d sp 00007ffe334959e0 error 6 in a.out[400000+1000]
never open>a.out[26692]: segfault at 70 ip 000000000040059d sp 00007ffe334959e0 error 6 in a.out[400000+1000]
<6>[  1310.986286] Code: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 02 00 <68> 65 6c 6c 6f 20 77 6f 72 6c 64 20 72 61 6e 64 6f 6d 20 64 61 74
<4>a.out/26692: potentially unexpected fatal signal 11.";

        let peekable_line_iter = LinesIterMock::from_message(realistic_message);
        let mut iter = RMesgReader::with_lines_iterator(
            Box::new(peekable_line_iter),
            Utc.timestamp_millis(4624626262),
            Utc.timestamp_millis(0),
            3,
        )
        .unwrap();

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(
            entry,
            Box::new(KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Emergency,
                timestamp: iter.system_start_time.add(ChronoDuration::from_std(Duration::from_secs_f64(1310.986286)).unwrap()),
                message: String::from(" Code: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 02 00 <68> 65 6c 6c 6f 20 77 6f 72 6c 64 20 72 61 6e 64 6f 6d 20 64 61 74"),
            })
        );
    }
}
