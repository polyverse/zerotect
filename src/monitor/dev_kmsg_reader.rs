// Copyright (c) 2019 Polyverse Corporation

use crate::events;
use crate::monitor::kmsg::{KMsg, KMsgParserError, KMsgParsingError};
use crate::system;
use std::boxed::Box;
use std::io::BufRead;
use timeout_iterator::TimeoutIterator;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use num::FromPrimitive;
use std::fs::File;
use std::io::BufReader;
use std::ops::Add;
use std::str::FromStr;
use std::time::Duration;

pub type LineItem = std::result::Result<String, std::io::Error>;
pub type LinesIterator = Box<dyn Iterator<Item = LineItem> + Send>;

const DEV_KMSG_LOCATION: &str = "/dev/kmsg";

#[derive(Clone)]
pub struct DevKMsgReaderConfig {
    pub from_sequence_number: u64,
    pub flush_timeout: Duration,
}

pub struct DevKMsgReader {
    verbosity: u8,
    kmsg_line_reader: TimeoutIterator<std::result::Result<std::string::String, std::io::Error>>,
    from_sequence_number: u64,
    flush_timeout: Duration,
    system_start_time: DateTime<Utc>,
}

impl DevKMsgReader {
    pub fn with_file(
        config: DevKMsgReaderConfig,
        verbosity: u8,
    ) -> Result<DevKMsgReader, KMsgParserError> {
        let dev_kmsg_file = match File::open(DEV_KMSG_LOCATION) {
            Ok(f) => f,
            Err(e) => {
                return Err(KMsgParserError::BadSource(format!(
                    "Unable to open file {}: {}",
                    DEV_KMSG_LOCATION, e
                )))
            }
        };

        let kmsg_lines_iter: LinesIterator = Box::new(BufReader::new(dev_kmsg_file).lines());
        DevKMsgReader::with_lines_iterator(
            config,
            kmsg_lines_iter,
            system::system_start_time()?,
            verbosity,
        )
    }

    fn with_lines_iterator(
        config: DevKMsgReaderConfig,
        reader: LinesIterator,
        system_start_time: DateTime<Utc>,
        verbosity: u8,
    ) -> Result<DevKMsgReader, KMsgParserError> {
        let mut kmsg_line_reader = TimeoutIterator::from_item_iterator(reader)?;
        match kmsg_line_reader.peek() {
            None => {
                return Err(KMsgParserError::BadSource(format!(
                    "Couldn't peek a single line from source. Source seems to be closed."
                )))
            }
            Some(l) => match l {
                Ok(_) => {}
                Err(e) => {
                    return Err(KMsgParserError::BadSource(format!(
                        "Couldn't peek a single line from source due to error: {:?}",
                        e
                    )))
                }
            },
        }

        Ok(DevKMsgReader {
            verbosity,
            kmsg_line_reader,
            from_sequence_number: config.from_sequence_number,
            flush_timeout: config.flush_timeout,
            system_start_time,
        })
    }

    // Message spec: https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/dev-kmsg
    // Parses a kernel log line that looks like this:
    // 6,550,12175490619,-;a.out[4054]: segfault at 7ffd5503d358 ip 00007ffd5503d358 sp 00007ffd5503d258 error 15
    fn parse_kmsg(&mut self) -> Result<KMsg, KMsgParsingError> {
        let line_str: String = self.next_kmsg_record()?;

        if line_str.trim() == "" {
            return Err(KMsgParsingError::EmptyLine);
        }

        // split this: 6,550,12175490619,-;a.out[4054]: segfault at 7ffd5503d358 ip 00007ffd5503d358 sp 00007ffd5503d258 error 15
        // into these
        // 6,550,12175490619,-
        // a.out[4054]: segfault at 7ffd5503d358 ip 00007ffd5503d358 sp 00007ffd5503d258 error 15
        let mut meta_and_msg = line_str.splitn(2, ';');
        let meta = match meta_and_msg.next() {
            Some(meta) => meta.trim(),
            None => {
                return Err(KMsgParsingError::Generic(format!(
                    "Didn't find kmsg metadata in line: {}",
                    line_str
                )))
            }
        };
        if self.verbosity > 2 {
            eprintln!(
                "Monitor:: parse_kmsg:: Broken line into metadata (part 1): {}",
                meta
            );
        }

        let message = match meta_and_msg.next() {
            Some(message) => message.trim(),
            None => {
                return Err(KMsgParsingError::Generic(format!(
                    "Didn't find kmsg message (even if empty) in line: {}",
                    line_str
                )))
            }
        };
        if self.verbosity > 2 {
            eprintln!(
                "Monitor:: parse_kmsg:: Broken line into message (part 2): {}",
                message
            );
        }

        let mut meta_parts = meta.splitn(4, ",");
        let (facility, level) = match meta_parts.next() {
            Some(faclevstr) => match DevKMsgReader::parse_fragment::<u32>(faclevstr) {
                Some(faclev) => {
                    // facility is top 28 bits, log level is bottom 3 bits
                    match (events::LogFacility::from_u32(faclev >> 3), events::LogLevel::from_u32(faclev >> 3)) {
                         (Some(facility), Some(level)) => (facility, level),
                         _ => return Err(KMsgParsingError::Generic(format!("Unable to parse {} into log facility and level. Line: {}", faclev, line_str)))
                    }
                },
                None => return Err(KMsgParsingError::Generic(format!("Unable to parse facility/level {} into a base-10 32-bit unsigned integer. Line: {}", faclevstr, line_str)))
            }
            None => return Err(KMsgParsingError::Generic(format!("Didn't find kmsg facility/level (the very first part) in line: {}", line_str)))
        };

        // Sequence is a 64-bit integer: https://www.kernel.org/doc/Documentation/ABI/testing/dev-kmsg
        let sequence_num = match meta_parts.next() {
            Some(seqnumstr) => match DevKMsgReader::parse_fragment::<u64>(seqnumstr) {
                Some(seqnum) => seqnum,
                None => {
                    return Err(KMsgParsingError::Generic(format!(
                        "Unable to parse sequence number into an integer: {}, Line: {}",
                        seqnumstr, line_str
                    )))
                }
            },
            None => {
                return Err(KMsgParsingError::Generic(format!(
                    "No sequence number found in line: {}",
                    line_str
                )))
            }
        };

        // exit if sequence number is less than where desired
        if sequence_num < self.from_sequence_number {
            return Err(KMsgParsingError::SequenceNumTooOld);
        }

        let duration_from_system_start = match meta_parts.next() {
            Some(tstr) => match DevKMsgReader::parse_fragment::<i64>(tstr) {
                Some(t) => ChronoDuration::microseconds(t),
                None => {
                    return Err(KMsgParsingError::Generic(format!(
                        "Unable to parse timestamp into integer: {}",
                        tstr
                    )))
                }
            },
            None => {
                return Err(KMsgParsingError::Generic(format!(
                    "No timestamp found in line: {}",
                    line_str
                )))
            }
        };

        if self.verbosity > 2 {
            if let Some(ignored) = meta_parts.next() {
                eprintln!(
                    "Monitor:: parse_kmsg:: Ignored metadata in kmsg: {}",
                    ignored
                );
            }
        }

        Ok(KMsg {
            facility,
            level,
            timestamp: self.system_start_time.add(duration_from_system_start),
            message: message.to_owned(),
        })
    }

    fn next_kmsg_record(&mut self) -> Result<String, KMsgParsingError> {
        // read next line
        let mut line_str = String::new();
        match self.kmsg_line_reader.next() {
            Some(maybe_line) => match maybe_line {
                Ok(line) => {
                    line_str.push_str(line.as_str());

                    // look for any supplemental lines and append them
                    loop {
                        match self.kmsg_line_reader.peek_timeout(self.flush_timeout) {
                            Ok(maybe_supplemental_line) => match maybe_supplemental_line {
                                Ok(supplemental_line) => {
                                    if supplemental_line.starts_with(' ') {
                                        line_str.push('\n'); //Preserve newlines
                                        line_str.push_str(supplemental_line);
                                        self.kmsg_line_reader.next(); //consume the next one
                                    } else {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            },
                            Err(_) => break,
                        }
                    }
                }
                Err(e) => {
                    return Err(KMsgParsingError::Generic(format!(
                        "Error from underlying iterator: {:?}",
                        e
                    )))
                }
            },
            None => return Err(KMsgParsingError::Completed),
        }
        Ok(line_str)
    }

    fn parse_fragment<F: FromStr + typename::TypeName>(frag: &str) -> Option<F>
    where
        <F as std::str::FromStr>::Err: std::fmt::Display,
    {
        match frag.trim().parse::<F>() {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("Unable to parse {} into {}: {}", frag, F::type_name(), e);
                None
            }
        }
    }
}

impl Iterator for DevKMsgReader {
    // we will be counting with usize
    type Item = KMsg;

    // next() is the only required method
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.parse_kmsg() {
                Ok(km) => return Some(km),
                Err(e) => match e {
                    KMsgParsingError::Completed => {
                        eprintln!("Iterator completed. No more messages expected");
                        return None;
                    }
                    KMsgParsingError::SequenceNumTooOld => {
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
    use std::thread;

    #[test]
    fn can_parse_kmsg_entries() {
        let realistic_message = r"
5,0,0,-;Linux version 4.14.131-linuxkit (root@6d384074ad24) (gcc version 8.3.0 (Alpine 8.3.0)) #1 SMP Fri Jul 19 12:31:17 UTC 2019
6,1,0,-;Command, line: BOOT_IMAGE=/boot/kernel console=ttyS0 console=ttyS1 page_poison=1 vsyscall=emulate panic=1 root=/dev/sr0 text
6,2,0,-;x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
6,3,0,-,more,deets;x86/fpu: Supporting XSAVE; feature 0x002: 'SSE registers'";

        let peekable_line_iter: LinesIterator =
            Box::new(realistic_message.lines().map(|s| Ok(s.to_owned())));
        let mut iter = DevKMsgReader::with_lines_iterator(
            DevKMsgReaderConfig {
                from_sequence_number: 0,
                flush_timeout: Duration::from_secs(1),
            },
            peekable_line_iter,
            Utc.timestamp_millis(4624626262),
            3,
        )
        .unwrap();

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(entry, KMsg{
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Emergency,
            timestamp: iter.system_start_time,
            message: String::from("Linux version 4.14.131-linuxkit (root@6d384074ad24) (gcc version 8.3.0 (Alpine 8.3.0)) #1 SMP Fri Jul 19 12:31:17 UTC 2019"),
        });

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(entry, KMsg{
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Emergency,
            timestamp: iter.system_start_time,
            message: String::from("Command, line: BOOT_IMAGE=/boot/kernel console=ttyS0 console=ttyS1 page_poison=1 vsyscall=emulate panic=1 root=/dev/sr0 text"),
        });

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(
            entry,
            KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Emergency,
                timestamp: iter.system_start_time,
                message: String::from(
                    "x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'"
                ),
            }
        );

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(
            entry,
            KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Emergency,
                timestamp: iter.system_start_time,
                message: String::from("x86/fpu: Supporting XSAVE; feature 0x002: 'SSE registers'"),
            }
        );
    }

    #[test]
    fn can_parse_kmsg_entries_from_sequence_number() {
        let realistic_message = r"
5,0,0,-;Linux version 4.14.131-linuxkit (root@6d384074ad24) (gcc version 8.3.0 (Alpine 8.3.0)) #1 SMP Fri Jul 19 12:31:17 UTC 2019
6,1,0,-;Command, line: BOOT_IMAGE=/boot/kernel console=ttyS0 console=ttyS1 page_poison=1 vsyscall=emulate panic=1 root=/dev/sr0 text
6,2,0,-;x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
6,3,0,-,more,deets;x86/fpu: Supporting XSAVE; feature 0x002: 'SSE registers'";

        let peekable_line_iter: LinesIterator =
            Box::new(realistic_message.lines().map(|s| Ok(s.to_owned())));
        let mut iter = DevKMsgReader::with_lines_iterator(
            DevKMsgReaderConfig {
                from_sequence_number: 3,
                flush_timeout: Duration::from_secs(1),
            },
            peekable_line_iter,
            Utc.timestamp_millis(4624626262),
            3,
        )
        .unwrap();

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(
            entry,
            KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Emergency,
                timestamp: iter.system_start_time,
                message: String::from("x86/fpu: Supporting XSAVE; feature 0x002: 'SSE registers'"),
            }
        );
    }

    #[test]
    fn can_parse_kmsg_entries_with_bad_line() {
        let realistic_message = r"
5,0,bad!!!n 4.14.131-linuxkit (root@6d384074ad24) (gcc version 8.3.0 (Alpine 8.3.0)) #1 SMP Fri Jul 19 12:31:17 UTC 2019
6,1,0,-;Command, line: BOOT_IMAGE=/boot/kernel console=ttyS0 console=ttyS1 page_poison=1 vsyscall=emulate panic=1 root=/dev/sr0 text
6,bad!!;x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
6,3,0,-,more,deets;x86/fpu: Supporting XSAVE; feature 0x002: 'SSE registers'";

        let peekable_line_iter: LinesIterator =
            Box::new(realistic_message.lines().map(|s| Ok(s.to_owned())));
        let mut iter = DevKMsgReader::with_lines_iterator(
            DevKMsgReaderConfig {
                from_sequence_number: 0,
                flush_timeout: Duration::from_secs(1),
            },
            peekable_line_iter,
            Utc.timestamp_millis(4624626262),
            3,
        )
        .unwrap();

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(entry, KMsg{
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Emergency,
            timestamp: iter.system_start_time,
            message: String::from("Command, line: BOOT_IMAGE=/boot/kernel console=ttyS0 console=ttyS1 page_poison=1 vsyscall=emulate panic=1 root=/dev/sr0 text"),
        });

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(
            entry,
            KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Emergency,
                timestamp: iter.system_start_time,
                message: String::from("x86/fpu: Supporting XSAVE; feature 0x002: 'SSE registers'"),
            }
        );
    }

    #[test]
    fn can_parse_kmsg_multi_line() {
        let realistic_message = r"
5,0,0,-;Linux version 4.14.131-linuxkit (root@6d384074ad24) (gcc version 8.3.0 (Alpine 8.3.0)) #1 SMP Fri Jul 19 12:31:17 UTC 2019
6,1,0,-;Command, line: BOOT_IMAGE=/boot/kernel console=ttyS0 console=ttyS1 page_poison=1 vsyscall=emulate panic=1 root=/dev/sr0 text
 LINE2=foobar
 LINE 3 = foobar ; with semicolon
6,2,0,-;x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
6,3,0,-,more,deets;x86/fpu: Supporting XSAVE; feature 0x002: 'SSE registers'";

        let peekable_line_iter: LinesIterator =
            Box::new(realistic_message.lines().map(|s| Ok(s.to_owned())));
        let mut iter = DevKMsgReader::with_lines_iterator(
            DevKMsgReaderConfig {
                from_sequence_number: 0,
                flush_timeout: Duration::from_secs(1),
            },
            peekable_line_iter,
            Utc.timestamp_millis(4624626262),
            3,
        )
        .unwrap();

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(entry, KMsg{
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Emergency,
            timestamp: iter.system_start_time,
            message: String::from("Linux version 4.14.131-linuxkit (root@6d384074ad24) (gcc version 8.3.0 (Alpine 8.3.0)) #1 SMP Fri Jul 19 12:31:17 UTC 2019"),
        });

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(
            entry,
            KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Emergency,
                timestamp: iter.system_start_time,
                message: String::from(
                    r"Command, line: BOOT_IMAGE=/boot/kernel console=ttyS0 console=ttyS1 page_poison=1 vsyscall=emulate panic=1 root=/dev/sr0 text
 LINE2=foobar
 LINE 3 = foobar ; with semicolon"
                ),
            }
        );

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(
            entry,
            KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Emergency,
                timestamp: iter.system_start_time,
                message: String::from(
                    "x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'"
                ),
            }
        );

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(
            entry,
            KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Emergency,
                timestamp: iter.system_start_time,
                message: String::from("x86/fpu: Supporting XSAVE; feature 0x002: 'SSE registers'"),
            }
        );
    }

    #[test]
    fn is_sendable() {
        let realistic_message = r"
5,0,0,-;Linux version 4.14.131-linuxkit (root@6d384074ad24) (gcc version 8.3.0 (Alpine 8.3.0)) #1 SMP Fri Jul 19 12:31:17 UTC 2019
6,1,0,-;Command, line: BOOT_IMAGE=/boot/kernel console=ttyS0 console=ttyS1 page_poison=1 vsyscall=emulate panic=1 root=/dev/sr0 text
6,2,0,-;x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
6,3,0,-,more,deets;x86/fpu: Supporting XSAVE; feature 0x002: 'SSE registers'";

        let peekable_line_iter: LinesIterator =
            Box::new(realistic_message.lines().map(|s| Ok(s.to_owned())));
        let mut iter = DevKMsgReader::with_lines_iterator(
            DevKMsgReaderConfig {
                from_sequence_number: 0,
                flush_timeout: Duration::from_secs(1),
            },
            peekable_line_iter,
            Utc.timestamp_millis(4624626262),
            3,
        )
        .unwrap();

        thread::spawn(move || {
            let maybe_entry = iter.next();
            assert!(maybe_entry.is_some());
            let entry = maybe_entry.unwrap();
            assert_eq!(entry, KMsg{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Emergency,
                timestamp: iter.system_start_time,
                message: String::from("Linux version 4.14.131-linuxkit (root@6d384074ad24) (gcc version 8.3.0 (Alpine 8.3.0)) #1 SMP Fri Jul 19 12:31:17 UTC 2019"),
            });
        });

        assert!(
            true,
            "If this compiles, DevKMsgReader is Send'able across threads."
        );
    }
}
