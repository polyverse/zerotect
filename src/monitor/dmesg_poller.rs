extern crate regex;
extern crate num;

use crate::events;
use crate::monitor::kmsg;

use regex::Regex;
use std::str::FromStr;
use std::{thread, time};
use std::process::Command;

pub struct DMesgPollerConfig {
    pub poll_interval: Option<time::Duration>,
    pub dmesg_location: Option<String>,
    pub args: Option<Vec<String>>,
}

pub struct DMesgPoller {
    poll_interval: time::Duration,
    dmesg_location: String,
    args: Vec<String>,
    last_timestamp: u64,
    queue: Vec<kmsg::KMsg>,
    verbosity: u8,
}

impl DMesgPoller {
    pub fn with_poll_settings(config: DMesgPollerConfig, verbosity: u8) -> DMesgPoller {
        let poll_interval = match config.poll_interval {
            None => {
                eprintln!("Monitor: No poll interval specified. Defaulting to '10 seconds'.");
                time::Duration::from_secs(10)
            },
            Some(l) => l,
        };

        let dmesg_location = match config.dmesg_location {
            None => {
                eprintln!("Monitor: No dmesg path specified. Trusting system PATH. Defaulting to 'dmesg'.");
                String::from("dmesg")
            },
            Some(l) => l,
        };

        let args = match config.args {
            None => {
                let default_args: Vec<String> = vec![
                    "-x".to_owned(), // Decode messages so we can textual representations of log-level and subsystem
                    "-k".to_owned(), // Show kernel messages
                    "-u".to_owned(), // Show user-mode messages
                ];
                default_args
            },
            Some(a) => a
        };

        DMesgPoller {
            poll_interval,
            dmesg_location: dmesg_location.clone(),
            args: args.clone(),
            last_timestamp: 0,
            queue: Vec::new(),
            verbosity,
        }
    }

    #[cfg(test)]
    fn no_polling() -> DMesgPoller {
        DMesgPoller {
            poll_interval: time::Duration::from_secs(0),
            dmesg_location: String::from(""),
            args: vec![],
            last_timestamp: 0,
            queue: Vec::new(),
            verbosity: 0,
        }
    }

    fn fetch_dmesg_and_enqueue(&mut self) {
            let maybe_dmesg_output = Command::new(&self.dmesg_location)
            .args(&self.args)
            .output();

            match maybe_dmesg_output {
                Ok(dmesg_output) => {
                    if !dmesg_output.status.success() {
                        eprintln!("Monitor: dmesg exit code: {}", dmesg_output.status);
                    }

                    let maybe_messages = String::from_utf8(dmesg_output.stdout);
                    match maybe_messages {
                        Ok(messages) => {
                            match self.parse_kmsgs(messages.as_str()) {
                                Ok(dmesg_entries) => {
                                    for dmesg_entry in dmesg_entries.into_iter() {
                                        if (dmesg_entry.info.timestamp > self.last_timestamp) || self.last_timestamp == 0 {
                                            // fetch all kernel start messages until we move past timestamp 0, then begin incrementing.
                                            if dmesg_entry.info.timestamp > 0 { self.last_timestamp = dmesg_entry.info.timestamp; }
                                            self.queue.push(dmesg_entry);
                                        }
                                    }
                                },
                                Err(e) => eprintln!("Monitor: Unable to parse dmesg_entries: {}", e)
                            }
                        },
                        Err(e) => {
                            eprintln!("Monitor: dmesg output was not utf8. Ignoring. Error: {}", e);
                        }
                    }
                },
                Err(e) => {
                    eprintln!("Monitor: Error occurred when calling dmesg: {}", e);
                }
            }
    }

    fn parse_kmsgs(&mut self, dmesg_output: &str) -> Result<Vec<kmsg::KMsg>, String> {
        lazy_static! {
            //This regex looks for this format across multiple lines:
            //kern  :info  : [174297.359257] <rest of the message>
            static ref RE1: Regex = Regex::new(r"(?mx)(^
                # the log facility (may have whitespace around it, followed by a colon)
                [[:space:]]*(?P<facility>[[:alpha:]]*)[[:space:]]*: 
                # log level (may have whitespace around it, followed by a colon)
                [[:space:]]*(?P<level>[[:alpha:]]*)[[:space:]]*:
                # [timestamp] enclosed in square brackets (may have whitespace preceeding it)
                [[:space:]]*[\[](?P<timestamp>[[:space:]]*[[:digit:]]*\.[[:digit:]]*)[\]]
                # message gobbles up everything left
                (?P<message>.*)
                # close out the line
                $)").unwrap();
        }

        if self.verbosity > 2 { eprintln!("Monitor:: parse_kmsgs:: complete dmesg raw output: {}", dmesg_output); }

        let mut kmsgs: Vec<kmsg::KMsg> = vec![];
        for line_parts in RE1.captures_iter(dmesg_output) {
            if self.verbosity > 2 { eprintln!("Monitor:: parse_kmsgs:: parsed parts of a line: {:?}", line_parts); }
            if let (Some(facility), Some(level), Some(timestamp)) = 
            (self.parse_fragment::<events::LogFacility>(&line_parts["facility"]), 
            self.parse_fragment::<events::LogLevel>(&line_parts["level"]), 
            self.parse_fragment::<f64>(&line_parts["timestamp"])) {
                let entry = kmsg::KMsg{
                    info: events::EventInfo {
                        facility,
                        level,
                        //undoing this: https://github.com/karelzak/util-linux/blob/master/sys-utils/dmesg.c#L493
                        timestamp: (timestamp*1000000.0) as u64, 
                    },
                    message: line_parts["message"].to_owned(),
                };

                if self.verbosity > 1 { eprintln!("Monitor:: parse_kmsgs:: parsed entry: {:?}", entry); }
                kmsgs.push(entry);
            } 
        };
        Ok(kmsgs)
    }


    fn parse_fragment<F: FromStr + typename::TypeName>(&mut self, frag: &str) -> Option<F> 
    where <F as std::str::FromStr>::Err: std::fmt::Display
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

impl Iterator for DMesgPoller {
    // we will be counting with usize
    type Item = kmsg::KMsg;

    // next() is the only required method
    fn next(&mut self) -> Option<Self::Item> {
        let mut first = true;
    
        // if queue has something, self it back
        while self.queue.is_empty() {
            if !first {
                eprintln!("Monitor:: DMesgPoller:: Iter:: Still no messages. Sleeping poller for {:#?}", self.poll_interval);
                thread::sleep(self.poll_interval);
            }

            first = false;
            eprintln!("Monitor:: DMesgPoller:: Iter:: No new messages. Polling dmesg...");
            self.fetch_dmesg_and_enqueue();
        }

        Some(self.queue.remove(0))
    }
}

/**********************************************************************************/
// Tests! Tests! Tests!

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_parse_dmesg_entries() {
        let realistic_message = "
        kern  :info  : [372850.968943] a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
kern: warn :[372850.970000] a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
badfacility: info :[372850.968943] a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
kern: badlevel :[ 372850.968943] a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
kern: invalid-level :[ 372850.968943] a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
invalid-facility :info :[372850.968943] a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
invalid-facility :info : no timestamp a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
no colons [372850.968943] a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
";

        let results = DMesgPoller::no_polling().parse_kmsgs(realistic_message);
        assert!(!results.is_err());
        let entries = results.unwrap();
        let mut iter = entries.iter();

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(entry, &kmsg::KMsg{
            info: events::EventInfo{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Info,
                timestamp: 372850968943,
            },
            message: String::from(" a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
        });

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(entry, &kmsg::KMsg{
            info: events::EventInfo{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                timestamp: 372850970000,
            },
            message: String::from(" a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
        });

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_none());
    }
}