// Strum contains all the trait definitions
extern crate strum;
extern crate regex;

use regex::Regex;
use std::str::FromStr;
use strum_macros::{EnumString};
use std::{thread, time};
use std::process::Command;
use std::sync::mpsc::{Sender};

use crate::events;


pub struct MonitorConfig {
    pub poll_interval: Option<time::Duration>,
    pub dmesg_location: Option<String>,
    pub args: Option<Vec<String>>,
}

#[derive(EnumString)]
#[derive(Debug)]
#[derive(PartialEq)]
enum LogFacility {
    #[strum(serialize="unknown")]
    Unknown,

    #[strum(serialize="kern")]
    Kern,

    #[strum(serialize="user")]
    User,

    #[strum(serialize="mail")]
    Mail,

    #[strum(serialize="daemon")]
    Daemon,

    #[strum(serialize="auth")]
    Auth,

    #[strum(serialize="syslog")]
    Syslog,

    #[strum(serialize="lpr")]
    Lpr,

    #[strum(serialize="news")]
    News
}

#[derive(EnumString)]
#[derive(Debug)]
#[derive(PartialEq)]
enum LogLevel {
    #[strum(serialize="unknown")]
    Unknown,

    #[strum(serialize="emerg")]
    Emergency,

    #[strum(serialize="alert")]
    Alert,

    #[strum(serialize="crit")]
    Critical,

    #[strum(serialize="err")]
    Error,

    #[strum(serialize="warn")]
    Warning,

    #[strum(serialize="notice")]
    Notice,

    #[strum(serialize="info")]
    Info,

    #[strum(serialize="debug")]
    Debug
}

#[derive(PartialEq)]
#[derive(Debug)]
struct DmesgEntry {
    facility: LogFacility,
    level: LogLevel,
    timestamp: f64,
    message: String,
}

pub fn monitor(mc: MonitorConfig, _sink: Sender<events::Event>) {
    eprintln!("Monitor: Reading dmesg periodically to get kernel messages...");

    let poll_interval = match mc.poll_interval {
        None => {
            eprintln!("Monitor: No poll interval specified. Defaulting to '10 seconds'.");
            time::Duration::from_secs(10)
        },
        Some(l) => l,
    };

    let dmesg_location = match mc.dmesg_location {
        None => {
            eprintln!("Monitor: No dmesg path specified. Trusting system PATH. Defaulting to 'dmesg'.");
            String::from("dmesg")
        },
        Some(l) => l,
    };

    let args = match mc.args {
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

    // infinite iterator
    for event in DMesgParser::from_dmesg_iterator(DMesgPoller::with_poll_settings(poll_interval, &dmesg_location, &args)) {
        eprintln!("{:#?}", event);
    }
}



struct DMesgPoller {
    poll_interval: time::Duration,
    dmesg_location: String,
    args: Vec<String>,
    last_timestamp: f64,
    queue: Vec<DmesgEntry>,
    re_dmesg_line_format_1: Regex,
}

impl DMesgPoller {
    fn with_poll_settings(poll_interval: time::Duration, dmesg_location: &String, args: &Vec<String>) -> DMesgPoller {
        DMesgPoller {
            poll_interval,
            dmesg_location: dmesg_location.clone(),
            args: args.clone(),
            last_timestamp: 0.0,
            queue: Vec::new(),
            re_dmesg_line_format_1: DMesgPoller::dmesg_format_1(),
        }
    }

    #[cfg(test)]
    fn no_polling() -> DMesgPoller {
        DMesgPoller {
            poll_interval: time::Duration::from_secs(0),
            dmesg_location: String::from(""),
            args: vec![],
            last_timestamp: 0.0,
            queue: Vec::new(),
            re_dmesg_line_format_1: DMesgPoller::dmesg_format_1(),
        }
    }

    fn dmesg_format_1() -> Regex {
        // Regex reference here: https://docs.rs/regex/1.3.1/regex/

        //This regex looks for this format:
        //kern  :info  : [174297.359257] docker0: port 2(veth51d1953) entered disabled state
        // Let's break this down a bit:
        // (?m) # Parse multiple lines - begin line begin (^
        let mut dmesg_format_1 = String::from(r"(?m)(^");
        // the log facility (may have whitespace around it, followed by a colon)
        dmesg_format_1.push_str(r"[[:space:]]*(?P<facility>[[:alpha:]]*)[[:space:]]*:");
        // log level (may have whitespace around it, followed by a colon)
        dmesg_format_1.push_str(r"[[:space:]]*(?P<level>[[:alpha:]]*)[[:space:]]*:");
        // [timestamp] enclosed in square brackets (may have whitespace preceeding it)
        dmesg_format_1.push_str(r"[[:space:]]*[\[](?P<timestamp>[[:digit:]]*\.[[:digit:]]*)[\]]"); 
        // message gobbles up everything left
        dmesg_format_1.push_str(r"(?P<message>.*)");
        // close out the line
        dmesg_format_1.push_str(r"$)");
        eprintln!("Monitor: Initializing dmesg format 1 regex: {}", dmesg_format_1);
        Regex::new(dmesg_format_1.as_str()).unwrap()
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
                            match self.parse_dmesg_entries(messages.as_str()) {
                                Ok(dmesg_entries) => {
                                    for dmesg_entry in dmesg_entries.into_iter() {
                                        if dmesg_entry.timestamp > self.last_timestamp {
                                            self.last_timestamp = dmesg_entry.timestamp;
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

    fn parse_dmesg_entries(&mut self, dmesg_output: &str) -> Result<Vec<DmesgEntry>, String> {
        let mut dmesg_entries: Vec<DmesgEntry> = vec![];

        for line_parts in self.re_dmesg_line_format_1.captures_iter(dmesg_output) {
                let facility = match LogFacility::from_str(&line_parts["facility"]) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("Unable to parse LogFacility {} into enum: {}", &line_parts["facility"], e);
                        continue
                    }
                };

                let level = match LogLevel::from_str(&line_parts["level"]) {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("Unable to parse LogLevel {} into enum: {}", &line_parts["level"], e);
                        continue
                    }
                };

                let timestamp = match &line_parts["timestamp"].parse::<f64>() {
                    Ok(num) => *num,
                    Err(e) => {
                        eprintln!("Unable to parse Timestamp {} into enum: {}", &line_parts["timestamp"], e);
                        continue
                    }
                };

                dmesg_entries.push(DmesgEntry{
                    facility,
                    level,
                    timestamp,
                    message: line_parts["message"].to_owned(),
                });
        };
        Ok(dmesg_entries)
    }
}

impl Iterator for DMesgPoller {
    // we will be counting with usize
    type Item = DmesgEntry;

    // next() is the only required method
    fn next(&mut self) -> Option<Self::Item> {
        let mut first = true;
    
        // if queue has something, self it back
        while self.queue.is_empty() {
            if !first {
                eprintln!("Monitor: Still no messages. Sleeping poller for {:#?}", self.poll_interval);
                thread::sleep(self.poll_interval);
            }

            first = false;
            eprintln!("Monitor: No new messages. Polling dmesg...");
            self.fetch_dmesg_and_enqueue();
        }

        Some(self.queue.remove(0))
    }
}


struct DMesgParser<T: Iterator<Item = DmesgEntry>> {
    dmesg_iter: T
}

impl<T> DMesgParser<T>
where T: Iterator<Item = DmesgEntry>  {
    fn from_dmesg_iterator(dmesg_iter: T) -> DMesgParser<T> { 
            DMesgParser {
                dmesg_iter
            }
    }

    fn parse_next_event(&mut self) -> Result<events::Event, String> {
        // find the next event (we don't use a for loop because we don't want to move
        // the iterator outside of self. We only want to move next() values out of the iterator.
        loop {
            let maybe_dmesg_entry = self.dmesg_iter.next();
            //println!("New DMesg Entry: {:#?}", maybe_dmesg_entry);
            match maybe_dmesg_entry {
                Some(dmesg_entry) => {
                    if dmesg_entry.message.contains("segfault") {
                        // We have this fatal's entry, enabled by debug.exception-trace
                        // kern  :info  : [372850.968943] a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
                        match self.parse_exception_trace(dmesg_entry) {
                            Ok(deets) => return Ok(events::Event::Segfault(deets)),
                            Err(e) => eprintln!("Monitor: Unable to parse exception-trace line into a Segfault Details struct: {}\n", e)
                        }
                    } else if dmesg_entry.message.contains("fatal signal 11") {
                        // We have this entry, enabled by kernel.print-fatal-signals
                        // kern  :info  : [372850.970643] potentially unexpected fatal signal 11.
                        // kern  :warn  : [372850.971417] CPU: 1 PID: 36075 Comm: a.out Not tainted 4.14.131-linuxkit #1
                        // kern  :warn  : [372850.972476] Hardware name:  BHYVE, BIOS 1.00 03/14/2014
                        // kern  :warn  : [372850.973380] task: ffff9b08f2e1c3c0 task.stack: ffffb493c0e98000
                        // kern  :warn  : [372850.974349] RIP: 0033:0x561bc8d8f12e
                        // kern  :warn  : [372850.974981] RSP: 002b:00007ffd5833d0c0 EFLAGS: 00010246
                        // kern  :warn  : [372850.975780] RAX: 0000000000000000 RBX: 0000000000000000 RCX: 00007fd15e0e0718
                        // kern  :warn  : [372850.976943] RDX: 00007ffd5833d1b8 RSI: 00007ffd5833d1a8 RDI: 0000000000000001
                        // kern  :warn  : [372850.978183] RBP: 00007ffd5833d0c0 R08: 00007fd15e0e1d80 R09: 00007fd15e0e1d80
                        // kern  :warn  : [372850.979232] R10: 0000000000000000 R11: 0000000000000000 R12: 0000561bc8d8f040
                        // kern  :warn  : [372850.980268] R13: 00007ffd5833d1a0 R14: 0000000000000000 R15: 0000000000000000
                        // kern  :warn  : [372850.981246] FS:  00007fd15e0e7500(0000) GS:ffff9b08ffd00000(0000) knlGS:0000000000000000
                        // kern  :warn  : [372850.982384] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
                        // kern  :warn  : [372850.983159] CR2: 0000000000000000 CR3: 0000000132d26005 CR4: 00000000000606a0
                    }
                },
                None => break
            }
        }

        Err("Exited dmesg iterator unexpectedly.".to_owned())
    }

    // Parses this: a.out[33629]: segfault at 0 ip 0000556b4c03c603 sp 00007ffe55496510 error 4 in a.out[556b4c03c000+1000]
    // Into SegfaultDetails
    fn parse_exception_trace(&mut self, dmesg_entry: DmesgEntry) -> Result<events::SegfaultDetails, String> {
        let  message = dmesg_entry.message;
        let mut exec_and_rest = message.splitn(2,"[");
        let executable = match exec_and_rest.next() {
            Some(exec) => exec,
            None => {
                eprintln!("Monitor: Unable to parse the first word, executable, in message: {}", message);
                ""
            }
        };

        let (pid_str, maybe_rest) = match exec_and_rest.next() {
            Some(rest) => {
                let mut pid_and_rest = rest.splitn(2, "]");
                match pid_and_rest.next() {
                    Some(p) => (p, pid_and_rest.next()),
                    None => {
                        eprintln!("Monitor: Unable to parse the second word, pid, in message: {}", message);
                        ("", Some(""))
                    }
                }
            }
            None => {
                eprintln!("Monitor: Segfault message has nothing after executable: {}", message);
                ("", Some(""))
            }
        };

        // https://stackoverflow.com/questions/6294133/maximum-pid-in-linux
        let pid = match pid_str.parse::<usize>() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Monitor: Could not parse pid from string: {}", pid_str);
                0
            }
        };

        let rest = match maybe_rest {
            Some(r) => r,
            None => {
                eprintln!("Monitor: No message after executable and pid in dmesg entry: {}", message);
                ""
            }
        };

        Ok(events::SegfaultDetails{
            executable: executable.to_owned(),
            pid: pid,
            message: rest.to_owned(),
        })
    }
}

impl<T: Iterator<Item = DmesgEntry>> Iterator for DMesgParser<T> {
   // we will be counting with usize
    type Item = events::Event;

    // next() is the only required method
    fn next(&mut self) -> Option<Self::Item> {
        match self.parse_next_event() {
            Ok(event) => Some(event),
            Err(err) => {
                eprintln!("Monitor: Error iterating over events from the dmesg parser: {}", err);
                None
            }
        }
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
kern: badlevel :[372850.968943] a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
kern: invalid-level :[372850.968943] a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
invalid-facility :info :[372850.968943] a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
invalid-facility :info : no timestamp a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
no colons [372850.968943] a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]
";

        let results = DMesgPoller::no_polling().parse_dmesg_entries(realistic_message);
        assert!(!results.is_err());
        let entries = results.unwrap();
        let mut iter = entries.iter();

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(entry, &DmesgEntry{
            facility: LogFacility::Kern,
            level: LogLevel::Info,
            timestamp: 372850.968943,
            message: String::from(" a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
        });

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(entry, &DmesgEntry{
            facility: LogFacility::Kern,
            level: LogLevel::Warning,
            timestamp: 372850.97,
            message: String::from(" a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
        });

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_none());
    }
}
/**********************************************************************************/
