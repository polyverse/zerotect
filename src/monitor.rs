// Strum contains all the trait definitions
extern crate strum;
extern crate regex;

use regex::Regex;
use strum_macros::{EnumString};
use std::str::FromStr;
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

#[derive(Debug)]
struct DmesgEntry {
    facility: LogFacility,
    level: LogLevel,
    timestamp: f64,
    message: String,
}

pub fn monitor(mc: MonitorConfig, sink: Sender<events::Event>) {
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
    for event in DMesgParser::from_dmesg_iterator(DMesgPoller::from(poll_interval, &dmesg_location, &args)) {
        eprintln!("{:#?}", event);
    }
}



struct DMesgPoller {
    poll_interval: time::Duration,
    dmesg_location: String,
    args: Vec<String>,
    last_timestamp: f64,
    queue: Vec<DmesgEntry>,
}

impl DMesgPoller {
    fn from(poll_interval: time::Duration, dmesg_location: &String, args: &Vec<String>) -> DMesgPoller {
        DMesgPoller {
            poll_interval,
            dmesg_location: dmesg_location.clone(),
            args: args.clone(),
            last_timestamp: 0.0,
            queue: Vec::new(),
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
                            match DMesgPoller::parse_dmesg_entries(messages) {
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

    fn parse_dmesg_entries(dmesg_output: String) -> Result<Vec<DmesgEntry>, String> {
        lazy_static! {
            // Regex reference here: https://docs.rs/regex/1.3.1/regex/

            //This regex looks for this format:
            //kern  :info  : [174297.359257] docker0: port 2(veth51d1953) entered disabled state

            // Let's break this down a bit:
            // (?m) # Parse multiple lines
            // (^[[:space:]]*(?P<facility>[[:alpha:]])[[:space:]]* # the log facility (may have spaces around it)
            // :[[:space:]]*(?P<level>[[:alpha:]])[[:space:]]*  # colon followed by log level (may have spaces around it)
            // :[[:space:]]?[\[](?P<timestamp>[[:digit:]]*\.[[:digit:]]*)][\[][:space:]] # colon followed by [timestamp] enclosed in square brackets
            static ref RE_DMESG_LINE_FORMAT_1: Regex = Regex::new(r"(?m)(^[[:space:]]*(?P<facility>[[:alpha:]])[[:space:]]*:[[:space:]]*(?P<level>[[:alpha:]])[[:space:]]* (?P<message>.*)$)").unwrap();



            //TODO: Others may add different formats later
        }

        for line_parts in RE_DMESG_LINE_FORMAT_1.captures_iter(dmesg_output.as_str()) {
            println!("LogFacility: {}, LogLevel: {}, Timestamp: {}, Message: {}", 
                &line_parts["facility"], 
                &line_parts["level"], 
                &line_parts["timestamp"], 
                &line_parts["message"]);
        };

        println!("Parsing complete!");

        Ok(vec![])
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
                        // kern  :info  : [Mon Sep 16 02:26:41 2019] a.out[33629]: segfault at 0 ip 0000556b4c03c603 sp 00007ffe55496510 error 4 in a.out[556b4c03c000+1000]
                        match self.parse_exception_trace(dmesg_entry) {
                            Ok(deets) => return Ok(events::Event::Segfault(deets)),
                            Err(e) => eprintln!("Monitor: Unable to parse exception-trace line into a Segfault Details struct: {}\n", e)
                        }
                    } else if dmesg_entry.message.contains("fatal signal 11") {
                        // We have this entry, enabled by kernel.print-fatal-signals
                        // kern  :info  : [Mon Sep 16 02:26:41 2019] potentially unexpected fatal signal 11.
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] CPU: 1 PID: 33629 Comm: a.out Not tainted 4.14.131-linuxkit #1
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] Hardware name:  BHYVE, BIOS 1.00 03/14/2014
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] task: ffff9b07ce43af00 task.stack: ffffb493c54b4000
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] RIP: 0033:0x556b4c03c603
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] RSP: 002b:00007ffe55496510 EFLAGS: 00010246
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] RAX: 0000000000000000 RBX: 0000000000000000 RCX: 00007f0152d2c718
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] RDX: 00007ffe55496608 RSI: 00007ffe554965f8 RDI: 0000000000000001
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] RBP: 00007ffe55496510 R08: 00007f0152d2dd80 R09: 00007f0152d2dd80
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] R10: 0000000000000000 R11: 0000000000000000 R12: 0000556b4c03c4f0
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] R13: 00007ffe554965f0 R14: 0000000000000000 R15: 0000000000000000
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] FS:  00007f0152d33500(0000) GS:ffff9b08ffd00000(0000) knlGS:0000000000000000
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
                        // kern  :warn  : [Mon Sep 16 02:26:41 2019] CR2: 0000000000000000 CR3: 00000000a3440005 CR4: 00000000000606a0
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
        let pid = match pid_str.parse::<u64>() {
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

