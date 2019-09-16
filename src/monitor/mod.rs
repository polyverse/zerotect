// Strum contains all the trait definitions
extern crate strum;
extern crate chrono;

use strum_macros::{EnumString};
use std::str::FromStr;
use std::{thread, time};
use std::process::Command;
use std::sync::mpsc::{Sender};

use crate::events;

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

pub struct MonitorConfig {
    pub poll_interval: Option<time::Duration>,
    pub dmesg_location: Option<String>,
    pub args: Option<Vec<String>>,
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
    for message in DMesgPoller::from(poll_interval, &dmesg_location, &args) {
        eprintln!("{:#?}", message);
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
                            for line in messages.lines() {
                                match DMesgPoller::parse_line(&line) {
                                    Ok(dmesg_entry) => {
                                        if dmesg_entry.timestamp > self.last_timestamp {
                                            self.last_timestamp = dmesg_entry.timestamp;
                                            self.queue.push(dmesg_entry);
                                        }
                                    },
                                    Err(e) => {
                                        eprintln!("Monitor: Unable to parse a line: {}" , e);
                                    }
                                }
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

    // line looks like: kern  :info  : [174297.359257] docker0: port 2(veth51d1953) entered disabled state
    fn parse_line(line: &str) -> Result<DmesgEntry, String> {
        let mut line_parts = line.splitn(3, ":");
        // At this level we split
        // kern  :info  : [174297.359257] docker0: port 2(veth51d1953) entered disabled state
        // into: <kern, info, [174297.359257] docker0: port 2(veth51d1953) entered disabled state>
        let facility: LogFacility = match line_parts.next() {
            Some(first) => {
                match LogFacility::from_str(first.trim()) {
                    Ok(facility) => facility,
                    Err(e) => return Err(format!("Unable to parse {} into Log Facility: {}", first.trim(), e))
                }
            },
            None => return Err(format!("No facility identifier found at first position in dmesg entry: {}", line))
        };

        let level: LogLevel = match line_parts.next() {
            Some(second) => {
                match LogLevel::from_str(second.trim()) {
                    Ok(level) => level,
                    Err(e) => return Err(format!("Unable to parse {} into Log Level: {}", second.trim(), e))
                }
            },
            None => return Err(format!("No level identifier found at second position in dmesg entry: {}", line))
        };

        let timestamp_and_message: &str = match line_parts.next() {
            Some(third) => third.trim(),
            None => return Err(format!("No message found at third position in dmesg entry: {}", line))
        };

        if let Some(last) = line_parts.next() {
            return Err(format!("This dmesg entry should have broken into three parts (facility, level, message), but found at least a fourth part: {}\nOriginal Line: {}", last, line))
        }

        // At this level, we split: 
        // [174297.359257] docker0: port 2(veth51d1953) entered disabled state
        // into: <[174297.359257], docker0: port 2(veth51d1953) entered disabled state>
        let mut timestamp_and_message_parts = timestamp_and_message.splitn(2,"]");
        let timestamp: f64 = match timestamp_and_message_parts.next() {
            Some(first) => {
                let mut firstparts = first.splitn(2, "[");
                firstparts.next();
                match firstparts.next() {
                    Some(numerical_string) => match numerical_string.trim().parse::<f64>() {
                        Ok(t) => t,
                        Err(e) => return Err(format!("Unable to parse timestamp {} into a floating point number: {}", numerical_string, e))
                    },
                    None => return Err(format!("Unable to isolate timestamp from {}.\nComplete line: {}", first, line))
                }
            },
            None => return Err(format!("No [timestamp] found in dmesg entry: {}", line))
        };

        let message: String = match timestamp_and_message_parts.next() {
            Some(first) => first.to_owned(),
            None => return Err(format!("Unable to any text after timestamp in line: {}", line))
        };

        if let Some(last) = timestamp_and_message_parts.next() {
            return Err(format!("This dmesg entry should have broken into four parts (facility, level, timestamp, message), but found at least a fifth part: {}\nOriginal Line: {}", last, line))
        }

        Ok(DmesgEntry {
            facility,
            level,
            timestamp,
            message,
        })

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



