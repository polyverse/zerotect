// Strum contains all the trait definitions
extern crate regex;
extern crate num;

use regex::Regex;
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

#[derive(PartialEq)]
#[derive(Debug)]
struct DmesgEntry {
    info: events::EventInfo,
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
    for event in DMesgParser::from_dmesg_iterator(DMesgPoller::with_poll_settings(poll_interval, &dmesg_location, &args)) {
        if let Err(e) = sink.send(event) {
            eprintln!("Monitor: Error occurred sending events. Receipent is dead. Closing monitor. Error: {}", e);
            return;
        }
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
    fn with_poll_settings(poll_interval: time::Duration, dmesg_location: &String, args: &Vec<String>) -> DMesgPoller {
        DMesgPoller {
            poll_interval,
            dmesg_location: dmesg_location.clone(),
            args: args.clone(),
            last_timestamp: 0.0,
            queue: Vec::new(),
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
                            match self.parse_dmesg_entries(messages.as_str()) {
                                Ok(dmesg_entries) => {
                                    for dmesg_entry in dmesg_entries.into_iter() {
                                        if dmesg_entry.info.timestamp > self.last_timestamp {
                                            self.last_timestamp = dmesg_entry.info.timestamp;
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
        lazy_static! {
            //This regex looks for this format across multiple lines:
            //kern  :info  : [174297.359257] <rest of the message>
            static ref RE1: Regex = Regex::new(r"(?mx)(^
                # the log facility (may have whitespace around it, followed by a colon)
                [[:space:]]*(?P<facility>[[:alpha:]]*)[[:space:]]*: 
                # log level (may have whitespace around it, followed by a colon)
                [[:space:]]*(?P<level>[[:alpha:]]*)[[:space:]]*:
                # [timestamp] enclosed in square brackets (may have whitespace preceeding it)
                [[:space:]]*[\[](?P<timestamp>[[:digit:]]*\.[[:digit:]]*)[\]]
                # message gobbles up everything left
                (?P<message>.*)
                # close out the line
                $)").unwrap();
        }
        let mut dmesg_entries: Vec<DmesgEntry> = vec![];

        for line_parts in RE1.captures_iter(dmesg_output) {
            if let (Some(facility), Some(level), Some(timestamp)) = 
            (parse_fragment::<events::LogFacility>(&line_parts["facility"]), 
            parse_fragment::<events::LogLevel>(&line_parts["level"]), 
            parse_fragment::<f64>(&line_parts["timestamp"])) {
                dmesg_entries.push(DmesgEntry{
                    info: events::EventInfo {
                        facility,
                        level,
                        timestamp,
                    },
                    message: line_parts["message"].to_owned(),
                });
            } 
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
    dmesg_iter: T,
}

impl<T> DMesgParser<T>
where T: Iterator<Item = DmesgEntry>  {
    fn from_dmesg_iterator(dmesg_iter: T) -> DMesgParser<T> { 
            DMesgParser {
                dmesg_iter,
            }
    }

    fn parse_next_event(&mut self) -> Result<events::Event, String> {
        // find the next event (we don't use a for loop because we don't want to move
        // the iterator outside of self. We only want to move next() values out of the iterator.
        loop {
            let maybe_dmesg_entry = self.dmesg_iter.next();
            match maybe_dmesg_entry {
                Some(dmesg_entry) => {
                    if let Some(e) = self.parse_kernel_trap(dmesg_entry) {
                        return Ok(e);
                    }
                },
                None => break
            }
        }

        Err("Exited dmesg iterator unexpectedly.".to_owned())
    }

    // Parsing based on: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/traps.c#n230
    // Parses this basic structure: 
    // a.out[33629]: <some text> ip 0000556b4c03c603 sp 00007ffe55496510 error 4 in a.out[556b4c03c000+1000]
    fn parse_kernel_trap(&mut self, dmesg_entry: DmesgEntry) -> Option<events::Event> {
       lazy_static! {
            static ref RE: Regex = Regex::new(r"(?x)^
                # the procname (may have whitespace around it),
                [[:space:]]*(?P<procname>[^\[]*)
                # followed by a [pid])
                [\[](?P<pid>[[:xdigit:]]*)[\]][[:space:]]*:
                # gobble up everything until the word 'ip'
                (?P<message>.+?)
                # ip <ip>
                [[:space:]]*ip[[:space:]]*(?P<ip>([[:xdigit:]]*|\(null\)))
                # sp <sp>
                [[:space:]]*sp[[:space:]]*(?P<sp>([[:xdigit:]]*|\(null\)))
                # error <errcode>
                [[:space:]]*error[[:space:]]*(?P<errcode>[[:digit:]]*)
                # in <file>[<vmastart>+<vmasize>]
                [[:space:]]*in[[:space:]]*(?P<file>[^\[]*)[\[](?P<vmastart>[[:xdigit:]]*)\+(?P<vmasize>[[:xdigit:]]*)[\]]
                [[:space:]]*$").unwrap();
       }

        if let Some(dmesg_parts) = RE.captures(dmesg_entry.message.as_str()) {
            if let (procname, Some(pid), Some(trap), Some(ip), Some(sp), Some(errcode), file, Some(vmastart), Some(vmasize)) = 
            (&dmesg_parts["procname"], parse_fragment::<usize>(&dmesg_parts["pid"]), self.parse_kernel_trap_type(&dmesg_parts["message"]), 
            parse_hex::<usize>(&dmesg_parts["ip"]), parse_hex::<usize>(&dmesg_parts["sp"]), parse_hex::<u8>(&dmesg_parts["errcode"]), &dmesg_parts["file"], 
            parse_hex::<usize>(&dmesg_parts["vmastart"]), parse_hex::<usize>(&dmesg_parts["vmasize"])) {
                return Some(events::Event::KernelTrap(dmesg_entry.info, events::KernelTrapInfo{
                    trap,
                    procname: procname.to_owned(),
                    pid,
                    ip: ip,
                    sp: sp,
                    errcode: events::SegfaultErrorCode::from_error_code(errcode),
                    file: file.to_owned(),
                    vmastart: vmastart,
                    vmasize: vmasize,
                }));
            } 
        };
        None
    }

        // Parsing based on: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/traps.c#n230
    // Parses this basic structure: 
    // a.out[33629]: <some text> ip 0000556b4c03c603 sp 00007ffe55496510 error 4 in a.out[556b4c03c000+1000]
    fn parse_kernel_trap_type(&mut self, trap_string: &str) -> Option<events::KernelTrapType> {
        lazy_static! {
            static ref RE_SEGFAULT: Regex = Regex::new(r"(?x)^
                [[:space:]]*
                segfault[[:space:]]*at[[:space:]]*(?P<location>[[:xdigit:]])
                [[:space:]]*$").unwrap();

            static ref RE_INVALID_OPCODE: Regex = Regex::new(r"(?x)^[[:space:]]*trap[[:space:]]*invalid[[:space:]]*opcode[[:space:]]*$").unwrap();
        }

        if let Some(segfault_parts) = RE_SEGFAULT.captures(trap_string) {
            if let Some(location) = parse_hex::<usize>(&segfault_parts["location"]) {
                return Some(events::KernelTrapType::Segfault(location))
            }
        } else if RE_INVALID_OPCODE.is_match(trap_string) {
            return Some(events::KernelTrapType::InvalidOpcode)
        }

        None
    }

    // Parses this
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
    fn parse_fatal_signal_11() {

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

fn parse_fragment<T: FromStr + typename::TypeName>(frag: &str) -> Option<T> 
where <T as std::str::FromStr>::Err: std::fmt::Display
{
    match frag.parse::<T>() {
        Ok(f) => Some(f),
        Err(e) => {
            eprintln!("Unable to parse {} into {}: {}", frag, T::type_name(), e);
            None
        }
    }
}

fn parse_hex<N: num::Num + typename::TypeName>(frag: &str) -> Option<N>
where <N as num::Num>::FromStrRadixErr: std::fmt::Display
{
    // special case
    if frag == "(null)" {
        return Some(N::zero());
    };

    match N::from_str_radix(frag, 16) {
        Ok(n) => Some(n),
        Err(e) => {
            eprintln!("Unable to parse {} into {}: {}", frag, N::type_name(), e);
            None
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
            info: events::EventInfo{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Info,
                timestamp: 372850.968943,
            },
            message: String::from(" a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
        });

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_some());
        let entry = maybe_entry.unwrap();
        assert_eq!(entry, &DmesgEntry{
            info: events::EventInfo{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                timestamp: 372850.97,
            },
            message: String::from(" a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
        });

        let maybe_entry = iter.next();
        assert!(maybe_entry.is_none());
    }

    #[test]
    fn can_parse_kernel_trap_segfault() {
        let dmesgs = vec![
            DmesgEntry{
                info: events::EventInfo{
                    facility: events::LogFacility::Kern,
                    level: events::LogLevel::Warning,
                    timestamp: 372850.97,
                },
                message: String::from(" a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
            },
            DmesgEntry{
                info: events::EventInfo{
                    facility: events::LogFacility::Kern,
                    level: events::LogLevel::Warning,
                    timestamp: 372850.97,
                },
                message: String::from(" a.out[36075]: segfault at 0 ip (null) sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
            },
        ];

        let mut parser = DMesgParser::from_dmesg_iterator(dmesgs.into_iter());

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, events::Event::KernelTrap(events::EventInfo{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                timestamp: 372850.97,
            },
            events::KernelTrapInfo{
                trap: events::KernelTrapType::Segfault(0),
                procname: String::from("a.out"),
                pid: 36075,
                ip: 0x0000561bc8d8f12e,
                sp: 0x00007ffd5833d0c0,
                errcode: events::SegfaultErrorCode{
                    reason: events::SegfaultReason::NoPageFound,
                    access_type: events::SegfaultAccessType::Read,
                    access_mode: events::SegfaultAccessMode::User,
                    use_of_reserved_bit: false,
                    instruction_fetch: false,
                    protection_keys_block_access: false,
                },
                file: String::from("a.out"),
                vmastart: 0x561bc8d8f000,
                vmasize: 0x1000,
            }));

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, events::Event::KernelTrap(events::EventInfo{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                timestamp: 372850.97,
            },
            events::KernelTrapInfo{
                trap: events::KernelTrapType::Segfault(0),
                procname: String::from("a.out"),
                pid: 36075,
                ip: 0x0,
                sp: 0x00007ffd5833d0c0,
                errcode: events::SegfaultErrorCode{
                    reason: events::SegfaultReason::NoPageFound,
                    access_type: events::SegfaultAccessType::Read,
                    access_mode: events::SegfaultAccessMode::User,
                    use_of_reserved_bit: false,
                    instruction_fetch: false,
                    protection_keys_block_access: false,
                },
                file: String::from("a.out"),
                vmastart: 0x561bc8d8f000,
                vmasize: 0x1000,
            }));

    }
}
/**********************************************************************************/
