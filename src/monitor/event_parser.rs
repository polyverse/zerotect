// Copyright (c) 2019 Polyverse Corporation

use crate::common;
use crate::events;
use crate::monitor::kmsg;

use num::FromPrimitive;
use regex::Regex;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::Arc;
use std::time::Duration;

use timeout_iterator::TimeoutIterator;

#[derive(Debug)]
pub struct EventParserError(String);
impl Error for EventParserError {}
impl Display for EventParserError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "EventParserError:: {}", &self.0)
    }
}
impl From<timeout_iterator::TimeoutIteratorError> for EventParserError {
    fn from(err: timeout_iterator::TimeoutIteratorError) -> EventParserError {
        EventParserError(format!(
            "Inner timeout_iterator::TimeoutIteratorError :: {}",
            err
        ))
    }
}

pub struct EventParser {
    timeout_kmsg_iter: TimeoutIterator<kmsg::KMsgPtr>,
    flush_timeout: Duration,
    verbosity: u8,
    hostname: Option<String>,
}

impl EventParser {
    pub fn from_kmsg_iterator(
        kmsg_iter: Box<dyn Iterator<Item = kmsg::KMsgPtr> + Send>,
        flush_timeout: Duration,
        verbosity: u8,
        hostname: Option<String>,
    ) -> Result<EventParser, EventParserError> {
        let timeout_kmsg_iter = TimeoutIterator::from_item_iterator(kmsg_iter)?;

        Ok(EventParser {
            timeout_kmsg_iter,
            flush_timeout,
            verbosity,
            hostname,
        })
    }

    fn parse_next_event(&mut self) -> Result<events::Version, EventParserError> {
        // we'll need to borrow and capture this in closures multiple times.
        // Make a one-time clone so we don't borrow self over and over again.
        let hostname = self.hostname.clone();

        // find the next event (we don't use a for loop because we don't want to move
        // the iterator outside of self. We only want to move next() values out of the iterator.
        loop {
            if let Some(kmsg_entry) = self.timeout_kmsg_iter.next() {
                if let Some(e) = EventParser::parse_finite_kmsg_to_event(&kmsg_entry, &hostname)
                    .or_else(|| self.parse_fatal_signal(&kmsg_entry, &hostname))
                {
                    return Ok(e);
                }
            // only break if the underlying iterator quit on us
            } else {
                return Err(EventParserError(
                    "Exited /dev/kmsg iterator unexpectedly.".to_owned(),
                ));
            }
        }
    }

    fn parse_finite_kmsg_to_event(
        kmsg_entry: &kmsg::KMsg,
        hostname: &Option<String>,
    ) -> Option<events::Version> {
        EventParser::parse_callbacks_suppressed(kmsg_entry, hostname)
            .or_else(|| EventParser::parse_kernel_trap(kmsg_entry, hostname))
    }

    // Parsing based on: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/traps.c#n230
    // Parses this basic structure:
    // ====>> a.out[33629]: <some text> ip 0000556b4c03c603 sp 00007ffe55496510 error 4
    // OR
    // NOTE: 'traps:' may or may not exist
    // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/traps.c#n142
    // ====>> traps: nginx[67494] general protection ip:43bbbc sp:7ffdd4474db0 error:0 in nginx[400000+92000]
    // Optionally followed by
    // ====>>  in a.out[556b4c03c000+1000]
    fn parse_kernel_trap(km: &kmsg::KMsg, hostname: &Option<String>) -> Option<events::Version> {
        lazy_static! {
            static ref RE_WITHOUT_LOCATION: Regex = Regex::new(r"(?x)^
                # start with any number of spaces or 'traps:'
                [[:space:]]*
                (?:traps:|[[:space:]]*)
                [[:space:]]*
                # the procname,
                (?P<procname>[^\[]*)
                # followed by a [pid])
                [\[](?P<pid>[[:xdigit:]]*)[\]]
                # after pid either a : and spaces or spaces
                (:[[:space:]]*|[[:space:]]*)
                # gobble up any messages everything until the word 'ip'
                (?P<message>.+?)
                # ip <ip> OR ip:<ip>
                [[:space:]]*ip(?::|[[:space:]]*)(?P<ip>([[:xdigit:]]*|\(null\)))
                # sp <sp> OR sp:<sp>
                [[:space:]]*sp(?::|[[:space:]]*)(?P<sp>([[:xdigit:]]*|\(null\)))
                # error <errcode> OR error:<errcode>
                [[:space:]]*error(?::|[[:space:]]*)(?P<errcode>[[:digit:]]*)
                (?P<maybelocation>.*)$").unwrap();

            static ref RE_LOCATION: Regex = Regex::new(r"(?x)^
                [[:space:]]*in[[:space:]]*(?P<file>[^\[]*)[\[](?P<vmastart>[[:xdigit:]]*)\+(?P<vmasize>[[:xdigit:]]*)[\]]
                [[:space:]]*$").unwrap();

        }

        if let Some(dmesg_parts) = RE_WITHOUT_LOCATION.captures(km.message.as_str()) {
            if let (
                procname,
                Some(pid),
                Some(trap),
                Some(ip),
                Some(sp),
                Some(errcode),
                maybelocation,
            ) = (
                &dmesg_parts["procname"],
                common::parse_fragment::<usize>(&dmesg_parts["pid"]),
                EventParser::parse_kernel_trap_type(&dmesg_parts["message"]),
                common::parse_hex::<usize>(&dmesg_parts["ip"]),
                common::parse_hex::<usize>(&dmesg_parts["sp"]),
                common::parse_hex::<usize>(&dmesg_parts["errcode"]),
                &dmesg_parts["maybelocation"],
            ) {
                let (file, vmastart, vmasize) =
                    if let Some(location_parts) = RE_LOCATION.captures(maybelocation) {
                        (
                            Some((&location_parts["file"]).to_owned()),
                            common::parse_hex::<usize>(&location_parts["vmastart"]),
                            common::parse_hex::<usize>(&location_parts["vmasize"]),
                        )
                    } else {
                        (None, None, None)
                    };

                return Some(events::Version::V1 {
                    timestamp: km.timestamp,
                    hostname: hostname.clone(),
                    event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                        facility: km.facility,
                        level: km.level,
                        trap,
                        procname: procname.to_owned(),
                        pid,
                        ip,
                        sp,
                        errcode: events::SegfaultErrorCode::from_error_code(errcode),
                        file,
                        vmastart,
                        vmasize,
                    }),
                });
            }
        };

        None
    }

    // Parsing based on: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/traps.c#n230
    // Parses this basic structure:
    // a.out[33629]: <some text> ip 0000556b4c03c603 sp 00007ffe55496510 error 4 in a.out[556b4c03c000+1000]
    fn parse_kernel_trap_type(trap_string: &str) -> Option<events::KernelTrapType> {
        lazy_static! {
            static ref RE_SEGFAULT: Regex = Regex::new(
                r"(?x)^
                [[:space:]]*
                segfault[[:space:]]*at[[:space:]]*(?P<location>[[:xdigit:]]*)
                [[:space:]]*$"
            )
            .unwrap();
            static ref RE_INVALID_OPCODE: Regex = Regex::new(
                r"(?x)^[[:space:]]*trap[[:space:]]*invalid[[:space:]]*opcode[[:space:]]*$"
            )
            .unwrap();
            static ref RE_GENERAL_PROTECTION: Regex =
                Regex::new(r"(?x)^[[:space:]]*general[[:space:]]*protection[[:space:]]*$").unwrap();
        }

        if let Some(segfault_parts) = RE_SEGFAULT.captures(trap_string) {
            if let Some(location) = common::parse_hex::<usize>(&segfault_parts["location"]) {
                Some(events::KernelTrapType::Segfault { location })
            } else {
                eprintln!("Reporting segfault as a generic kernel trap because {} couldn't be parsed as a hexadecimal.", &segfault_parts["location"]);
                Some(events::KernelTrapType::Generic {
                    description: trap_string.trim().to_owned(),
                })
            }
        } else if RE_INVALID_OPCODE.is_match(trap_string) {
            Some(events::KernelTrapType::InvalidOpcode)
        } else if RE_GENERAL_PROTECTION.is_match(trap_string) {
            Some(events::KernelTrapType::GeneralProtectionFault)
        } else {
            Some(events::KernelTrapType::Generic {
                description: trap_string.trim().to_owned(),
            })
        }
    }

    // Parses this
    // We have this entry, enabled by kernel.print-fatal-signals
    // Signal Printed here: https://github.com/torvalds/linux/blob/master/kernel/signal.c#L1239
    // ---------------------------------------------------------------
    // potentially unexpected fatal signal 11.
    fn parse_fatal_signal(
        &mut self,
        km: &kmsg::KMsg,
        hostname: &Option<String>,
    ) -> Option<events::Version> {
        lazy_static! {
            static ref RE_FATAL_SIGNAL: Regex = Regex::new(r"(?x)^[[:space:]]*potentially[[:space:]]*unexpected[[:space:]]*fatal[[:space:]]*signal[[:space:]]*(?P<signalnumstr>[[:digit:]]*).*$").unwrap();
        }
        if let Some(fatal_signal_parts) = RE_FATAL_SIGNAL.captures(km.message.as_str()) {
            if let Some(signalnum) =
                common::parse_fragment::<u8>(&fatal_signal_parts["signalnumstr"])
            {
                if let Some(signal) = events::FatalSignalType::from_u8(signalnum) {
                    return Some(events::Version::V1 {
                        timestamp: km.timestamp,
                        hostname: hostname.clone(),
                        event: events::EventType::LinuxFatalSignal(events::LinuxFatalSignal {
                            facility: km.facility,
                            level: km.level,
                            signal,
                            stack_dump: self.parse_stack_dump(hostname),
                        }),
                    });
                } else {
                    eprintln!(
                        "Unable to fatal signal number {} into known enumeration.",
                        signalnum
                    );
                    return None;
                }
            } else {
                eprintln!(
                    "Unable to parse fatal signal integer from {}",
                    &fatal_signal_parts["signalnumstr"]
                );
                return None;
            }
        };

        None
    }

    // Parses this whole segment which may follow a fatal signal
    // Next two lines printed here: https://github.com/torvalds/linux/blob/6f0d349d922ba44e4348a17a78ea51b7135965b1/lib/dump_stack.c#L45
    // ---------------------------------------------------------------
    // Then the regs are architecture-specific
    // CPU: 1 PID: 36075 Comm: a.out Not tainted 4.14.131-linuxkit #1
    // Hardware name:  BHYVE, BIOS 1.00 03/14/2014
    // task: ffff9b08f2e1c3c0 task.stack: ffffb493c0e98000
    // RIP: 0033:0x561bc8d8f12e
    // RSP: 002b:00007ffd5833d0c0 EFLAGS: 00010246
    // RAX: 0000000000000000 RBX: 0000000000000000 RCX: 00007fd15e0e0718
    // RDX: 00007ffd5833d1b8 RSI: 00007ffd5833d1a8 RDI: 0000000000000001
    // RBP: 00007ffd5833d0c0 R08: 00007fd15e0e1d80 R09: 00007fd15e0e1d80
    // R10: 0000000000000000 R11: 0000000000000000 R12: 0000561bc8d8f040
    // R13: 00007ffd5833d1a0 R14: 0000000000000000 R15: 0000000000000000
    // FS:  00007fd15e0e7500(0000) GS:ffff9b08ffd00000(0000) knlGS:0000000000000000
    // CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
    // CR2: 0000000000000000 CR3: 0000000132d26005 CR4: 00000000000606a0
    fn parse_stack_dump(&mut self, hostname: &Option<String>) -> BTreeMap<String, String> {
        // Not implemented
        let mut sd = BTreeMap::<String, String>::new();

        // the various branches of the loop will terminate...
        loop {
            let maybe_peek_msg = self.timeout_kmsg_iter.peek_timeout(self.flush_timeout);
            // peek next line, and if it has a colon, take it
            let km = match maybe_peek_msg {
                Ok(peek_kmsg) => {
                    // is next message possibly a finite event? Like a kernel trap?
                    // if so, don't consume it and end this KV madness
                    if EventParser::parse_finite_kmsg_to_event(peek_kmsg, hostname).is_some() {
                        return sd;
                    }

                    if !peek_kmsg.message.contains(':') {
                        // if no ":", then this isn't part of all the KV pairs
                        return sd;
                    } else {
                        self.timeout_kmsg_iter.next().unwrap()
                    }
                }
                // if error peeking, return what we have...
                // error might be a timeout or something else.
                Err(_) => return sd,
            };

            // now operate on the owned KMsg line
            // since all other paths have exited

            // split message parts on whitespace
            let parts: Vec<_> = km.message.split(|c| c == ' ').collect();

            // consume kmsg key->value one by one (don't split all at once)
            // maintain state as we iterate
            let mut key: Option<String> = None;
            let mut value: Option<String> = None;
            for part in parts {
                // this word is part of the next key,
                // first handle any k/vs we already have (if any)
                if let Some(part_without_colon) = part.strip_suffix(':') {
                    // if there's a value, let's publish it before transitioning to new key
                    if let Some(v) = value {
                        if let Some(k) = key {
                            if self.verbosity > 1 {
                                eprintln!("Monitor:: parse_stack_dump:: Adding K/V pair: ({}, {}). Log Line: {}", &k, &v, km.message);
                            }
                            sd.insert(k, v);
                        } else if self.verbosity > 0 {
                            eprintln!("Monitor:: parse_stack_dump:: For this line, transitioned to value without a key. Some data might not be parsed. Log Line: {}", km.message);
                        }

                        // Key becomes this part, minus the :
                        key = Some(part_without_colon.to_owned());
                    } else {
                        let appended_key = match key {
                            Some(mut ks) => {
                                if ks != "" {
                                    ks.push(' ')
                                };
                                ks.push_str(part_without_colon);
                                ks
                            }
                            None => part_without_colon.to_owned(),
                        };
                        key = Some(appended_key);
                    }

                    // start a blank value - with the colon, anything that comes after is a value
                    value = Some(String::new());
                } else {
                    // are we in a value? if so append to it
                    if let Some(mut v) = value {
                        if v != "" {
                            v.push(' ')
                        };
                        v.push_str(part);
                        value = Some(v);
                    } else if let Some(mut k) = key {
                        if k != "" {
                            k.push(' ')
                        };
                        k.push_str(part);
                        key = Some(k);
                    } else if key == None {
                        key = Some(part.to_owned());
                    }
                }
            }

            // cleanup last value - if it comes in a pair
            if let (Some(k), Some(v)) = (key, value) {
                if self.verbosity > 1 {
                    eprintln!("Monitor:: parse_stack_dump:: Adding Final K/V pair: ({}, {}). Log Line: {}", &k, &v, km.message);
                }
                sd.insert(k, v);
            }
        }
    }

    // Parsing based on: https://github.com/torvalds/linux/blob/9331b6740f86163908de69f4008e434fe0c27691/lib/ratelimit.c#L51
    // Parses this basic structure:
    // ====> <function name>: 9 callbacks suppressed
    fn parse_callbacks_suppressed(
        km: &kmsg::KMsg,
        hostname: &Option<String>,
    ) -> Option<events::Version> {
        lazy_static! {
            static ref RE_CALLBACKS_SUPPRESSED: Regex = Regex::new(
                r"(?x)^
                 # the function name (may have whitespace around it),
                 [[:space:]]*(?P<function>[^:]*):[[:space:]]*
                 # followed by a [number])
                 (?P<count>[[:digit:]]*)
                 # the literal 'callbacks suppressed'
                 [[:space:]]*callbacks[[:space:]]*suppressed[[:space:]]*$"
            )
            .unwrap();
        }

        if let Some(dmesg_parts) = RE_CALLBACKS_SUPPRESSED.captures(km.message.as_str()) {
            if let (function_name, Some(count)) = (
                &dmesg_parts["function"],
                common::parse_fragment::<usize>(&dmesg_parts["count"]),
            ) {
                return Some(events::Version::V1 {
                    timestamp: km.timestamp,
                    hostname: hostname.clone(),
                    event: events::EventType::LinuxSuppressedCallback(
                        events::LinuxSuppressedCallback {
                            facility: km.facility,
                            level: km.level,
                            function_name: function_name.to_owned(),
                            count,
                        },
                    ),
                });
            }
        };

        None
    }
}

impl Iterator for EventParser {
    // we will be counting with usize
    type Item = events::Event;

    // next() is the only required method
    fn next(&mut self) -> Option<Self::Item> {
        match self.parse_next_event() {
            Ok(version) => Some(Arc::new(version)),
            Err(err) => {
                eprintln!(
                    "Monitor: Error iterating over events from the dmesg parser: {}",
                    err
                );
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
    use chrono::{TimeZone, Utc};
    use pretty_assertions::assert_eq;
    use serde_json::{from_str, to_value};
    use std::thread;

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
    fn can_parse_kernel_trap_segfault() {
        let timestamp = Utc.timestamp_millis(378084605);
        let kmsgs = boxed_kmsgs(timestamp,
                vec![
                    String::from(" a.out[36175]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
                    String::from(" a.out[36275]: segfault at 0 ip (null) sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
                    String::from("a.out[37659]: segfault at 7fff4b8ba8b8 ip 00007fff4b8ba8b8 sp 00007fff4b8ba7b8 error 15"),
                ]);

        let event1 = Arc::new(events::Version::V1 {
            timestamp,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                trap: events::KernelTrapType::Segfault { location: 0 },
                procname: String::from("a.out"),
                pid: 36175,
                ip: 0x0000561bc8d8f12e,
                sp: 0x00007ffd5833d0c0,
                errcode: events::SegfaultErrorCode {
                    reason: events::SegfaultReason::NoPageFound,
                    access_type: events::SegfaultAccessType::Read,
                    access_mode: events::SegfaultAccessMode::User,
                    use_of_reserved_bit: false,
                    instruction_fetch: false,
                    protection_keys_block_access: false,
                },
                file: Some(String::from("a.out")),
                vmastart: Some(0x561bc8d8f000),
                vmasize: Some(0x1000),
            }),
        });

        let event2 = Arc::new(events::Version::V1 {
            timestamp,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                trap: events::KernelTrapType::Segfault { location: 0 },
                procname: String::from("a.out"),
                pid: 36275,
                ip: 0x0,
                sp: 0x00007ffd5833d0c0,
                errcode: events::SegfaultErrorCode {
                    reason: events::SegfaultReason::NoPageFound,
                    access_type: events::SegfaultAccessType::Read,
                    access_mode: events::SegfaultAccessMode::User,
                    use_of_reserved_bit: false,
                    instruction_fetch: false,
                    protection_keys_block_access: false,
                },
                file: Some(String::from("a.out")),
                vmastart: Some(0x561bc8d8f000),
                vmasize: Some(0x1000),
            }),
        });

        let event3 = Arc::new(events::Version::V1 {
            timestamp,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                trap: events::KernelTrapType::Segfault {
                    location: 0x7fff4b8ba8b8,
                },
                procname: String::from("a.out"),
                pid: 37659,
                ip: 0x7fff4b8ba8b8,
                sp: 0x00007fff4b8ba7b8,
                errcode: events::SegfaultErrorCode {
                    reason: events::SegfaultReason::ProtectionFault,
                    access_type: events::SegfaultAccessType::Read,
                    access_mode: events::SegfaultAccessMode::User,
                    use_of_reserved_bit: false,
                    instruction_fetch: true,
                    protection_keys_block_access: false,
                },
                file: None,
                vmastart: None,
                vmasize: None,
            }),
        });

        let mut parser =
            EventParser::from_kmsg_iterator(Box::new(kmsgs.into_iter()), Duration::from_secs(1), 0)
                .unwrap();

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event1);

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event2);

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event3);

        assert_eq!(
            to_value(&event1).unwrap(),
            from_str::<serde_json::Value>(
                r#"{
                "version": "V1",
                "timestamp": "1970-01-05T09:01:24.605Z",
                "event": {
                    "type": "LinuxKernelTrap",
                    "facility": "Kern",
                    "level": "Warning",
                    "trap": {
                        "type": "Segfault",
                        "location": 0
                    },
                    "procname": "a.out",
                    "pid": 36175,
                    "ip": 94677333766446,
                    "sp": 140726083244224,
                    "errcode": {
                        "reason": "NoPageFound",
                        "access_type": "Read",
                        "access_mode": "User",
                        "use_of_reserved_bit": false,
                        "instruction_fetch": false,
                        "protection_keys_block_access": false
                    },
                    "file": "a.out",
                    "vmasize": 4096,
                    "vmastart": 94677333766144
                }
            }"#
            )
            .unwrap()
        );
        assert_eq!(
            to_value(&event2).unwrap(),
            from_str::<serde_json::Value>(
                r#"{
                "version": "V1",
                "timestamp": "1970-01-05T09:01:24.605Z",
                "event": {
                    "type": "LinuxKernelTrap",
                    "facility": "Kern",
                    "level": "Warning",
                    "trap": {
                        "type": "Segfault",
                        "location": 0
                    },
                    "procname": "a.out",
                    "pid": 36275,
                    "ip": 0,
                    "sp": 140726083244224,
                    "errcode": {
                        "reason": "NoPageFound",
                        "access_type": "Read",
                        "access_mode": "User",
                        "use_of_reserved_bit": false,
                        "instruction_fetch": false,
                        "protection_keys_block_access": false
                    },
                    "file": "a.out",
                    "vmastart": 94677333766144,
                    "vmasize": 4096
                }
            }"#
            )
            .unwrap()
        );
        assert_eq!(
            to_value(&event3).unwrap(),
            from_str::<serde_json::Value>(
                r#"{
                "version": "V1",
                "timestamp": "1970-01-05T09:01:24.605Z",
                "event": {
                    "type": "LinuxKernelTrap",
                    "facility": "Kern",
                    "level": "Warning",
                    "trap": {
                        "type": "Segfault",
                        "location": 140734460831928
                    },
                    "procname": "a.out",
                    "pid": 37659,
                    "ip": 140734460831928,
                    "sp": 140734460831672,
                    "errcode": {
                        "reason": "ProtectionFault",
                        "access_type": "Read",
                        "access_mode": "User",
                        "use_of_reserved_bit": false,
                        "instruction_fetch": true,
                        "protection_keys_block_access": false
                    },
                    "file": null,
                    "vmasize": null,
                    "vmastart": null
                }
            }"#
            )
            .unwrap()
        );
    }

    #[test]
    fn can_parse_kernel_trap_invalid_opcode() {
        let timestamp = Utc.timestamp_millis(5606197845);

        let kmsgs = boxed_kmsgs(timestamp,
            vec![
                String::from(" a.out[38175]: trap invalid opcode ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
                String::from(" a.out[38275]: trap invalid opcode ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4"),
            ]);

        let event1 = Arc::new(events::Version::V1 {
            timestamp,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                trap: events::KernelTrapType::InvalidOpcode,
                procname: String::from("a.out"),
                pid: 38175,
                ip: 0x0000561bc8d8f12e,
                sp: 0x00007ffd5833d0c0,
                errcode: events::SegfaultErrorCode {
                    reason: events::SegfaultReason::NoPageFound,
                    access_type: events::SegfaultAccessType::Read,
                    access_mode: events::SegfaultAccessMode::User,
                    use_of_reserved_bit: false,
                    instruction_fetch: false,
                    protection_keys_block_access: false,
                },
                file: Some(String::from("a.out")),
                vmastart: Some(0x561bc8d8f000),
                vmasize: Some(0x1000),
            }),
        });

        let event2 = Arc::new(events::Version::V1 {
            timestamp,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                trap: events::KernelTrapType::InvalidOpcode,
                procname: String::from("a.out"),
                pid: 38275,
                ip: 0x0000561bc8d8f12e,
                sp: 0x00007ffd5833d0c0,
                errcode: events::SegfaultErrorCode {
                    reason: events::SegfaultReason::NoPageFound,
                    access_type: events::SegfaultAccessType::Read,
                    access_mode: events::SegfaultAccessMode::User,
                    use_of_reserved_bit: false,
                    instruction_fetch: false,
                    protection_keys_block_access: false,
                },
                file: None,
                vmastart: None,
                vmasize: None,
            }),
        });

        let mut parser =
            EventParser::from_kmsg_iterator(Box::new(kmsgs.into_iter()), Duration::from_secs(1), 0)
                .unwrap();

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event1);

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event2);

        assert_eq!(
            to_value(&event1).unwrap(),
            from_str::<serde_json::Value>(
                r#"{
                "version": "V1",
                "timestamp": "1970-03-06T21:16:37.845Z",
                "event": {
                    "type": "LinuxKernelTrap",
                    "facility": "Kern",
                    "level": "Warning",
                    "trap": {
                        "type": "InvalidOpcode"
                    },
                    "procname": "a.out",
                    "pid": 38175,
                    "ip": 94677333766446,
                    "sp": 140726083244224,
                    "errcode": {
                        "reason": "NoPageFound",
                        "access_type": "Read",
                        "access_mode": "User",
                        "use_of_reserved_bit": false,
                        "instruction_fetch": false,
                        "protection_keys_block_access": false
                    },
                    "file": "a.out",
                    "vmastart": 94677333766144,
                    "vmasize": 4096
                }
            }"#
            )
            .unwrap()
        );
        assert_eq!(
            to_value(&event2).unwrap(),
            from_str::<serde_json::Value>(
                r#"{
                "version": "V1",
                "timestamp": "1970-03-06T21:16:37.845Z",
                "event": {
                    "type": "LinuxKernelTrap",
                    "facility": "Kern",
                    "level": "Warning",
                    "trap": {
                        "type": "InvalidOpcode"
                    },
                    "procname": "a.out",
                    "pid": 38275,
                    "ip": 94677333766446,
                    "sp": 140726083244224,
                    "errcode": {
                        "reason": "NoPageFound",
                        "access_type": "Read",
                        "access_mode": "User",
                        "use_of_reserved_bit": false,
                        "instruction_fetch": false,
                        "protection_keys_block_access": false
                    },
                    "file": null,
                    "vmastart": null,
                    "vmasize": null
                }
            }"#
            )
            .unwrap()
        );
    }

    #[test]
    fn can_parse_kernel_trap_generic() {
        let timestamp = Utc.timestamp_millis(471804323);

        let kmsgs = vec![
            boxed_kmsg(timestamp, String::from(" a.out[39175]: foo ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]")),
            boxed_kmsg(timestamp, String::from(" a.out[39275]: bar ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4")),
        ];

        let event1 = Arc::new(events::Version::V1 {
            timestamp,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                trap: events::KernelTrapType::Generic {
                    description: "foo".to_owned(),
                },
                procname: String::from("a.out"),
                pid: 39175,
                ip: 0x0000561bc8d8f12e,
                sp: 0x00007ffd5833d0c0,
                errcode: events::SegfaultErrorCode {
                    reason: events::SegfaultReason::NoPageFound,
                    access_type: events::SegfaultAccessType::Read,
                    access_mode: events::SegfaultAccessMode::User,
                    use_of_reserved_bit: false,
                    instruction_fetch: false,
                    protection_keys_block_access: false,
                },
                file: Some(String::from("a.out")),
                vmastart: Some(0x561bc8d8f000),
                vmasize: Some(0x1000),
            }),
        });

        let event2 = Arc::new(events::Version::V1 {
            timestamp,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                trap: events::KernelTrapType::Generic {
                    description: "bar".to_owned(),
                },
                procname: String::from("a.out"),
                pid: 39275,
                ip: 0x0000561bc8d8f12e,
                sp: 0x00007ffd5833d0c0,
                errcode: events::SegfaultErrorCode {
                    reason: events::SegfaultReason::NoPageFound,
                    access_type: events::SegfaultAccessType::Read,
                    access_mode: events::SegfaultAccessMode::User,
                    use_of_reserved_bit: false,
                    instruction_fetch: false,
                    protection_keys_block_access: false,
                },
                file: None,
                vmastart: None,
                vmasize: None,
            }),
        });

        let mut parser =
            EventParser::from_kmsg_iterator(Box::new(kmsgs.into_iter()), Duration::from_secs(1), 0)
                .unwrap();

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event1);

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event2);

        assert_eq!(
            to_value(&event1).unwrap(),
            from_str::<serde_json::Value>(
                r#"{
                "version": "V1",
                "timestamp": "1970-01-06T11:03:24.323Z",
                "event": {
                    "type": "LinuxKernelTrap",
                        "facility": "Kern",
                        "level": "Warning",
                        "trap": {
                            "type": "Generic",
                            "description": "foo"
                        },
                        "procname": "a.out",
                        "pid": 39175,
                        "ip": 94677333766446,
                        "sp": 140726083244224,
                        "errcode": {
                            "reason": "NoPageFound",
                            "access_type": "Read",
                            "access_mode": "User",
                            "use_of_reserved_bit": false,
                            "instruction_fetch": false,
                            "protection_keys_block_access": false
                        },
                        "vmastart": 94677333766144,
                        "file": "a.out",
                        "vmasize": 4096
                }
            }"#
            )
            .unwrap()
        );
        assert_eq!(
            to_value(&event2).unwrap(),
            from_str::<serde_json::Value>(
                r#"{
                "version": "V1",
                "timestamp": "1970-01-06T11:03:24.323Z",
                "event": {
                    "type": "LinuxKernelTrap",
                    "facility": "Kern",
                    "level": "Warning",
                    "trap": {
                        "type": "Generic",
                        "description": "bar"
                    },
                    "procname": "a.out",
                    "pid": 39275,
                    "ip": 94677333766446,
                    "sp": 140726083244224,
                    "errcode": {
                        "reason": "NoPageFound",
                        "access_type": "Read",
                        "access_mode": "User",
                        "use_of_reserved_bit": false,
                        "instruction_fetch": false,
                        "protection_keys_block_access": false
                    },
                    "vmastart": null,
                    "vmasize": null,
                    "file": null
                }
            }"#
            )
            .unwrap()
        );
    }

    #[test]
    fn can_parse_kernel_trap_general_protection() {
        let timestamp = Utc.timestamp_millis(378084605);
        let kmsgs = boxed_kmsgs(timestamp,
                vec![
                    String::from("traps: nginx[67494] general protection ip:43bbbc sp:7ffdd4474db0 error:0 in nginx[400000+92000]"),
                    String::from("  traps: nginx[67494] general protection ip:43bbbc sp:7ffdd4474db0 error:0 in nginx[400000+92000]"),
                    String::from(" traps:   nginx[67494] general protection ip:43bbbc sp:7ffdd4474db0 error:0 in nginx[400000+92000]"),
                    String::from(" nginx[67494] general protection ip:43bbbc sp:7ffdd4474db0 error:0 in nginx[400000+92000]"),
                    String::from("nginx[67494] general protection ip:43bbbc sp:7ffdd4474db0 error:0 in nginx[400000+92000]"),
                ]);

        let event1 = Arc::new(events::Version::V1 {
            timestamp,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                trap: events::KernelTrapType::GeneralProtectionFault,
                procname: String::from("nginx"),
                pid: 67494,
                ip: 0x43bbbc,
                sp: 0x7ffdd4474db0,
                errcode: events::SegfaultErrorCode {
                    reason: events::SegfaultReason::NoPageFound,
                    access_type: events::SegfaultAccessType::Read,
                    access_mode: events::SegfaultAccessMode::Kernel,
                    use_of_reserved_bit: false,
                    instruction_fetch: false,
                    protection_keys_block_access: false,
                },
                file: Some(String::from("nginx")),
                vmastart: Some(0x400000),
                vmasize: Some(0x92000),
            }),
        });

        let mut parser =
            EventParser::from_kmsg_iterator(Box::new(kmsgs.into_iter()), Duration::from_secs(1), 0)
                .unwrap();

        let maybe_gpf = parser.next();
        assert!(maybe_gpf.is_some());
        let gpf = maybe_gpf.unwrap();
        assert_eq!(gpf, event1);

        let maybe_gpf = parser.next();
        assert!(maybe_gpf.is_some());
        let gpf = maybe_gpf.unwrap();
        assert_eq!(gpf, event1);

        let maybe_gpf = parser.next();
        assert!(maybe_gpf.is_some());
        let gpf = maybe_gpf.unwrap();
        assert_eq!(gpf, event1);

        let maybe_gpf = parser.next();
        assert!(maybe_gpf.is_some());
        let gpf = maybe_gpf.unwrap();
        assert_eq!(gpf, event1);

        let maybe_gpf = parser.next();
        assert!(maybe_gpf.is_some());
        let gpf = maybe_gpf.unwrap();
        assert_eq!(gpf, event1);

        let maybe_gpf = parser.next();
        assert!(maybe_gpf.is_none());

        assert_eq!(
            to_value(&event1).unwrap(),
            from_str::<serde_json::Value>(
                r#"{
                "version": "V1",
                "timestamp": "1970-01-05T09:01:24.605Z",
                "event": {
                    "type": "LinuxKernelTrap",
                    "facility": "Kern",
                    "level": "Warning",
                    "trap": {
                        "type": "GeneralProtectionFault"
                    },
                    "procname": "nginx",
                    "pid": 67494,
                    "ip": 4438972,
                    "sp": 140728164896176,
                    "errcode": {
                        "reason": "NoPageFound",
                        "access_type": "Read",
                        "access_mode": "Kernel",
                        "use_of_reserved_bit": false,
                        "instruction_fetch": false,
                        "protection_keys_block_access": false
                    },
                    "file": "nginx",
                    "vmasize": 598016,
                    "vmastart": 4194304
                }
            }"#
            )
            .unwrap()
        );
    }

    #[test]
    fn can_parse_fatal_signal_optional_dump() {
        let timestamp = Utc.timestamp_millis(376087724);

        let kmsgs = vec![Box::new(kmsg::KMsg {
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Warning,
            timestamp,
            message: String::from("potentially unexpected fatal signal 11."),
        })];

        let mut parser =
            EventParser::from_kmsg_iterator(Box::new(kmsgs.into_iter()), Duration::from_secs(1), 0)
                .unwrap();
        let sig11 = parser.next();
        assert!(sig11.is_some());
        assert_eq!(
            sig11.unwrap(),
            Arc::new(events::Version::V1 {
                timestamp,
                event: events::EventType::LinuxFatalSignal(events::LinuxFatalSignal {
                    facility: events::LogFacility::Kern,
                    level: events::LogLevel::Warning,
                    signal: events::FatalSignalType::SIGSEGV,
                    stack_dump: BTreeMap::new(),
                }),
            })
        )
    }

    #[test]
    fn can_parse_fatal_signal_11() {
        let timestamp = Utc.timestamp_millis(6433742 + 372858970);
        let mut kmsgs = boxed_kmsgs(
            timestamp,
            vec![
                String::from("potentially unexpected fatal signal 11."),
                String::from("CPU: 1 PID: 36075 Comm: a.out Not tainted 4.14.131-linuxkit #1"),
                String::from("Hardware name:  BHYVE, BIOS 1.00 03/14/2014"),
                String::from("task: ffff9b08f2e1c3c0 task.stack: ffffb493c0e98000"),
                String::from("RIP: 0033:0x561bc8d8f12e"),
                String::from("RSP: 002b:00007ffd5833d0c0 EFLAGS: 00010246"),
                String::from("RAX: 0000000000000000 RBX: 0000000000000000 RCX: 00007fd15e0e0718"),
                String::from("RDX: 00007ffd5833d1b8 RSI: 00007ffd5833d1a8 RDI: 0000000000000001"),
                String::from("RBP: 00007ffd5833d0c0 R08: 00007fd15e0e1d80 R09: 00007fd15e0e1d80"),
                String::from("R10: 0000000000000000 R11: 0000000000000000 R12: 0000561bc8d8f040"),
                String::from("R13: 00007ffd5833d1a0 R14: 0000000000000000 R15: 0000000000000000"),
                String::from(
                    "FS:  00007fd15e0e7500(0000) GS:ffff9b08ffd00000(0000) knlGS:0000000000000000",
                ),
                String::from("CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033"),
                String::from("CR2: 0000000000000000 CR3: 0000000132d26005 CR4: 00000000000606a0"),
            ],
        );

        {
            // Validate when new kmsg's stop coming in (at timeout).
            let mut parser = EventParser::from_kmsg_iterator(
                Box::new(kmsgs.clone().into_iter()),
                Duration::from_secs(1),
                0,
            )
            .unwrap();
            let sig11 = parser.next();
            assert!(sig11.is_some());
            eprintln!("Sig11: {}", sig11.as_ref().unwrap());
            assert_eq!(
                sig11.unwrap(),
                Arc::new(events::Version::V1 {
                    timestamp: Utc.timestamp_millis(6433742 + 372858970),
                    event: events::EventType::LinuxFatalSignal(events::LinuxFatalSignal {
                        facility: events::LogFacility::Kern,
                        level: events::LogLevel::Warning,
                        signal: events::FatalSignalType::SIGSEGV,
                        stack_dump: map! {
                            "CPU" => "1",
                            "PID" => "36075",
                            "Comm" => "a.out Not tainted 4.14.131-linuxkit #1",
                            "Hardware name" => "BHYVE, BIOS 1.00 03/14/2014",
                            "task" => "ffff9b08f2e1c3c0",
                            "task.stack" => "ffffb493c0e98000",
                            "RIP" => "0033:0x561bc8d8f12e",
                            "RSP" => "002b:00007ffd5833d0c0",
                            "EFLAGS" => "00010246",
                            "RBX" => "0000000000000000",
                            "RAX" => "0000000000000000",
                            "RCX" => "00007fd15e0e0718",
                            "RDX" => "00007ffd5833d1b8",
                            "RSI" => "00007ffd5833d1a8",
                            "RDI" => "0000000000000001",
                            "RBP" => "00007ffd5833d0c0",
                            "R08" => "00007fd15e0e1d80",
                            "R09" => "00007fd15e0e1d80",
                            "R10" => "0000000000000000",
                            "R11" => "0000000000000000",
                            "R12" => "0000561bc8d8f040",
                            "R13" => "00007ffd5833d1a0",
                            "R14" => "0000000000000000",
                            "R15" => "0000000000000000",
                            "FS" => "00007fd15e0e7500(0000) GS:ffff9b08ffd00000(0000) knlGS:0000000000000000",
                            "CS" => "0010",
                            "DS" => "0000",
                            "ES" => "0000",
                            "CR0" => "0000000080050033",
                            "CR2" => "0000000000000000",
                            "CR3" => "0000000132d26005",
                            "CR4" => "00000000000606a0"
                        },
                    }),
                })
            )
        }

        {
            // Validate when new kmsg's stop bring KV/pairs
            kmsgs.push(boxed_kmsg(timestamp, String::from("traps: nginx[65914] general protection ip:7f883f6f39a5 sp:7ffc914464e8 error:0 in libpthread-2.23.so[7f883f6e3000+18000]")));

            let mut parser = EventParser::from_kmsg_iterator(
                Box::new(kmsgs.into_iter()),
                Duration::from_secs(1),
                0,
            )
            .unwrap();
            let sig11 = parser.next();
            assert!(sig11.is_some());
            assert_eq!(
                sig11.unwrap(),
                Arc::new(events::Version::V1 {
                    timestamp: Utc.timestamp_millis(6433742 + 372858970),
                    event: events::EventType::LinuxFatalSignal(events::LinuxFatalSignal {
                        facility: events::LogFacility::Kern,
                        level: events::LogLevel::Warning,
                        signal: events::FatalSignalType::SIGSEGV,
                        stack_dump: map! {
                            "CPU" => "1",
                            "PID" => "36075",
                            "Comm" => "a.out Not tainted 4.14.131-linuxkit #1",
                            "Hardware name" => "BHYVE, BIOS 1.00 03/14/2014",
                            "task" => "ffff9b08f2e1c3c0",
                            "task.stack" => "ffffb493c0e98000",
                            "RIP" => "0033:0x561bc8d8f12e",
                            "RSP" => "002b:00007ffd5833d0c0",
                            "EFLAGS" => "00010246",
                            "RBX" => "0000000000000000",
                            "RAX" => "0000000000000000",
                            "RCX" => "00007fd15e0e0718",
                            "RDX" => "00007ffd5833d1b8",
                            "RSI" => "00007ffd5833d1a8",
                            "RDI" => "0000000000000001",
                            "RBP" => "00007ffd5833d0c0",
                            "R08" => "00007fd15e0e1d80",
                            "R09" => "00007fd15e0e1d80",
                            "R10" => "0000000000000000",
                            "R11" => "0000000000000000",
                            "R12" => "0000561bc8d8f040",
                            "R13" => "00007ffd5833d1a0",
                            "R14" => "0000000000000000",
                            "R15" => "0000000000000000",
                            "FS" => "00007fd15e0e7500(0000) GS:ffff9b08ffd00000(0000) knlGS:0000000000000000",
                            "CS" => "0010",
                            "DS" => "0000",
                            "ES" => "0000",
                            "CR0" => "0000000080050033",
                            "CR2" => "0000000000000000",
                            "CR3" => "0000000132d26005",
                            "CR4" => "00000000000606a0"
                        },
                    }),
                })
            );

            // make sure the next kernel trap message is parsed as well
            let kt = parser.next();
            assert!(kt.is_some());
            assert_matches!(
                kt.unwrap().as_ref(),
                events::Version::V1 {
                    timestamp: _,
                    event: events::EventType::LinuxKernelTrap(_),
                }
            );
        }
    }

    #[test]
    fn is_sendable() {
        let timestamp = Utc.timestamp_millis(57533475 + 372850970);
        let kmsgs = vec![
            Box::new(kmsg::KMsg{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                timestamp,
                message: String::from(" a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
            }),
        ];

        let mut parser =
            EventParser::from_kmsg_iterator(Box::new(kmsgs.into_iter()), Duration::from_secs(1), 0)
                .unwrap();

        thread::spawn(move || {
            let maybe_segfault = parser.next();
            assert!(maybe_segfault.is_some());
            let segfault = maybe_segfault.unwrap();
            assert_eq!(
                segfault,
                Arc::new(events::Version::V1 {
                    timestamp,
                    event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                        facility: events::LogFacility::Kern,
                        level: events::LogLevel::Warning,
                        trap: events::KernelTrapType::Segfault { location: 0 },
                        procname: String::from("a.out"),
                        pid: 36075,
                        ip: 0x0000561bc8d8f12e,
                        sp: 0x00007ffd5833d0c0,
                        errcode: events::SegfaultErrorCode {
                            reason: events::SegfaultReason::NoPageFound,
                            access_type: events::SegfaultAccessType::Read,
                            access_mode: events::SegfaultAccessMode::User,
                            use_of_reserved_bit: false,
                            instruction_fetch: false,
                            protection_keys_block_access: false,
                        },
                        file: Some(String::from("a.out")),
                        vmastart: Some(0x561bc8d8f000),
                        vmasize: Some(0x1000),
                    }),
                })
            );
        });

        assert!(
            true,
            "If this compiles, EventParser is Send-able across threads."
        );
    }

    #[test]
    fn can_parse_suppressed_callback() {
        let timestamp = Utc.timestamp_millis(803835 + 372850970);

        let kmsgs = vec![Box::new(kmsg::KMsg {
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Warning,
            timestamp,
            message: String::from("show_signal_msg: 9 callbacks suppressed"),
        })];

        let mut parser =
            EventParser::from_kmsg_iterator(Box::new(kmsgs.into_iter()), Duration::from_secs(1), 0)
                .unwrap();
        let suppressed_callback = parser.next();
        assert!(suppressed_callback.is_some());
        assert_eq!(
            suppressed_callback.unwrap(),
            Arc::new(events::Version::V1 {
                timestamp,
                event: events::EventType::LinuxSuppressedCallback(
                    events::LinuxSuppressedCallback {
                        facility: events::LogFacility::Kern,
                        level: events::LogLevel::Warning,
                        function_name: "show_signal_msg".to_owned(),
                        count: 9,
                    }
                ),
            })
        )
    }

    fn boxed_kmsg(timestamp: chrono::DateTime<Utc>, message: String) -> Box<kmsg::KMsg> {
        Box::new(kmsg::KMsg {
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Warning,
            timestamp,
            message,
        })
    }

    fn boxed_kmsgs(
        timestamp: chrono::DateTime<Utc>,
        messages: Vec<String>,
    ) -> Vec<Box<kmsg::KMsg>> {
        messages
            .into_iter()
            .map(|message| boxed_kmsg(timestamp, message))
            .collect()
    }
}
