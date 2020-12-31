// Copyright (c) 2019 Polyverse Corporation
// Copyright (c) 2019 Polyverse Corporation

use crate::common;
use crate::events;
use crate::system;

use core::pin::Pin;
use futures::{
    stream::{self, Stream},
    StreamExt,
};
use num::FromPrimitive;
use regex::Regex;
use rmesg::{entry::Entry, error::RMesgError};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    ops::Add,
    sync::Arc,
    time::Duration,
};
use time::OffsetDateTime;
use timeout_iterator::asynchronous::TimeoutStream;

pub async fn new(
    c: RawEventStreamConfig,
) -> Result<impl Stream<Item = events::Event>, RawEventStreamError> {
    if c.verbosity > 0 {
        eprintln!("RawEventStream: Reading and parsing relevant kernel messages...");
    }

    new_with_rmesg_stream(c, rmesg::logs_stream(rmesg::Backend::Default, false, false).await?).await
}

pub async fn new_with_rmesg_stream(
    c: RawEventStreamConfig,
    rmesg_stream: rmesg::EntriesStream
) -> Result<impl Stream<Item = events::Event>, RawEventStreamError> {
    let entries = TimeoutStream::with_stream(
        rmesg_stream,
    )
    .await?;

    let system_start_time = system::system_start_time()?;

    // Start processing events from system start? Or when zerotect was started?
    let event_stream_start_time = match c.gobble_old_events {
        true => system_start_time,
        false => OffsetDateTime::now_utc(),
    };

    let res = RawEventStream {
        entries,
        verbosity: c.verbosity,
        hostname: c.hostname,
        flush_timeout: c.flush_timeout,
        system_start_time,
        event_stream_start_time,
    };

    let s = common::result_stream_exit_on_error(stream::unfold(res, |mut res| async move {
        Some((res.parse_next_event().await, res))
    }));

    Ok(s)
}

#[derive(Debug)]
pub enum RawEventStreamError {
    UnderlyingStreamClosed,
    UnderlyingStreamedItemError(RMesgError),
    TimeoutStreamError(timeout_iterator::error::Error),
    SystemConfigError(system::SystemConfigError),
    Generic(String),
}
impl Error for RawEventStreamError {}
impl Display for RawEventStreamError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::UnderlyingStreamClosed => write!(
                f,
                "Underlying stream that provided Log Entries to be parsed closed"
            ),
            Self::TimeoutStreamError(err) => write!(f, "TimeoutStreamError: {}", err),
            Self::SystemConfigError(err) => write!(f, "SystemConfigError: {}", err),
            Self::UnderlyingStreamedItemError(err) => {
                write!(f, "UnderlyingStreamedItemError: {}", err)
            }
            Self::Generic(s) => write!(f, "{}", s),
        }
    }
}
impl From<timeout_iterator::error::Error> for RawEventStreamError {
    fn from(err: timeout_iterator::error::Error) -> Self {
        Self::TimeoutStreamError(err)
    }
}
impl From<RMesgError> for RawEventStreamError {
    fn from(err: RMesgError) -> Self {
        Self::UnderlyingStreamedItemError(err)
    }
}
impl From<system::SystemConfigError> for RawEventStreamError {
    fn from(err: system::SystemConfigError) -> Self {
        Self::SystemConfigError(err)
    }
}

#[derive(Clone)]
pub struct RawEventStreamConfig {
    pub verbosity: u8,
    pub hostname: Option<String>,
    pub gobble_old_events: bool,
    pub flush_timeout: Duration,
}

type TimeoutStreamItem = Result<Entry, RMesgError>;

pub struct RawEventStream {
    entries: TimeoutStream<TimeoutStreamItem, Pin<Box<dyn Stream<Item = TimeoutStreamItem>>>>,
    verbosity: u8,
    hostname: Option<String>,
    flush_timeout: Duration,

    // What was the time when the system started?
    // we need this to set timestamps of events
    system_start_time: OffsetDateTime,

    // only read events from this time on
    event_stream_start_time: OffsetDateTime,
}

impl RawEventStream {
    async fn parse_next_event(&mut self) -> Result<events::Event, RawEventStreamError> {
        // we'll need to borrow and capture this in closures multiple times.
        // Make a one-time clone so we don't borrow self over and over again.
        let hostname = self.hostname.clone();

        // Loop until either:
        // 1. We find a legit event and can return it
        // 2. We get an error parsing an event
        // 3. The underlying stream closes and returns a None
        loop {
            match self.entries.next().await {
                Some(Ok(entry)) => {
                    let entry_timestamp = match entry.timestamp_from_system_start {
                        Some(timestamp_from_system_start) => {
                            self.system_start_time.add(timestamp_from_system_start)
                        }
                        None => continue, // ignore events without timestamp
                    };

                    // skip events older than when a stream should start
                    if entry_timestamp < self.event_stream_start_time {
                        continue;
                    }

                    match RawEventStream::parse_finite_kmsg_to_event(
                        &entry,
                        entry_timestamp,
                        &hostname,
                    )
                    .await
                    {
                        Some(e) => return Ok(e),
                        None => match self
                            .parse_fatal_signal(&entry, entry_timestamp, &hostname)
                            .await
                        {
                            Some(e) => return Ok(e),
                            // next entry wasn't a legit event... keep looping
                            // since the stream hasn't returned None, don't return None
                            // to indicate ending of upstream stream
                            None => continue,
                        },
                    }
                }

                // If Iterated Item had an error, propagate up
                Some(Err(e)) => return Err(e.into()),

                // If iterator returned None, we're done
                None => return Err(RawEventStreamError::UnderlyingStreamClosed),
            }
        }
    }

    async fn parse_finite_kmsg_to_event(
        entry: &rmesg::entry::Entry,
        entry_timestamp: OffsetDateTime,
        hostname: &Option<String>,
    ) -> Option<events::Event> {
        match RawEventStream::parse_callbacks_suppressed(entry, entry_timestamp, hostname).await {
            Some(e) => Some(e),
            None => RawEventStream::parse_kernel_trap(entry, entry_timestamp, hostname).await,
        }
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
    async fn parse_kernel_trap(
        entry: &rmesg::entry::Entry,
        entry_timestamp: OffsetDateTime,
        hostname: &Option<String>,
    ) -> Option<events::Event> {
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

        if let Some(dmesg_parts) = RE_WITHOUT_LOCATION.captures(entry.message.as_str()) {
            if let (
                Some(facility),
                Some(level),
                procname,
                Some(pid),
                Some(trap),
                Some(ip),
                Some(sp),
                Some(errcode),
                maybelocation,
            ) = (
                entry.facility,
                entry.level,
                &dmesg_parts["procname"],
                common::parse_fragment::<usize>(&dmesg_parts["pid"]),
                RawEventStream::parse_kernel_trap_type(&dmesg_parts["message"]).await,
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

                return Some(Arc::new(events::Version::V1 {
                    timestamp: entry_timestamp,
                    hostname: hostname.clone(),
                    event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                        facility: facility,
                        level: level,
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
                }));
            }
        };

        None
    }

    // Parsing based on: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/traps.c#n230
    // Parses this basic structure:
    // a.out[33629]: <some text> ip 0000556b4c03c603 sp 00007ffe55496510 error 4 in a.out[556b4c03c000+1000]
    async fn parse_kernel_trap_type(trap_string: &str) -> Option<events::KernelTrapType> {
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
    async fn parse_fatal_signal(
        &mut self,
        rmesg_entry: &rmesg::entry::Entry,
        entry_timestamp: OffsetDateTime,
        hostname: &Option<String>,
    ) -> Option<events::Event> {
        lazy_static! {
            static ref RE_FATAL_SIGNAL: Regex = Regex::new(r"(?x)^[[:space:]]*potentially[[:space:]]*unexpected[[:space:]]*fatal[[:space:]]*signal[[:space:]]*(?P<signalnumstr>[[:digit:]]*).*$").unwrap();
        }
        if let Some(fatal_signal_parts) = RE_FATAL_SIGNAL.captures(rmesg_entry.message.as_str()) {
            if let Some(signalnum) =
                common::parse_fragment::<u8>(&fatal_signal_parts["signalnumstr"])
            {
                if let (Some(facility), Some(level), Some(signal)) = (
                    rmesg_entry.facility,
                    rmesg_entry.level,
                    events::FatalSignalType::from_u8(signalnum),
                ) {
                    return Some(Arc::new(events::Version::V1 {
                        timestamp: entry_timestamp,
                        hostname: hostname.clone(),
                        event: events::EventType::LinuxFatalSignal(events::LinuxFatalSignal {
                            facility: facility,
                            level: level,
                            signal,
                            stack_dump: self.parse_stack_dump(hostname).await,
                        }),
                    }));
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
    async fn parse_stack_dump(&mut self, hostname: &Option<String>) -> BTreeMap<String, String> {
        // Not implemented
        let mut sd = BTreeMap::<String, String>::new();

        // the various branches of the loop will terminate...
        loop {
            // peek next line, and if it has a colon, take it
            let entry = match self.entries.peek_timeout(self.flush_timeout).await {
                Ok(Ok(peek_entry)) => {
                    let peek_entry_timestamp = match peek_entry.timestamp_from_system_start {
                        Some(timestamp_from_system_start) => {
                            self.system_start_time.add(timestamp_from_system_start)
                        }
                        None => return sd, // no timestamp? That ends the loop!
                    };

                    // is next message possibly a finite event? Like a kernel trap?
                    // if so, don't consume it and end this KV madness
                    if RawEventStream::parse_finite_kmsg_to_event(
                        peek_entry,
                        peek_entry_timestamp,
                        hostname,
                    )
                    .await
                    .is_some()
                    {
                        return sd;
                    }

                    if !peek_entry.message.contains(':') {
                        // if no ":", then this isn't part of all the KV pairs
                        return sd;
                    } else {
                        // consume next since it worked.
                        // double-unwrap since we matched for Ok(Ok(_)) above
                        self.entries.next().await.unwrap().unwrap()
                    }
                }
                // if error peeking, return what we have...
                // error might be a timeout or something else.
                _ => return sd,
            };

            // now operate on the owned KMsg line
            // since all other paths have exited

            // split message parts on whitespace
            let parts: Vec<_> = entry.message.split(|c| c == ' ').collect();

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
                                eprintln!("Monitor:: parse_stack_dump:: Adding K/V pair: ({}, {}). Log Line: {}", &k, &v, entry.message);
                            }
                            sd.insert(k, v);
                        } else if self.verbosity > 0 {
                            eprintln!("Monitor:: parse_stack_dump:: For this line, transitioned to value without a key. Some data might not be parsed. Log Line: {}", entry.message);
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
                    eprintln!("Monitor:: parse_stack_dump:: Adding Final K/V pair: ({}, {}). Log Line: {}", &k, &v, entry.message);
                }
                sd.insert(k, v);
            }
        }
    }

    // Parsing based on: https://github.com/torvalds/linux/blob/9331b6740f86163908de69f4008e434fe0c27691/lib/ratelimit.c#L51
    // Parses this basic structure:
    // ====> <function name>: 9 callbacks suppressed
    async fn parse_callbacks_suppressed(
        rmesg_entry: &rmesg::entry::Entry,
        entry_timestamp: OffsetDateTime,
        hostname: &Option<String>,
    ) -> Option<events::Event> {
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

        if let Some(dmesg_parts) = RE_CALLBACKS_SUPPRESSED.captures(rmesg_entry.message.as_str()) {
            if let (Some(level), Some(facility), function_name, Some(count)) = (
                rmesg_entry.level,
                rmesg_entry.facility,
                &dmesg_parts["function"],
                common::parse_fragment::<usize>(&dmesg_parts["count"]),
            ) {
                return Some(Arc::new(events::Version::V1 {
                    timestamp: entry_timestamp,
                    hostname: hostname.clone(),
                    event: events::EventType::LinuxSuppressedCallback(
                        events::LinuxSuppressedCallback {
                            facility: facility,
                            level: level,
                            function_name: function_name.to_owned(),
                            count,
                        },
                    ),
                }));
            }
        };

        None
    }
}

/**********************************************************************************/
// Tests! Tests! Tests!

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::{from_str, to_value};
    use futures::stream::iter;
    use std::ops::Sub;
    use std::convert::TryInto;

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
    async fn can_parse_kernel_trap_segfault() {
        let timestamp = OffsetDateTime::from_unix_timestamp_nanos(378084605000000);
        let kmsgs = unboxed_kmsgs(timestamp,
                vec![
                    String::from(" a.out[36175]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
                    String::from(" a.out[36275]: segfault at 0 ip (null) sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
                    String::from("a.out[37659]: segfault at 7fff4b8ba8b8 ip 00007fff4b8ba8b8 sp 00007fff4b8ba7b8 error 15"),
                ]);

        let event1 = Arc::new(events::Version::V1 {
            timestamp,
            hostname: None,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: rmesg::entry::LogFacility::Kern,
                level: rmesg::entry::LogLevel::Warning,
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
            hostname: None,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: rmesg::entry::LogFacility::Kern,
                level: rmesg::entry::LogLevel::Warning,
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
            hostname: None,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: rmesg::entry::LogFacility::Kern,
                level: rmesg::entry::LogLevel::Warning,
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

        let mut parser = Box::pin(new_with_rmesg_stream(
            RawEventStreamConfig{
                verbosity: 0,
                hostname: None,
                gobble_old_events: false,
                flush_timeout: Duration::from_secs(1),
            },
            Box::pin(iter(kmsgs.into_iter().map(|k| Ok(k)))),
        ).await
        .unwrap());

        let maybe_segfault = parser.next().await;
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event1);

        let maybe_segfault = parser.next().await;
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event2);

        let maybe_segfault = parser.next().await;
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
                    }
                }
            }"#
            )
            .unwrap()
        );
    }

    #[tokio::test]
    async fn can_parse_kernel_trap_invalid_opcode() {
        let timestamp = OffsetDateTime::from_unix_timestamp_nanos(5606197845000000);

        let kmsgs = unboxed_kmsgs(timestamp,
            vec![
                String::from(" a.out[38175]: trap invalid opcode ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
                String::from(" a.out[38275]: trap invalid opcode ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4"),
            ]);

        let event1 = Arc::new(events::Version::V1 {
            timestamp,
            hostname: None,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: rmesg::entry::LogFacility::Kern,
                level: rmesg::entry::LogLevel::Warning,
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
            hostname: None,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: rmesg::entry::LogFacility::Kern,
                level: rmesg::entry::LogLevel::Warning,
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

        let mut parser = Box::pin(new_with_rmesg_stream(
            RawEventStreamConfig{
                verbosity: 0,
                hostname: None,
                gobble_old_events: false,
                flush_timeout: Duration::from_secs(1),
            },
            Box::pin(iter(kmsgs.into_iter().map(|k| Ok(k)))),
        ).await
        .unwrap());

        let maybe_segfault = parser.next().await;
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event1);

        let maybe_segfault = parser.next().await;
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
                    }
                }
            }"#
            )
            .unwrap()
        );
    }

    #[tokio::test]
    async fn can_parse_kernel_trap_generic() {
        let timestamp = OffsetDateTime::from_unix_timestamp_nanos(471804323000000);

        let kmsgs = vec![
            unboxed_kmsg(timestamp, String::from(" a.out[39175]: foo ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]")),
            unboxed_kmsg(timestamp, String::from(" a.out[39275]: bar ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4")),
        ];

        let event1 = Arc::new(events::Version::V1 {
            timestamp,
            hostname: None,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: rmesg::entry::LogFacility::Kern,
                level: rmesg::entry::LogLevel::Warning,
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
            hostname: None,
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: rmesg::entry::LogFacility::Kern,
                level: rmesg::entry::LogLevel::Warning,
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

        let mut parser = Box::pin(new_with_rmesg_stream(
            RawEventStreamConfig{
                verbosity: 0,
                hostname: None,
                gobble_old_events: false,
                flush_timeout: Duration::from_secs(1),
            },
            Box::pin(iter(kmsgs.into_iter().map(|k| Ok(k)))),
        ).await
        .unwrap());

        let maybe_segfault = parser.next().await;
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event1);

        let maybe_segfault = parser.next().await;
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
                    }
                }
            }"#
            )
            .unwrap()
        );
    }

    #[tokio::test]
    async fn can_parse_kernel_trap_general_protection() {
        let timestamp = OffsetDateTime::from_unix_timestamp_nanos(378084605000000);
        let kmsgs = unboxed_kmsgs(timestamp,
                vec![
                    String::from("traps: nginx[67494] general protection ip:43bbbc sp:7ffdd4474db0 error:0 in nginx[400000+92000]"),
                    String::from("  traps: nginx[67494] general protection ip:43bbbc sp:7ffdd4474db0 error:0 in nginx[400000+92000]"),
                    String::from(" traps:   nginx[67494] general protection ip:43bbbc sp:7ffdd4474db0 error:0 in nginx[400000+92000]"),
                    String::from(" nginx[67494] general protection ip:43bbbc sp:7ffdd4474db0 error:0 in nginx[400000+92000]"),
                    String::from("nginx[67494] general protection ip:43bbbc sp:7ffdd4474db0 error:0 in nginx[400000+92000]"),
                ]);

        let event1 = Arc::new(events::Version::V1 {
            timestamp,
            hostname: Some("testhost".to_owned()),
            event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                facility: rmesg::entry::LogFacility::Kern,
                level: rmesg::entry::LogLevel::Warning,
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

        let mut parser = Box::pin(new_with_rmesg_stream(
            RawEventStreamConfig{
                verbosity: 0,
                hostname: None,
                gobble_old_events: false,
                flush_timeout: Duration::from_secs(1),
            },
            Box::pin(iter(kmsgs.into_iter().map(|k| Ok(k)))),
        ).await
        .unwrap());


        let maybe_gpf = parser.next().await;
        assert!(maybe_gpf.is_some());
        let gpf = maybe_gpf.unwrap();
        assert_eq!(gpf, event1);

        let maybe_gpf = parser.next().await;
        assert!(maybe_gpf.is_some());
        let gpf = maybe_gpf.unwrap();
        assert_eq!(gpf, event1);

        let maybe_gpf = parser.next().await;
        assert!(maybe_gpf.is_some());
        let gpf = maybe_gpf.unwrap();
        assert_eq!(gpf, event1);

        let maybe_gpf = parser.next().await;
        assert!(maybe_gpf.is_some());
        let gpf = maybe_gpf.unwrap();
        assert_eq!(gpf, event1);

        let maybe_gpf = parser.next().await;
        assert!(maybe_gpf.is_some());
        let gpf = maybe_gpf.unwrap();
        assert_eq!(gpf, event1);

        let maybe_gpf = parser.next().await;
        assert!(maybe_gpf.is_none());

        assert_eq!(
            to_value(&event1).unwrap(),
            from_str::<serde_json::Value>(
                r#"{
                "version": "V1",
                "timestamp": "1970-01-05T09:01:24.605Z",
                "hostname": "testhost",
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

    #[tokio::test]
    async fn can_parse_fatal_signal_optional_dump() {
        let timestamp = OffsetDateTime::from_unix_timestamp_nanos(376087724000000);

        let kmsgs = vec![rmesg::entry::Entry {
            facility: Some(rmesg::entry::LogFacility::Kern),
            level: Some(rmesg::entry::LogLevel::Warning),
            timestamp_from_system_start: Some(timestamp_from_system_start(timestamp)),
            sequence_num: None,
            message: String::from("potentially unexpected fatal signal 11."),
        }];

        let mut parser = Box::pin(new_with_rmesg_stream(
            RawEventStreamConfig{
                verbosity: 0,
                hostname: None,
                gobble_old_events: false,
                flush_timeout: Duration::from_secs(1),
            },
            Box::pin(iter(kmsgs.into_iter().map(|k| Ok(k)))),
        ).await
        .unwrap());

        let sig11 = parser.next().await;
        assert!(sig11.is_some());
        assert_eq!(
            sig11.unwrap(),
            Arc::new(events::Version::V1 {
                timestamp,
                hostname: Some("testhost2".to_owned()),
                event: events::EventType::LinuxFatalSignal(events::LinuxFatalSignal {
                    facility: rmesg::entry::LogFacility::Kern,
                    level: rmesg::entry::LogLevel::Warning,
                    signal: events::FatalSignalType::SIGSEGV,
                    stack_dump: BTreeMap::new(),
                }),
            })
        )
    }

    #[tokio::test]
    async fn can_parse_fatal_signal_11() {
        let timestamp = OffsetDateTime::from_unix_timestamp_nanos(6433742000000 + 372858970000000);
        let mut kmsgs = unboxed_kmsgs(
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
            let mut parser = Box::pin(new_with_rmesg_stream(
                RawEventStreamConfig{
                    verbosity: 0,
                    hostname: None,
                    gobble_old_events: false,
                    flush_timeout: Duration::from_secs(1),
                },
                Box::pin(iter(kmsgs.clone().into_iter().map(|k| Ok(k)))),
            ).await
            .unwrap());

            let sig11 = parser.next().await;
            assert!(sig11.is_some());
            eprintln!("Sig11: {}", sig11.as_ref().unwrap());
            assert_eq!(
                sig11.unwrap(),
                Arc::new(events::Version::V1 {
                    timestamp: OffsetDateTime::from_unix_timestamp_nanos(6433742000000 + 372858970000000),
                    hostname: None,
                    event: events::EventType::LinuxFatalSignal(events::LinuxFatalSignal {
                        facility: rmesg::entry::LogFacility::Kern,
                        level: rmesg::entry::LogLevel::Warning,
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
            kmsgs.push(unboxed_kmsg(timestamp, String::from("traps: nginx[65914] general protection ip:7f883f6f39a5 sp:7ffc914464e8 error:0 in libpthread-2.23.so[7f883f6e3000+18000]")));

            let mut parser = Box::pin(new_with_rmesg_stream(
                RawEventStreamConfig{
                    verbosity: 0,
                    hostname: None,
                    gobble_old_events: false,
                    flush_timeout: Duration::from_secs(1),
                },
                Box::pin(iter(kmsgs.into_iter().map(|k| Ok(k)))),
            ).await
            .unwrap());

            let sig11 = parser.next().await;
            assert!(sig11.is_some());
            assert_eq!(
                sig11.unwrap(),
                Arc::new(events::Version::V1 {
                    timestamp: OffsetDateTime::from_unix_timestamp_nanos(6433742000000 + 372858970000000),
                    hostname: None,
                    event: events::EventType::LinuxFatalSignal(events::LinuxFatalSignal {
                        facility: rmesg::entry::LogFacility::Kern,
                        level: rmesg::entry::LogLevel::Warning,
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
            let kt = parser.next().await;
            assert!(kt.is_some());
            assert_matches!(
                kt.unwrap().as_ref(),
                events::Version::V1 {
                    timestamp: _,
                    hostname: None,
                    event: events::EventType::LinuxKernelTrap(_),
                }
            );
        }
    }

    #[tokio::test]
    async fn can_parse_suppressed_callback() {
        let timestamp = OffsetDateTime::from_unix_timestamp_nanos(803835000000 + 372850970000000);

        let kmsgs = vec![rmesg::entry::Entry {
            facility: Some(rmesg::entry::LogFacility::Kern),
            level: Some(rmesg::entry::LogLevel::Warning),
            timestamp_from_system_start: Some(timestamp_from_system_start(timestamp)),
            sequence_num: None,
            message: String::from("show_signal_msg: 9 callbacks suppressed"),
        }];

        let mut parser = Box::pin(new_with_rmesg_stream(
            RawEventStreamConfig{
                verbosity: 0,
                hostname: None,
                gobble_old_events: false,
                flush_timeout: Duration::from_secs(1),
            },
            Box::pin(iter(kmsgs.into_iter().map(|k| Ok(k)))),
        ).await
        .unwrap());

        let suppressed_callback = parser.next().await;
        assert!(suppressed_callback.is_some());
        assert_eq!(
            suppressed_callback.unwrap(),
            Arc::new(events::Version::V1 {
                timestamp,
                hostname: None,
                event: events::EventType::LinuxSuppressedCallback(
                    events::LinuxSuppressedCallback {
                        facility: rmesg::entry::LogFacility::Kern,
                        level: rmesg::entry::LogLevel::Warning,
                        function_name: "show_signal_msg".to_owned(),
                        count: 9,
                    }
                ),
            })
        )
    }

    fn unboxed_kmsg(timestamp: OffsetDateTime, message: String) -> rmesg::entry::Entry {
        rmesg::entry::Entry {
            facility: Some(rmesg::entry::LogFacility::Kern),
            level: Some(rmesg::entry::LogLevel::Warning),
            timestamp_from_system_start: Some(timestamp_from_system_start(timestamp)),
            sequence_num: None,
            message,
        }
    }

    fn unboxed_kmsgs(timestamp: OffsetDateTime, messages: Vec<String>) -> Vec<rmesg::entry::Entry> {
        messages
            .into_iter()
            .map(|message| unboxed_kmsg(timestamp, message))
            .collect()
    }

    fn timestamp_from_system_start(timestamp: OffsetDateTime) -> Duration {
        lazy_static! {
            static ref system_start: OffsetDateTime = system::system_start_time().unwrap();
        }

        timestamp.sub(*system_start).try_into().unwrap()
    }
}
