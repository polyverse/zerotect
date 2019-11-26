use crate::events;
use crate::monitor::kmsg;
use crate::system;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use num::FromPrimitive;
use regex::Regex;
use std::collections::HashMap;
use std::ops::Add;
use std::str::FromStr;
use std::time::Duration;

use timeout_iterator::TimeoutIterator;

pub struct EventParser {
    timeout_kmsg_iter: TimeoutIterator<kmsg::KMsg>,
    verbosity: u8,
    system_start_time: DateTime<Utc>,
}

impl EventParser {
    pub fn from_kmsg_iterator(
        kmsg_iter: Box<dyn Iterator<Item = kmsg::KMsg> + Send>,
        verbosity: u8,
    ) -> EventParser {
        let timeout_kmsg_iter = TimeoutIterator::from_item_iterator(kmsg_iter, verbosity);

        EventParser {
            timeout_kmsg_iter,
            verbosity,
            system_start_time: system::system_start_time(),
        }
    }

    pub fn from_kmsg_iterator_and_system_start_time(
        kmsg_iter: Box<dyn Iterator<Item = kmsg::KMsg> + Send>,
        verbosity: u8,
        system_start_time: DateTime<Utc>,
    ) -> EventParser {
        let timeout_kmsg_iter = TimeoutIterator::from_item_iterator(kmsg_iter, verbosity);

        EventParser {
            timeout_kmsg_iter,
            verbosity,
            system_start_time,
        }
    }

    fn parse_next_event(&mut self) -> Result<events::Event, String> {
        // find the next event (we don't use a for loop because we don't want to move
        // the iterator outside of self. We only want to move next() values out of the iterator.
        loop {
            let maybe_kmsg_entry = self.timeout_kmsg_iter.next();
            match maybe_kmsg_entry {
                Some(kmsg_entry) => {
                    if let Some(e) = self.parse_callbacks_suppressed(&kmsg_entry) {
                        return Ok(e);
                    } else if let Some(e) = self.parse_kernel_trap(&kmsg_entry) {
                        return Ok(e);
                    } else if let Some(e) = self.parse_fatal_signal(&kmsg_entry) {
                        return Ok(e);
                    }
                }
                None => break,
            }
        }

        Err("Exited dmesg iterator unexpectedly.".to_owned())
    }

    // Parsing based on: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/traps.c#n230
    // Parses this basic structure:
    // ====>> a.out[33629]: <some text> ip 0000556b4c03c603 sp 00007ffe55496510 error 4
    // Optionally followed by
    // ====>>  in a.out[556b4c03c000+1000]
    fn parse_kernel_trap(&mut self, km: &kmsg::KMsg) -> Option<events::Event> {
        lazy_static! {
            static ref RE_WITHOUT_LOCATION: Regex = Regex::new(r"(?x)^
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
                (?P<maybelocation>.*)$").unwrap();

            static ref RE_LOCATION: Regex = Regex::new(r"(?x)^
                [[:space:]]*in[[:space:]]*(?P<file>[^\[]*)[\[](?P<vmastart>[[:xdigit:]]*)\+(?P<vmasize>[[:xdigit:]]*)[\]]
                [[:space:]]*$").unwrap();

        }

        if self.verbosity > 2 {
            eprintln!(
                "Monitor:: parse_kernel_trap:: Attempting to parse kernel log as kernel trap: {:?}",
                km
            );
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
                EventParser::parse_fragment::<usize>(&dmesg_parts["pid"]),
                self.parse_kernel_trap_type(&dmesg_parts["message"]),
                EventParser::parse_hex::<usize>(&dmesg_parts["ip"]),
                EventParser::parse_hex::<usize>(&dmesg_parts["sp"]),
                EventParser::parse_hex::<u8>(&dmesg_parts["errcode"]),
                &dmesg_parts["maybelocation"],
            ) {
                if self.verbosity > 2 {
                    eprintln!(
                        "Monitor:: parse_kernel_trap:: Successfully parsed kernel trap parts: {:?}",
                        dmesg_parts
                    );
                }

                let (file, vmastart, vmasize) = if let Some(location_parts) =
                    RE_LOCATION.captures(maybelocation)
                {
                    if self.verbosity > 2 {
                        eprintln!("Monitor:: parse_kernel_trap:: Successfully parsed kernel trap location: {:?}", location_parts);
                    }
                    (
                        Some((&location_parts["file"]).to_owned()),
                        EventParser::parse_hex::<usize>(&location_parts["vmastart"]),
                        EventParser::parse_hex::<usize>(&location_parts["vmasize"]),
                    )
                } else {
                    (None, None, None)
                };

                let trapinfo = events::KernelTrapInfo {
                    trap,
                    procname: procname.to_owned(),
                    pid,
                    ip: ip,
                    sp: sp,
                    errcode: events::SegfaultErrorCode::from_error_code(errcode),
                    file,
                    vmastart,
                    vmasize,
                };

                if self.verbosity > 2 {
                    eprintln!(
                        "Monitor:: parse_kernel_trap:: Successfully parsed kernel trap: {:?}",
                        trapinfo
                    );
                }
                return Some(events::Event {
                    facility: km.facility.clone(),
                    level: km.level.clone(),
                    timestamp: self.system_start_time.add(km.duration_from_system_start),
                    event_type: events::EventType::KernelTrap(trapinfo),
                });
            }
        };

        None
    }

    // Parsing based on: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/traps.c#n230
    // Parses this basic structure:
    // a.out[33629]: <some text> ip 0000556b4c03c603 sp 00007ffe55496510 error 4 in a.out[556b4c03c000+1000]
    fn parse_kernel_trap_type(&mut self, trap_string: &str) -> Option<events::KernelTrapType> {
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
        }

        if let Some(segfault_parts) = RE_SEGFAULT.captures(trap_string) {
            if let Some(location) = EventParser::parse_hex::<usize>(&segfault_parts["location"]) {
                Some(events::KernelTrapType::Segfault(location))
            } else {
                eprintln!("Reporting segfault as a generic kernel trap because {} couldn't be parsed as a hexadecimal.", &segfault_parts["location"]);
                Some(events::KernelTrapType::Generic(trap_string.to_owned()))
            }
        } else if RE_INVALID_OPCODE.is_match(trap_string) {
            Some(events::KernelTrapType::InvalidOpcode)
        } else {
            Some(events::KernelTrapType::Generic(trap_string.to_owned()))
        }
    }

    // Parses this
    // We have this entry, enabled by kernel.print-fatal-signals
    // Signal Printed here: https://github.com/torvalds/linux/blob/master/kernel/signal.c#L1239
    // ---------------------------------------------------------------
    // potentially unexpected fatal signal 11.
    fn parse_fatal_signal(&mut self, km: &kmsg::KMsg) -> Option<events::Event> {
        lazy_static! {
            static ref RE_FATAL_SIGNAL: Regex = Regex::new(r"(?x)^[[:space:]]*potentially[[:space:]]*unexpected[[:space:]]*fatal[[:space:]]*signal[[:space:]]*(?P<signalnumstr>[[:digit:]]*).*$").unwrap();
        }
        if let Some(fatal_signal_parts) = RE_FATAL_SIGNAL.captures(km.message.as_str()) {
            if let Some(signalnum) =
                EventParser::parse_fragment::<u8>(&fatal_signal_parts["signalnumstr"])
            {
                if let Some(signal) = events::FatalSignalType::from_u8(signalnum) {
                    return Some(events::Event {
                        facility: km.facility.clone(),
                        level: km.level.clone(),
                        timestamp: self.system_start_time.add(km.duration_from_system_start),
                        event_type: events::EventType::FatalSignal(events::FatalSignalInfo {
                            signal,
                            stack_dump: self.parse_stack_dump(),
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
    fn parse_stack_dump(&mut self) -> Option<events::StackDump> {
        if let (
            (Some(cpu), Some(pid), Some(command), Some(kernel)),
            hardware,
            taskinfo,
            registers,
        ) = (
            self.parse_fatal_signal_cpu_line(),
            self.parse_fatal_signal_hardware(),
            self.parse_fatal_signal_task_line(),
            self.parse_fatal_signal_registers(),
        ) {
            return Some(events::StackDump {
                cpu,
                pid,
                command,
                kernel,
                hardware,
                taskinfo,
                registers,
            });
        }

        None
    }

    // CPU: 1 PID: 36075 Comm: a.out Not tainted 4.14.131-linuxkit #1
    fn parse_fatal_signal_cpu_line(
        &mut self,
    ) -> (Option<usize>, Option<usize>, Option<String>, Option<String>) {
        lazy_static! {
            static ref RE_CPU_LINE: Regex = Regex::new(
                r"(?x)^
                [[:space:]]*CPU:[[:space:]]*(?P<cpu>[[:digit:]]*)
                [[:space:]]*PID:[[:space:]]*(?P<pid>[[:digit:]]*)
                [[:space:]]*Comm:[[:space:]]*(?P<command>[[:^space:]]*)
                (?P<kernel>.*)$"
            )
            .unwrap();
        }
        if let Ok(maybe_cpu_line) = self.timeout_kmsg_iter.peek_timeout(Duration::from_secs(1)) {
            if let Some(line_parts) = RE_CPU_LINE.captures(maybe_cpu_line.message.as_str()) {
                let retval = (
                    EventParser::parse_fragment::<usize>(&line_parts["cpu"]),
                    EventParser::parse_fragment::<usize>(&line_parts["pid"]),
                    Some(line_parts["command"].trim().to_owned()),
                    Some(line_parts["kernel"].trim().to_owned()),
                );
                self.timeout_kmsg_iter.next(); //consume the line
                return retval;
            }
        }

        (None, None, None, None)
    }

    // Hardware name:  BHYVE, BIOS 1.00 03/14/2014
    fn parse_fatal_signal_hardware(&mut self) -> String {
        lazy_static! {
            static ref RE_HARDWARE_LINE: Regex = Regex::new(
                r"(?x)^[[:space:]]*Hardware[[:space:]]*name:[[:space:]]*(?P<hardware>.*)$"
            )
            .unwrap();
        }
        if let Ok(maybe_hardware_line) = self.timeout_kmsg_iter.peek_timeout(Duration::from_secs(1))
        {
            if let Some(line_parts) =
                RE_HARDWARE_LINE.captures(maybe_hardware_line.message.as_str())
            {
                let hardware = line_parts["hardware"].trim().to_owned();
                self.timeout_kmsg_iter.next(); //consume the line
                return hardware;
            }
        }

        String::new()
    }

    // task: ffff9b08f2e1c3c0 task.stack: ffffb493c0e98000
    // task: ffff880076e1aa00 ti: ffff880079ed4000 task.ti: ffff880079ed4000
    fn parse_fatal_signal_task_line(&mut self) -> HashMap<String, String> {
        lazy_static! {
            static ref RE_HARDWARE_LINE: Regex = Regex::new(
                r"(?x)[[:space:]]*(?P<key>task[^:]*):[[:space:]]*(?P<value>[[:xdigit:]]*)"
            )
            .unwrap();
        }

        let mut taskinfo = HashMap::<String, String>::new();
        if let Ok(maybe_hardware_line) = self.timeout_kmsg_iter.peek_timeout(Duration::from_secs(1))
        {
            for keyval in RE_HARDWARE_LINE.captures_iter(maybe_hardware_line.message.as_str()) {
                println!("{}: {}", &keyval["key"], &keyval["value"]);
                taskinfo.insert(
                    keyval["key"].trim().to_owned(),
                    keyval["value"].trim().to_owned(),
                );
            }
            if taskinfo.len() > 0 {
                // we let go of the first iterator borrow after we cloned off it, now we can borrow again,
                // and delete the message
                self.timeout_kmsg_iter.next(); //consume the message if we like it
            }
        }
        return taskinfo;
    }

    // This is the tricky part! No way to know when it ends
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
    fn parse_fatal_signal_registers(&mut self) -> HashMap<String, String> {
        // Not implemented
        HashMap::<String, String>::new()
    }

    // Parsing based on: https://github.com/torvalds/linux/blob/9331b6740f86163908de69f4008e434fe0c27691/lib/ratelimit.c#L51
    // Parses this basic structure:
    // ====> <function name>: 9 callbacks suppressed
    fn parse_callbacks_suppressed(&mut self, km: &kmsg::KMsg) -> Option<events::Event> {
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

        if self.verbosity > 2 {
            eprintln!("Monitor:: parse_callbacks_suppressed:: Attempting to parse kernel log as suppressed number of callbacks: {:?}", km);
        }

        if let Some(dmesg_parts) = RE_CALLBACKS_SUPPRESSED.captures(km.message.as_str()) {
            if let (function_name, Some(count)) = (
                &dmesg_parts["function"],
                EventParser::parse_fragment::<usize>(&dmesg_parts["count"]),
            ) {
                if self.verbosity > 2 {
                    eprintln!("Monitor:: parse_callbacks_suppressed:: Successfully suppressed callbacks: {:?}", dmesg_parts);
                }

                let suppressed_callback_info = events::SuppressedCallbackInfo {
                    function_name: function_name.to_owned(),
                    count,
                };

                return Some(events::Event {
                    facility: km.facility.clone(),
                    level: km.level.clone(),
                    timestamp: self.system_start_time.add(km.duration_from_system_start),
                    event_type: events::EventType::SuppressedCallback(suppressed_callback_info),
                });
            }
        };

        None
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

    fn parse_hex<N: num::Num + typename::TypeName>(frag: &str) -> Option<N>
    where
        <N as num::Num>::FromStrRadixErr: std::fmt::Display,
    {
        // special case
        if frag == "(null)" {
            return Some(N::zero());
        };

        match N::from_str_radix(frag.trim(), 16) {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("Unable to parse {} into {}: {}", frag, N::type_name(), e);
                None
            }
        }
    }
}

impl Iterator for EventParser {
    // we will be counting with usize
    type Item = events::Event;

    // next() is the only required method
    fn next(&mut self) -> Option<Self::Item> {
        match self.parse_next_event() {
            Ok(event) => Some(event),
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
    use chrono::offset::TimeZone;
    use std::thread;

    macro_rules! map(
    { $($key:expr => $value:expr),+ } => {
        {
            let mut m = ::std::collections::HashMap::new();
            $(
                m.insert($key.to_owned(), $value.to_owned());
            )+
            m
        }
     };
    );

    #[test]
    fn can_parse_kernel_trap_segfault() {
        //initialize a random system start time
        let system_start_time = Utc.timestamp_millis(5233635);

        let kmsgs = vec![
            kmsg::KMsg{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372850970000),
                message: String::from(" a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
            },
            kmsg::KMsg{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372856970000),
                message: String::from(" a.out[36075]: segfault at 0 ip (null) sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
            },
            kmsg::KMsg{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372852970000),
                message: String::from("a.out[37659]: segfault at 7fff4b8ba8b8 ip 00007fff4b8ba8b8 sp 00007fff4b8ba7b8 error 15"),
            },
        ];

        let event1 = events::Event {
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Warning,
            timestamp: system_start_time.add(ChronoDuration::microseconds(372850970000)),
            event_type: events::EventType::KernelTrap(events::KernelTrapInfo {
                trap: events::KernelTrapType::Segfault(0),
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
        };

        let event2 = events::Event {
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Warning,
            timestamp: system_start_time.add(ChronoDuration::microseconds(372856970000)),
            event_type: events::EventType::KernelTrap(events::KernelTrapInfo {
                trap: events::KernelTrapType::Segfault(0),
                procname: String::from("a.out"),
                pid: 36075,
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
        };

        let event3 = events::Event {
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Warning,
            timestamp: system_start_time.add(ChronoDuration::microseconds(372852970000)),
            event_type: events::EventType::KernelTrap(events::KernelTrapInfo {
                trap: events::KernelTrapType::Segfault(0x7fff4b8ba8b8),
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
        };

        let mut parser = EventParser::from_kmsg_iterator_and_system_start_time(
            Box::new(kmsgs.into_iter()),
            0,
            system_start_time,
        );

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

        assert_eq!(serde_json::to_string(&event1).unwrap(), "{\"facility\":\"Kern\",\"level\":\"Warning\",\"timestamp\":\"1970-01-05T09:01:24.605Z\",\"event_type\":{\"KernelTrap\":{\"trap\":{\"Segfault\":0},\"procname\":\"a.out\",\"pid\":36075,\"ip\":94677333766446,\"sp\":140726083244224,\"errcode\":{\"reason\":\"NoPageFound\",\"access_type\":\"Read\",\"access_mode\":\"User\",\"use_of_reserved_bit\":false,\"instruction_fetch\":false,\"protection_keys_block_access\":false},\"file\":\"a.out\",\"vmastart\":94677333766144,\"vmasize\":4096}}}");
        assert_eq!(serde_json::to_string(&event2).unwrap(), "{\"facility\":\"Kern\",\"level\":\"Warning\",\"timestamp\":\"1970-01-05T09:01:30.605Z\",\"event_type\":{\"KernelTrap\":{\"trap\":{\"Segfault\":0},\"procname\":\"a.out\",\"pid\":36075,\"ip\":0,\"sp\":140726083244224,\"errcode\":{\"reason\":\"NoPageFound\",\"access_type\":\"Read\",\"access_mode\":\"User\",\"use_of_reserved_bit\":false,\"instruction_fetch\":false,\"protection_keys_block_access\":false},\"file\":\"a.out\",\"vmastart\":94677333766144,\"vmasize\":4096}}}");
        assert_eq!(serde_json::to_string(&event3).unwrap(), "{\"facility\":\"Kern\",\"level\":\"Warning\",\"timestamp\":\"1970-01-05T09:01:26.605Z\",\"event_type\":{\"KernelTrap\":{\"trap\":{\"Segfault\":140734460831928},\"procname\":\"a.out\",\"pid\":37659,\"ip\":140734460831928,\"sp\":140734460831672,\"errcode\":{\"reason\":\"ProtectionFault\",\"access_type\":\"Read\",\"access_mode\":\"User\",\"use_of_reserved_bit\":false,\"instruction_fetch\":true,\"protection_keys_block_access\":false},\"file\":null,\"vmastart\":null,\"vmasize\":null}}}");
    }

    #[test]
    fn can_parse_kernel_trap_invalid_opcode() {
        //initialize a random system start time
        let system_start_time = Utc.timestamp_millis(5233345875);

        let kmsgs = vec![
            kmsg::KMsg{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372851970000),
                message: String::from(" a.out[36075]: trap invalid opcode ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
            },
            kmsg::KMsg{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372855970000),
                message: String::from(" a.out[36075]: trap invalid opcode ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4"),
            },
        ];

        let event1 = events::Event {
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Warning,
            timestamp: system_start_time.add(ChronoDuration::microseconds(372851970000)),
            event_type: events::EventType::KernelTrap(events::KernelTrapInfo {
                trap: events::KernelTrapType::InvalidOpcode,
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
        };

        let event2 = events::Event {
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Warning,
            timestamp: system_start_time.add(ChronoDuration::microseconds(372855970000)),
            event_type: events::EventType::KernelTrap(events::KernelTrapInfo {
                trap: events::KernelTrapType::InvalidOpcode,
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
                file: None,
                vmastart: None,
                vmasize: None,
            }),
        };

        let mut parser = EventParser::from_kmsg_iterator_and_system_start_time(
            Box::new(kmsgs.into_iter()),
            0,
            system_start_time,
        );

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event1);

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event2);

        assert_eq!(serde_json::to_string(&event1).unwrap(), "{\"facility\":\"Kern\",\"level\":\"Warning\",\"timestamp\":\"1970-03-06T21:16:37.845Z\",\"event_type\":{\"KernelTrap\":{\"trap\":\"InvalidOpcode\",\"procname\":\"a.out\",\"pid\":36075,\"ip\":94677333766446,\"sp\":140726083244224,\"errcode\":{\"reason\":\"NoPageFound\",\"access_type\":\"Read\",\"access_mode\":\"User\",\"use_of_reserved_bit\":false,\"instruction_fetch\":false,\"protection_keys_block_access\":false},\"file\":\"a.out\",\"vmastart\":94677333766144,\"vmasize\":4096}}}");
        assert_eq!(serde_json::to_string(&event2).unwrap(), "{\"facility\":\"Kern\",\"level\":\"Warning\",\"timestamp\":\"1970-03-06T21:16:41.845Z\",\"event_type\":{\"KernelTrap\":{\"trap\":\"InvalidOpcode\",\"procname\":\"a.out\",\"pid\":36075,\"ip\":94677333766446,\"sp\":140726083244224,\"errcode\":{\"reason\":\"NoPageFound\",\"access_type\":\"Read\",\"access_mode\":\"User\",\"use_of_reserved_bit\":false,\"instruction_fetch\":false,\"protection_keys_block_access\":false},\"file\":null,\"vmastart\":null,\"vmasize\":null}}}");
    }

    #[test]
    fn can_parse_kernel_trap_generic() {
        //initialize a random system start time
        let system_start_time = Utc.timestamp_millis(98952353);

        let kmsgs = vec![
            kmsg::KMsg{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372851970000),
                message: String::from(" a.out[36075]: foo ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
            },
            kmsg::KMsg{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372855970000),
                message: String::from(" a.out[36075]: bar ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4"),
            },
        ];

        let event1 = events::Event {
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Warning,
            timestamp: system_start_time.add(ChronoDuration::microseconds(372851970000)),
            event_type: events::EventType::KernelTrap(events::KernelTrapInfo {
                trap: events::KernelTrapType::Generic(" foo".to_owned()),
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
        };

        let event2 = events::Event {
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Warning,
            timestamp: system_start_time.add(ChronoDuration::microseconds(372855970000)),
            event_type: events::EventType::KernelTrap(events::KernelTrapInfo {
                trap: events::KernelTrapType::Generic(" bar".to_owned()),
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
                file: None,
                vmastart: None,
                vmasize: None,
            }),
        };

        let mut parser = EventParser::from_kmsg_iterator_and_system_start_time(
            Box::new(kmsgs.into_iter()),
            0,
            system_start_time,
        );

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event1);

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, event2);

        assert_eq!(serde_json::to_string(&event1).unwrap(), "{\"facility\":\"Kern\",\"level\":\"Warning\",\"timestamp\":\"1970-01-06T11:03:24.323Z\",\"event_type\":{\"KernelTrap\":{\"trap\":{\"Generic\":\" foo\"},\"procname\":\"a.out\",\"pid\":36075,\"ip\":94677333766446,\"sp\":140726083244224,\"errcode\":{\"reason\":\"NoPageFound\",\"access_type\":\"Read\",\"access_mode\":\"User\",\"use_of_reserved_bit\":false,\"instruction_fetch\":false,\"protection_keys_block_access\":false},\"file\":\"a.out\",\"vmastart\":94677333766144,\"vmasize\":4096}}}");
        assert_eq!(serde_json::to_string(&event2).unwrap(), "{\"facility\":\"Kern\",\"level\":\"Warning\",\"timestamp\":\"1970-01-06T11:03:28.323Z\",\"event_type\":{\"KernelTrap\":{\"trap\":{\"Generic\":\" bar\"},\"procname\":\"a.out\",\"pid\":36075,\"ip\":94677333766446,\"sp\":140726083244224,\"errcode\":{\"reason\":\"NoPageFound\",\"access_type\":\"Read\",\"access_mode\":\"User\",\"use_of_reserved_bit\":false,\"instruction_fetch\":false,\"protection_keys_block_access\":false},\"file\":null,\"vmastart\":null,\"vmasize\":null}}}");
    }

    #[test]
    fn can_parse_fatal_signal_optional_dump() {
        //initialize a random system start time
        let system_start_time = Utc.timestamp_millis(3236754);

        let kmsgs = vec![kmsg::KMsg {
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Warning,
            duration_from_system_start: ChronoDuration::microseconds(372850970000),
            message: String::from("potentially unexpected fatal signal 11."),
        }];

        let mut parser = EventParser::from_kmsg_iterator_and_system_start_time(
            Box::new(kmsgs.into_iter()),
            0,
            system_start_time,
        );
        let sig11 = parser.next();
        assert!(sig11.is_some());
        assert_eq!(
            sig11.unwrap(),
            events::Event {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                timestamp: system_start_time.add(ChronoDuration::microseconds(372850970000)),
                event_type: events::EventType::FatalSignal(events::FatalSignalInfo {
                    signal: events::FatalSignalType::SIGSEGV,
                    stack_dump: None,
                }),
            }
        )
    }

    #[test]
    fn can_parse_fatal_signal_11() {
        //initialize a random system start time
        let system_start_time = Utc.timestamp_millis(6433742);

        let kmsgs = vec![
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372858970000),
                message: String::from("potentially unexpected fatal signal 11."),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372852970000),
                message: String::from(
                    "CPU: 1 PID: 36075 Comm: a.out Not tainted 4.14.131-linuxkit #1",
                ),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372855970000),
                message: String::from("Hardware name:  BHYVE, BIOS 1.00 03/14/2014"),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372850970000),
                message: String::from("task: ffff9b08f2e1c3c0 task.stack: ffffb493c0e98000"),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372858970000),
                message: String::from("RIP: 0033:0x561bc8d8f12e"),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372851970000),
                message: String::from("RSP: 002b:00007ffd5833d0c0 EFLAGS: 00010246"),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372856970000),
                message: String::from(
                    "RAX: 0000000000000000 RBX: 0000000000000000 RCX: 00007fd15e0e0718",
                ),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372857970000),
                message: String::from(
                    "RDX: 00007ffd5833d1b8 RSI: 00007ffd5833d1a8 RDI: 0000000000000001",
                ),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372855970000),
                message: String::from(
                    "RBP: 00007ffd5833d0c0 R08: 00007fd15e0e1d80 R09: 00007fd15e0e1d80",
                ),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372852970000),
                message: String::from(
                    "R10: 0000000000000000 R11: 0000000000000000 R12: 0000561bc8d8f040",
                ),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372850970000),
                message: String::from(
                    "R13: 00007ffd5833d1a0 R14: 0000000000000000 R15: 0000000000000000",
                ),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372856970000),
                message: String::from(
                    "FS:  00007fd15e0e7500(0000) GS:ffff9b08ffd00000(0000) knlGS:0000000000000000",
                ),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372853970000),
                message: String::from("CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033"),
            },
            kmsg::KMsg {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372854970000),
                message: String::from(
                    "CR2: 0000000000000000 CR3: 0000000132d26005 CR4: 00000000000606a0",
                ),
            },
        ];

        let mut parser = EventParser::from_kmsg_iterator_and_system_start_time(
            Box::new(kmsgs.into_iter()),
            0,
            system_start_time,
        );
        let sig11 = parser.next();
        assert!(sig11.is_some());
        assert_eq!(
            sig11.unwrap(),
            events::Event {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                timestamp: system_start_time.add(ChronoDuration::microseconds(372858970000)),
                event_type: events::EventType::FatalSignal(events::FatalSignalInfo {
                    signal: events::FatalSignalType::SIGSEGV,
                    stack_dump: Some(events::StackDump {
                        cpu: 1,
                        pid: 36075,
                        command: "a.out".to_owned(),
                        kernel: "Not tainted 4.14.131-linuxkit #1".to_owned(),
                        hardware: "BHYVE, BIOS 1.00 03/14/2014".to_owned(),
                        taskinfo: map!("task.stack" => "ffffb493c0e98000", "task" => "ffff9b08f2e1c3c0"),
                        registers: HashMap::new(),
                    })
                }),
            }
        )
    }

    #[test]
    fn is_sendable() {
        //initialize a random system start time
        let system_start_time = Utc.timestamp_millis(57533475);

        let kmsgs = vec![
            kmsg::KMsg{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                duration_from_system_start: ChronoDuration::microseconds(372850970000),
                message: String::from(" a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
            },
        ];

        let mut parser = EventParser::from_kmsg_iterator_and_system_start_time(
            Box::new(kmsgs.into_iter()),
            0,
            system_start_time,
        );

        thread::spawn(move || {
            let maybe_segfault = parser.next();
            assert!(maybe_segfault.is_some());
            let segfault = maybe_segfault.unwrap();
            assert_eq!(
                segfault,
                events::Event {
                    facility: events::LogFacility::Kern,
                    level: events::LogLevel::Warning,
                    timestamp: system_start_time.add(ChronoDuration::microseconds(372850970000)),
                    event_type: events::EventType::KernelTrap(events::KernelTrapInfo {
                        trap: events::KernelTrapType::Segfault(0),
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
                    })
                }
            );
        });

        assert!(
            true,
            "If this compiles, EventParser is Send-able across threads."
        );
    }

    #[test]
    fn can_parse_suppressed_callback() {
        //initialize a random system start time
        let system_start_time = Utc.timestamp_millis(803835);

        let kmsgs = vec![kmsg::KMsg {
            facility: events::LogFacility::Kern,
            level: events::LogLevel::Warning,
            duration_from_system_start: ChronoDuration::microseconds(372850970000),
            message: String::from("show_signal_msg: 9 callbacks suppressed"),
        }];

        let mut parser = EventParser::from_kmsg_iterator_and_system_start_time(
            Box::new(kmsgs.into_iter()),
            0,
            system_start_time,
        );
        let suppressed_callback = parser.next();
        assert!(suppressed_callback.is_some());
        assert_eq!(
            suppressed_callback.unwrap(),
            events::Event {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                timestamp: system_start_time.add(ChronoDuration::microseconds(372850970000)),
                event_type: events::EventType::SuppressedCallback(events::SuppressedCallbackInfo {
                    function_name: "show_signal_msg".to_owned(),
                    count: 9,
                }),
            }
        )
    }
}
