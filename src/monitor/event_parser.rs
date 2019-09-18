extern crate regex;
extern crate num;

use crate::events;
use crate::monitor::kmsg;

use regex::Regex;
use std::str::FromStr;

pub struct EventParser {
    kmsg_iter: Box<dyn Iterator<Item = kmsg::KMsg>>,
    verbosity: u8,
}

impl EventParser{
    pub fn from_kmsg_iterator(kmsg_iter: Box<dyn Iterator<Item = kmsg::KMsg>>, verbosity: u8) -> EventParser { 
            EventParser {
                kmsg_iter,
                verbosity,
            }
    }

    fn parse_next_event(&mut self) -> Result<events::Event, String> {
        // find the next event (we don't use a for loop because we don't want to move
        // the iterator outside of self. We only want to move next() values out of the iterator.
        loop {
            let maybe_kmsg_entry = self.kmsg_iter.next();
            match maybe_kmsg_entry {
                Some(kmsg_entry) => {
                    if let Some(e) = self.parse_kernel_trap(kmsg_entry) {
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
    // ====>> a.out[33629]: <some text> ip 0000556b4c03c603 sp 00007ffe55496510 error 4
    // Optionally followed by
    // ====>>  in a.out[556b4c03c000+1000]
    fn parse_kernel_trap(&mut self, km: kmsg::KMsg) -> Option<events::Event> {
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
        
        if self.verbosity > 2 { eprintln!("Monitor:: parse_kernel_trap:: Attempting to kernel log as kernel trap: {:?}", km); }

        if let Some(dmesg_parts) = RE_WITHOUT_LOCATION.captures(km.message.as_str()) {
            if let (procname, Some(pid), Some(trap), Some(ip), Some(sp), Some(errcode), maybelocation) = 
                (&dmesg_parts["procname"], self.parse_fragment::<usize>(&dmesg_parts["pid"]), 
                self.parse_kernel_trap_type(&dmesg_parts["message"]), self.parse_hex::<usize>(&dmesg_parts["ip"]), 
                self.parse_hex::<usize>(&dmesg_parts["sp"]), self.parse_hex::<u8>(&dmesg_parts["errcode"]), 
                &dmesg_parts["maybelocation"]) {

                if self.verbosity > 2 { eprintln!("Monitor:: parse_kernel_trap:: Successfully parsed kernel trap parts: {:?}", dmesg_parts); }

                let (file, vmastart, vmasize) = if let Some(location_parts) = RE_LOCATION.captures(maybelocation) {
                    if self.verbosity > 2 { eprintln!("Monitor:: parse_kernel_trap:: Successfully parsed kernel trap location: {:?}", location_parts); }
                    (Some((&location_parts["file"]).to_owned()), self.parse_hex::<usize>(&location_parts["vmastart"]), self.parse_hex::<usize>(&location_parts["vmasize"]))
                } else {
                    (None, None, None)
                };

                let trapinfo = events::KernelTrapInfo{
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

                if self.verbosity > 2 { eprintln!("Monitor:: parse_kernel_trap:: Successfully parsed kernel trap: {:?}", trapinfo); }
                return Some(events::Event::KernelTrap(km.info, trapinfo));
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
                segfault[[:space:]]*at[[:space:]]*(?P<location>[[:xdigit:]]*)
                [[:space:]]*$").unwrap();

            static ref RE_INVALID_OPCODE: Regex = Regex::new(r"(?x)^[[:space:]]*trap[[:space:]]*invalid[[:space:]]*opcode[[:space:]]*$").unwrap();
        }

        if let Some(segfault_parts) = RE_SEGFAULT.captures(trap_string) {
            if let Some(location) = self.parse_hex::<usize>(&segfault_parts["location"]) {
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
    fn parse_fatal_signal_11(&mut self) {

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

    fn parse_hex<N: num::Num + typename::TypeName>(&mut self, frag: &str) -> Option<N>
    where <N as num::Num>::FromStrRadixErr: std::fmt::Display
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
    fn can_parse_kernel_trap_segfault() {
        let kmsgs = vec![
            kmsg::KMsg{
                info: events::EventInfo{
                    facility: events::LogFacility::Kern,
                    level: events::LogLevel::Warning,
                    timestamp: 372850970000,
                },
                message: String::from(" a.out[36075]: segfault at 0 ip 0000561bc8d8f12e sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
            },
            kmsg::KMsg{
                info: events::EventInfo{
                    facility: events::LogFacility::Kern,
                    level: events::LogLevel::Warning,
                    timestamp: 372850970000,
                },
                message: String::from(" a.out[36075]: segfault at 0 ip (null) sp 00007ffd5833d0c0 error 4 in a.out[561bc8d8f000+1000]"),
            },
            kmsg::KMsg{
                info: events::EventInfo{
                    facility: events::LogFacility::Kern,
                    level: events::LogLevel::Warning,
                    timestamp: 372850970000,
                },
                message: String::from("a.out[37659]: segfault at 7fff4b8ba8b8 ip 00007fff4b8ba8b8 sp 00007fff4b8ba7b8 error 15"),
            },
        ];

        let mut parser = EventParser::from_kmsg_iterator(Box::new(kmsgs.into_iter()), 0);

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, events::Event::KernelTrap(events::EventInfo{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                timestamp: 372850970000,
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
                file: Some(String::from("a.out")),
                vmastart: Some(0x561bc8d8f000),
                vmasize: Some(0x1000),
            }));

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, events::Event::KernelTrap(events::EventInfo{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                timestamp: 372850970000,
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
                file: Some(String::from("a.out")),
                vmastart: Some(0x561bc8d8f000),
                vmasize: Some(0x1000),
            }));

        let maybe_segfault = parser.next();
        assert!(maybe_segfault.is_some());
        let segfault = maybe_segfault.unwrap();
        assert_eq!(segfault, events::Event::KernelTrap(events::EventInfo{
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                timestamp: 372850970000,
            },
            events::KernelTrapInfo{
                trap: events::KernelTrapType::Segfault(0x7fff4b8ba8b8),
                procname: String::from("a.out"),
                pid: 37659,
                ip: 0x7fff4b8ba8b8,
                sp: 0x00007fff4b8ba7b8,
                errcode: events::SegfaultErrorCode{
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
            }));

    }
}
