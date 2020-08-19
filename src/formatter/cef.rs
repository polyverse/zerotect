use crate::events;
use crate::formatter::{FormatResult, Formatter};
use rust_cef::ToCef;

pub struct CEFFormatter {}
impl Formatter for CEFFormatter {
    fn format(&self, event: &events::Version) -> FormatResult {
        Ok(event.to_cef()?)
    }
}

/**********************************************************************************/
// Tests! Tests! Tests!

#[cfg(test)]
mod test {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::collections::HashMap;

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
    fn test_linux_kernel_trap() {
        let timestamp = Utc.timestamp_millis(471804323);

        let event1 = events::Version::V1 {
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
        };

        let formatter = CEFFormatter {};

        assert_eq!(
            formatter.format(&event1).unwrap(),
            "CEF:0|polyverse|zerotect|V1|LinuxKernelTrap|Linux Kernel Trap|10|access_mode=User access_type=Read file=a.out instruction_fetch=false ip=0 pid=36275 procname=a.out protection_keys_block_access=false reason=NoPageFound sp=140726083244224 use_of_reserved_bit=false vmasize=4096 vmastart=94677333766144"
        );
    }

    #[test]
    fn test_linux_fatal_signal() {
        let timestamp = Utc.timestamp_millis(471804323);

        let event1 = events::Version::V1 {
            timestamp,
            event: events::EventType::LinuxFatalSignal(events::LinuxFatalSignal {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                signal: events::FatalSignalType::SIGSEGV,
                stack_dump: Some(events::StackDump {
                    cpu: 1,
                    pid: 36075,
                    command: "a.out".to_owned(),
                    kernel: "Not tainted 4.14.131-linuxkit #1".to_owned(),
                    hardware: "BHYVE, BIOS 1.00 03/14/2014".to_owned(),
                    taskinfo: map!("task.stack" => "ffffb493c0e98000", "task" => "ffff9b08f2e1c3c0"),
                    registers: HashMap::new(),
                }),
            }),
        };

        let formatter = CEFFormatter {};

        assert_eq!(
            formatter.format(&event1).unwrap(),
            "CEF:0|polyverse|zerotect|V1|LinuxFatalSignal|Linux Fatal Signal|10|command=a.out cpu=1 hardware=BHYVE, BIOS 1.00 03/14/2014 kernel=Not tainted 4.14.131-linuxkit #1 pid=36075 signal=SIGSEGV task.stack=ffffb493c0e98000 task=ffff9b08f2e1c3c0"
        );
    }

    #[test]
    fn test_linux_suppressed_callback() {
        let timestamp = Utc.timestamp_millis(471804323);

        let event1 = events::Version::V1 {
            timestamp,
            event: events::EventType::LinuxSuppressedCallback(events::LinuxSuppressedCallback {
                facility: events::LogFacility::Kern,
                level: events::LogLevel::Warning,
                function_name: "show_signal_msg".to_owned(),
                count: 9,
            }),
        };

        let formatter = CEFFormatter {};

        assert_eq!(formatter.format(&event1).unwrap(), "CEF:0|polyverse|zerotect|V1|ConfigMismatch|Configuration mismatched what zerotect expected|4|expected_value=Y key=/sys/module/printk/parameters/time observed_value=N");
    }

    #[test]
    fn test_zerotect_config_mismatch() {
        let timestamp = Utc.timestamp_millis(471804323);

        let event1 = events::Version::V1 {
            timestamp,
            event: events::EventType::ConfigMismatch(events::ConfigMismatch {
                key: "/sys/module/printk/parameters/time".to_owned(),
                expected_value: "Y".to_owned(),
                observed_value: "N".to_owned(),
            }),
        };

        let formatter = CEFFormatter {};

        assert_eq!(formatter.format(&event1).unwrap(), "CEF:0|polyverse|zerotect|V1|LinuxSuppressedCallback|Linux kernel suppressed repetitive log entries|3|count=9 function_name=show_signal_msg");
    }
}
