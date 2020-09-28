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
    use std::collections::BTreeMap;

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
            "CEF:0|polyverse|zerotect|1.0|LinuxKernelTrap|Linux Kernel Trap|10|access_mode=User access_type=Read file=a.out instruction_fetch=false ip=0 pid=36275 procname=a.out protection_keys_block_access=false reason=NoPageFound sp=140726083244224 use_of_reserved_bit=false vmasize=4096 vmastart=94677333766144"
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
                stack_dump: BTreeMap::new(),
            }),
        };

        let formatter = CEFFormatter {};

        assert_eq!(
            formatter.format(&event1).unwrap(),
            "CEF:0|polyverse|zerotect|1.0|LinuxFatalSignal|Linux Fatal Signal|10|signal=SIGSEGV"
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
        assert_eq!(formatter.format(&event1).unwrap(), "CEF:0|polyverse|zerotect|1.0|LinuxSuppressedCallback|Linux kernel suppressed repetitive log entries|3|count=9 function_name=show_signal_msg");
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

        assert_eq!(formatter.format(&event1).unwrap(), "CEF:0|polyverse|zerotect|1.0|ConfigMismatch|Configuration mismatched what zerotect expected|4|expected_value=Y key=/sys/module/printk/parameters/time observed_value=N");
    }

    #[test]
    fn test_zerotect_register_probe() {
        let timestamp = Utc.timestamp_millis(471804323);

        let event1 = events::Version::V1 {
            timestamp,
            event: events::EventType::RegisterProbe(events::RegisterProbe {
                register: "RIP".to_owned(),
                message: "Instruction pointer".to_owned(),
                procname: "nginx".to_owned(),
                justification: events::RegisterProbeJustification::FullEvents(vec![]),
            }),
        };

        let formatter = CEFFormatter {};

        assert_eq!(formatter.format(&event1).unwrap(), "CEF:0|polyverse|zerotect|1.0|RegisterProbe|Probe using Register Increment|10|justifying_event_count=0 message=Instruction pointer procname=nginx register=RIP");
    }
}
