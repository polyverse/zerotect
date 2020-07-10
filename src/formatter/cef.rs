use crate::events;
use crate::formatter::{FormatResult, Formatter};

// CEF:Version|Device Vendor|Device Product|
const CEF_PREFIX: &str = "CEF:0|polyverse|zerotect";

pub struct CEFFormatter {}
impl Formatter for CEFFormatter {
    fn format(&self, event: &events::Version) -> FormatResult {
        let mut cef_event = String::from(CEF_PREFIX);

        match event {
            events::Version::V1{timestamp: _, event: event_type} => {
                // | Device Version
                cef_event.push_str("|V1");

                // | Device Event Class ID | Name | Severity
                match event_type {
                    events::EventType::LinuxKernelTrap{..} => cef_event.push_str("|LinuxKernelTrap|Linux Kernel Trap|10"),
                    events::EventType::LinuxFatalSignal{..} => cef_event.push_str("|LinuxFatalSignal|Linux Fatal Signal|10"),
                    events::EventType::ConfigMismatch{..} => cef_event.push_str("|ConfigMismatch|Configuration mismatched what zerotect expected|4"),
                    events::EventType::LinuxSuppressedCallback{..} => cef_event.push_str("|LinuxSuppressedCallback|Linux kernel suppressed repetitive log entries|3"),
                }
            }
        }

        Ok(cef_event)
    }
}

/**********************************************************************************/
// Tests! Tests! Tests!

#[cfg(test)]
mod test {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_linux_kernel_trap() {
        let timestamp = Utc.timestamp_millis(471804323);

        let event1 = events::Version::V1 {
            timestamp,
            event: events::EventType::LinuxKernelTrap {
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
            },
        };

        let formatter = CEFFormatter{};

        assert_eq!(formatter.format(&event1).unwrap(), "CEF:0|polyverse|zerotect|V1|LinuxKernelTrap|Linux Kernel Trap|10");
    }
}
