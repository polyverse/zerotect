use crate::events;
use crate::formatter::{FormatResult, Formatter};

pub struct JsonFormatter {}
impl Formatter for JsonFormatter {
    fn format(&self, event: &events::Version) -> FormatResult {
        Ok(serde_json::to_string(&event)?)
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

        let formatter = JsonFormatter {};

        assert_eq!(
            formatter.format(&event1).unwrap(),
            "{\"version\":\"V1\",\"timestamp\":\"1970-01-06T11:03:24.323Z\",\"event\":{\"type\":\"LinuxKernelTrap\",\"level\":\"Warning\",\"facility\":\"Kern\",\"trap\":{\"type\":\"Segfault\",\"location\":0},\"procname\":\"a.out\",\"pid\":36275,\"ip\":0,\"sp\":140726083244224,\"errcode\":{\"reason\":\"NoPageFound\",\"access_type\":\"Read\",\"access_mode\":\"User\",\"use_of_reserved_bit\":false,\"instruction_fetch\":false,\"protection_keys_block_access\":false},\"file\":\"a.out\",\"vmastart\":94677333766144,\"vmasize\":4096}}"
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

        let formatter = JsonFormatter {};

        assert_eq!(
            formatter.format(&event1).unwrap(),
            "{\"version\":\"V1\",\"timestamp\":\"1970-01-06T11:03:24.323Z\",\"event\":{\"type\":\"LinuxFatalSignal\",\"level\":\"Warning\",\"facility\":\"Kern\",\"signal\":\"SIGSEGV\",\"stack_dump\":{}}}"
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

        let formatter = JsonFormatter {};

        assert_eq!(formatter.format(&event1).unwrap(), "{\"version\":\"V1\",\"timestamp\":\"1970-01-06T11:03:24.323Z\",\"event\":{\"type\":\"LinuxSuppressedCallback\",\"level\":\"Warning\",\"facility\":\"Kern\",\"function_name\":\"show_signal_msg\",\"count\":9}}");
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

        let formatter = JsonFormatter {};

        assert_eq!(formatter.format(&event1).unwrap(), "{\"version\":\"V1\",\"timestamp\":\"1970-01-06T11:03:24.323Z\",\"event\":{\"type\":\"ConfigMismatch\",\"key\":\"/sys/module/printk/parameters/time\",\"expected_value\":\"Y\",\"observed_value\":\"N\"}}");
    }

    #[test]
    fn test_zerotect_ip_probe() {
        let timestamp = Utc.timestamp_millis(471804323);

        let event1 = events::Version::V1 {
            timestamp,
            event: events::EventType::InstructionPointerProbe(events::InstructionPointerProbe {
                justifying_events: vec![],
            }),
        };

        let formatter = JsonFormatter {};

        assert_eq!(formatter.format(&event1).unwrap(), "{\"version\":\"V1\",\"timestamp\":\"1970-01-06T11:03:24.323Z\",\"event\":{\"type\":\"InstructionPointerProbe\",\"justifying_events\":[]}}");
    }
}
