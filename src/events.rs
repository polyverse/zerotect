// Copyright (c) 2019 Polyverse Corporation

use chrono::{DateTime, Utc};
use num_derive::FromPrimitive;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::Arc;
use strum_macros::EnumString;
use typename::TypeName;

pub type Event = Arc<Version>;

/// Event is the complete structure that Polycorder (Polyverse-hosted
/// zero-day detection service) understands. This structure is also
/// the reference schema/format for all detect-efforts.
///
/// As such, it is encouraged to have many detectors that emit
/// data in this structure.
///
/// Different implementations of the structure may very. Various fields
/// may come or go.
///
/// All parsers are encouraged to first test the "Version" field and then
/// parse the correct structure. The field `version` is guaranteed to exist
/// on ALL versions and instances of Event. Any structure/data that does not
/// contain the version field, is considered invalid.
///
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    JsonSchema,
    ToCef,
    CefHeaderVersion,
    CefHeaderDeviceVendor,
    CefHeaderDeviceProduct,
    CefHeaderDeviceVersion,
    CefHeaderDeviceEventClassID,
    CefHeaderName,
    CefHeaderSeverity,
    CefExtensions,
)]
#[cef_values(
    CefHeaderVersion = "0",
    CefHeaderDeviceVendor = "polyverse",
    CefHeaderDeviceProduct = "zerotect"
)]
#[serde(tag = "version")]
pub enum Version {
    /// Version is guaranteed to exist. All other fields may change or not exist,
    /// and it is recommended to use a different version when making breaking changes
    /// to all other fields. It allows parsers to test on version and determine if they
    /// know what to do with the rest.
    /// For this particular variant, set DeviceVersion to a fixed value "V1"
    #[cef_values(CefHeaderDeviceVersion = "V1")]
    V1 {
        /// This is universal and important for all events. They occur at a time.
        timestamp: DateTime<Utc>,

        /// Platform records fields specific to a specific mechanism/platform.
        // For this variant, inherit the other three headers from the event field
        #[cef_inherit(CefHeaderDeviceEventClassID, CefHeaderName, CefHeaderSeverity)]
        #[cef_ext_gobble]
        event: EventType,
    },
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Version::V1 { timestamp, event } => write!(f, "Event<V1,{}>::{}", timestamp, event),
        }
    }
}

/// The Platform this event originated on.
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    JsonSchema,
    CefHeaderDeviceEventClassID,
    CefHeaderName,
    CefHeaderSeverity,
    CefExtensions,
)]
#[serde(tag = "type")]
pub enum EventType {
    /// An analytics-detected internal event based on other events
    #[cef_values(
        CefHeaderDeviceEventClassID = "InstructionPointerProbe",
        CefHeaderName = "Probe using Instruction Pointer Increment",
        CefHeaderSeverity = "10"
    )]
    InstructionPointerProbe(#[cef_ext_gobble] InstructionPointerProbe),

    /// An analytics-detected internal event based on other events
    #[cef_values(
        CefHeaderDeviceEventClassID = "RegisterProbe",
        CefHeaderName = "Probe using Register Increment",
        CefHeaderSeverity = "10"
    )]
    RegisterProbe(#[cef_ext_gobble] RegisterProbe),

    /// The Linux platform and event details in the Linux context
    /// A Kernel Trap event - the kernel stops process execution for attempting something stupid
    #[cef_values(
        CefHeaderDeviceEventClassID = "LinuxKernelTrap",
        CefHeaderName = "Linux Kernel Trap",
        CefHeaderSeverity = "10"
    )]
    LinuxKernelTrap(#[cef_ext_gobble] LinuxKernelTrap),

    /// A Fatal Signal from the process because the process did something stupid
    #[cef_values(
        CefHeaderDeviceEventClassID = "LinuxFatalSignal",
        CefHeaderName = "Linux Fatal Signal",
        CefHeaderSeverity = "10"
    )]
    LinuxFatalSignal(#[cef_ext_gobble] LinuxFatalSignal),

    /// Information about a suppressed callback i.e. when a particular
    /// type of error happens so much it is suppressed 'n' times.
    ///
    /// This captures what the log was, and how many times it was suppressed.
    ///
    /// This is a crucial data point because under Blind ROP attacks an error
    /// might happen thousands of times but may only be logged once, with all the
    /// remaining attempts being suppressed.
    #[cef_values(
        CefHeaderDeviceEventClassID = "LinuxSuppressedCallback",
        CefHeaderName = "Linux kernel suppressed repetitive log entries",
        CefHeaderSeverity = "3"
    )]
    LinuxSuppressedCallback(#[cef_ext_gobble] LinuxSuppressedCallback),

    /// This is a zerotect-internal event. zerotect can be commanded to set and ensure certain
    /// configuration settings to capture events, such as enabling kernel fatal-signals, or
    /// core dumps.
    ///
    /// This event is triggered when, after zerotect has configured a machine as commanded, the
    /// configuration later mismatched. It means someone attempted to undo those changes.
    ///
    /// This event usually tells an observer they may not be seeing other events because they may be
    /// disabled.
    #[cef_values(
        CefHeaderDeviceEventClassID = "ConfigMismatch",
        CefHeaderName = "Configuration mismatched what zerotect expected",
        CefHeaderSeverity = "4"
    )]
    ConfigMismatch(#[cef_ext_gobble] ConfigMismatch),
}

impl Display for EventType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            EventType::InstructionPointerProbe(InstructionPointerProbe {
                justifying_events,
            }) => {
                write!(f,
                    "Instruction Pointers found close to each other {} times. The set of events that justify this analyzed event are: {:?}", justifying_events.len(), justifying_events)
            },
            EventType::LinuxKernelTrap(LinuxKernelTrap {
                level,
                facility,
                trap,
                procname,
                pid,
                ip,
                sp,
                errcode,
                file,
                vmasize,
                vmastart,
            }) => {
                let location = if let (Some(file), Some(vmastart), Some(vmasize)) =
                    (file.as_ref(), vmastart, vmasize)
                {
                    Some(format!(
                        "in file {} (VMM region {} of size {})",
                        file, vmastart, vmasize
                    ))
                } else {
                    None
                };

                write!(
                    f,
                    "<log_level: {}, log_facility: {}>{}:: {} by process {}(pid:{}, instruction pointer: {}, stack pointer: {}) {}.",
                    level,
                    facility,
                    trap,
                    errcode,
                    procname,
                    pid,
                    ip,
                    sp,
                    location.unwrap_or_default()
                )
            }
            EventType::LinuxFatalSignal(LinuxFatalSignal {
                level,
                facility,
                signal,
                stack_dump,
            }) => {
                write!(
                    f,
                    "<log_level: {}, log_facility: {}>Fatal Signal: {}({}, StackDump: {:?})",
                    level,
                    facility,
                    signal,
                    // https://stackoverflow.com/questions/31358826/how-do-i-convert-an-enum-reference-to-a-number
                    *signal as u8,
                    stack_dump,
                )
            }
            EventType::LinuxSuppressedCallback(LinuxSuppressedCallback {
                level,
                facility,
                function_name,
                count,
            }) => write!(
                f,
                "<log_level: {}, log_facility: {}>Suppressed {} callbacks to {}",
                level, facility, count, &function_name,
            ),
            EventType::ConfigMismatch(ConfigMismatch {
                key,
                expected_value,
                observed_value,
            }) => write!(
                f,
                "Configuration key {} should have been {}, but found to be {}",
                &key, &expected_value, &observed_value
            ),
        }
    }
}

/// This event represents a probe using the instruction pointer
/// i.e. someone is exploiting a buffer overflow to visit various random
/// instruction locations in memory and trying to execute at them.
///
/// The goal is to find beneficial or suitable instructions that are
/// executable and helpful.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InstructionPointerProbe {
    /// How many pairs of kernel events offcurred with an instruction pointer that was
    /// mutually close. For example if there were 3 segfaults, each with IP:
    /// 0x1000, 0x1008 and 0x100B, then the first two are 8-bytes apart, the next two
    /// are 4 bytes apart. This means there were two pairs of close-IPs.
    /// The events which justify this analytics event.
    pub justifying_events: Vec<Event>,
}

impl rust_cef::CefExtensions for InstructionPointerProbe {
    fn cef_extensions(
        &self,
        collector: &mut HashMap<String, String>,
    ) -> rust_cef::CefExtensionsResult {
        collector.insert(
            "number_of_segfaults_with_instruction_pointer_within_word_size".to_owned(),
            format!("{}", self.justifying_events.len()),
        );
        Ok(())
    }
}

/// This event represents a probe using a Register
/// i.e. someone is probing/fuzzing a program with different values of
/// a particular register.
///
/// When probing a stack canary, RDI/RSI increment by one value, for instance.
///
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterProbe {
    /// Which register was being probed?
    pub register: String,

    /// What does this probe mean? What interpretation could this
    /// particular register probe have?
    pub message: String,

    /// The raw events which justify this analytics event.
    pub justifying_events: Vec<Event>,
}

impl rust_cef::CefExtensions for RegisterProbe {
    fn cef_extensions(
        &self,
        collector: &mut HashMap<String, String>,
    ) -> rust_cef::CefExtensionsResult {
        collector.insert(
            "number_of_segfaults_with_instruction_pointer_within_word_size".to_owned(),
            format!("{}", self.justifying_events.len()),
        );
        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, JsonSchema, CefExtensions)]
pub struct LinuxKernelTrap {
    /// The type of kernel trap triggered
    /// A Log-level for this event - was it critical?
    pub level: LogLevel,

    /// A Log-facility - most OSes would have one, but this is Linux-specific for now
    pub facility: LogFacility,

    pub trap: KernelTrapType,

    #[cef_ext_field]
    /// Name of the process in which the trap occurred
    pub procname: String,

    #[cef_ext_field]
    /// Process ID
    pub pid: usize,

    #[cef_ext_field]
    /// Instruction Pointer (what memory address was executing)
    pub ip: usize,

    #[cef_ext_field]
    /// Stack Pointer
    pub sp: usize,

    /// The error code for the trap
    #[cef_ext_gobble]
    pub errcode: SegfaultErrorCode,

    /// (Optional) File in which the trap occurred (could be the main executable or library).
    #[cef_ext_optional_field]
    pub file: Option<String>,

    /// (Optional) The Virtual Memory Address where this file (main executable or library) was mapped (with ASLR could be arbitrary).
    #[cef_ext_optional_field]
    pub vmastart: Option<usize>,

    /// (Optional) The Virtual Memory Size of this file's mapping.
    #[cef_ext_optional_field]
    pub vmasize: Option<usize>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, JsonSchema, CefExtensions)]
pub struct LinuxFatalSignal {
    /// A Log-level for this event - was it critical?
    pub level: LogLevel,

    /// A Log-facility - most OSes would have one, but this is Linux-specific for now
    pub facility: LogFacility,

    /// The type of Fatal triggered
    #[cef_ext_field]
    pub signal: FatalSignalType,

    /// An Optional Stack Dump if one was found and parsable.
    #[cef_ext_gobble_kv_iterator]
    pub stack_dump: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, JsonSchema, CefExtensions)]
pub struct LinuxSuppressedCallback {
    /// A Log-level for this event - was it critical?
    pub level: LogLevel,

    /// A Log-facility - most OSes would have one, but this is Linux-specific for now
    pub facility: LogFacility,

    /// Name of the function being suppressed/folded.
    #[cef_ext_field]
    pub function_name: String,

    /// Number of times it was suppressed.
    #[cef_ext_field]
    pub count: usize,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, JsonSchema, CefExtensions)]
pub struct ConfigMismatch {
    /// The key in question whose values mismatched.
    #[cef_ext_field]
    pub key: String,

    /// The value zerotect configured and thus expected.
    #[cef_ext_field]
    pub expected_value: String,

    /// The value zerotect observed.
    #[cef_ext_field]
    pub observed_value: String,
}

/// Linux kmesg (kernel message buffer) Log Facility.
#[derive(
    EnumString,
    Debug,
    PartialEq,
    TypeName,
    Display,
    FromPrimitive,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub enum LogFacility {
    #[strum(serialize = "kern")]
    Kern = 0,

    #[strum(serialize = "user")]
    User,

    #[strum(serialize = "mail")]
    Mail,

    #[strum(serialize = "daemon")]
    Daemon,

    #[strum(serialize = "auth")]
    Auth,

    #[strum(serialize = "syslog")]
    Syslog,

    #[strum(serialize = "lpr")]
    Lpr,

    #[strum(serialize = "news")]
    News,

    #[strum(serialize = "uucp")]
    UUCP,

    #[strum(serialize = "cron")]
    Cron,

    #[strum(serialize = "authpriv")]
    AuthPriv,

    #[strum(serialize = "ftp")]
    FTP,
}

/// Linux kmesg (kernel message buffer) Log Level.
#[derive(
    EnumString,
    Debug,
    PartialEq,
    TypeName,
    Display,
    FromPrimitive,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub enum LogLevel {
    #[strum(serialize = "emerg")]
    Emergency = 0,

    #[strum(serialize = "alert")]
    Alert,

    #[strum(serialize = "crit")]
    Critical,

    #[strum(serialize = "err")]
    Error,

    #[strum(serialize = "warn")]
    Warning,

    #[strum(serialize = "notice")]
    Notice,

    #[strum(serialize = "info")]
    Info,

    #[strum(serialize = "debug")]
    Debug,
}

/// The types of kernel traps understood
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum KernelTrapType {
    /// This is type zerotect doesn't know how to parse. So it captures and stores the string description.
    Generic {
        description: String,
    },

    /// Segfault occurs when an invalid memory access is performed (writing to read-only memory,
    /// executing non-executable memory, etc.)
    Segfault {
        location: usize,
    },

    /// Invalid Opcode occurs when the processor doesn't understand an opcode. This usually occurs
    /// when execution jumps to an otherwise data segment, or in the wrong byte within an instruction.
    InvalidOpcode,

    // General Protection Fault
    GeneralProtectionFault,
}

impl Display for KernelTrapType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            KernelTrapType::Segfault { location } => write!(f, "Segfault at location {}", location),
            KernelTrapType::InvalidOpcode => write!(f, "Invalid Opcode"),
            KernelTrapType::GeneralProtectionFault => write!(f, "General Protection Fault"),
            KernelTrapType::Generic { description } => {
                write!(f, "Please parse this kernel trap: {}", description)
            }
        }
    }
}

/// The reason for the Segmentation Fault
#[derive(EnumString, Debug, Display, PartialEq, Clone, Serialize, Deserialize, JsonSchema)]
pub enum SegfaultReason {
    /// The page attempted to access was not found (i.e. in invalid memory address)
    NoPageFound,

    /// The memory access was illegal (i.e. protection kicked in)
    /// For example, writing to read-only memory or executing non-executable memory.
    ProtectionFault,
}

/// The type of Access that triggered this Segmentation Fault
#[derive(EnumString, Debug, Display, PartialEq, Clone, Serialize, Deserialize, JsonSchema)]
pub enum SegfaultAccessType {
    /// Attempting to Read
    Read,

    /// Attempting to Write
    Write,
}

/// The context under which the Segmentation Fault was triggered
#[derive(EnumString, Debug, Display, PartialEq, Clone, Serialize, Deserialize, JsonSchema)]
pub enum SegfaultAccessMode {
    /// Process was in kernel mode (during a syscall, context switch, etc.)
    Kernel,
    /// Process was in user mode (userspace), i.e. the program was at fault.
    User,
}

/// Segmentation Fault ErrorCode flags parsed into a structure
/// See more: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/traps.h#n167
/// See more: https://utcc.utoronto.ca/~cks/space/blog/linux/KernelSegfaultMessageMeaning
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, JsonSchema, CefExtensions)]
pub struct SegfaultErrorCode {
    /// The reason for the segmentation fault
    #[cef_ext_field]
    pub reason: SegfaultReason,

    /// The type of access causing the fault
    #[cef_ext_field]
    pub access_type: SegfaultAccessType,

    /// The mode under which access was performed
    #[cef_ext_field]
    pub access_mode: SegfaultAccessMode,

    /// use of reserved bits in the page table entry detected (the kernel will panic if this happens)
    #[cef_ext_field]
    pub use_of_reserved_bit: bool,

    /// fault was an instruction fetch, not data read or write
    #[cef_ext_field]
    pub instruction_fetch: bool,

    /// Memory Protection Keys related. Not sure what exactly triggers this.
    /// See more: https://lore.kernel.org/patchwork/patch/633070/
    #[cef_ext_field]
    pub protection_keys_block_access: bool,
}

impl SegfaultErrorCode {
    const REASON_BIT: u8 = 1 << 0;
    const ACCESS_TYPE_BIT: u8 = 1 << 1;
    const ACCESS_MODE_BIT: u8 = 1 << 2;
    const USE_OF_RESERVED_BIT: u8 = 1 << 3;
    const INSTRUCTION_FETCH_BIT: u8 = 1 << 4;
    const PROTECTION_KEYS_BLOCK_ACCESS_BIT: u8 = 1 << 5;

    pub fn from_error_code(code: u8) -> SegfaultErrorCode {
        SegfaultErrorCode {
            reason: match (code & SegfaultErrorCode::REASON_BIT) > 0 {
                false => SegfaultReason::NoPageFound,
                true => SegfaultReason::ProtectionFault,
            },
            access_type: match (code & SegfaultErrorCode::ACCESS_TYPE_BIT) > 0 {
                false => SegfaultAccessType::Read,
                true => SegfaultAccessType::Write,
            },
            access_mode: match (code & SegfaultErrorCode::ACCESS_MODE_BIT) > 0 {
                false => SegfaultAccessMode::Kernel,
                true => SegfaultAccessMode::User,
            },
            use_of_reserved_bit: (code & SegfaultErrorCode::USE_OF_RESERVED_BIT) > 0,
            instruction_fetch: (code & SegfaultErrorCode::INSTRUCTION_FETCH_BIT) > 0,
            protection_keys_block_access: (code
                & SegfaultErrorCode::PROTECTION_KEYS_BLOCK_ACCESS_BIT)
                > 0,
        }
    }
}

impl Display for SegfaultErrorCode {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        if self.use_of_reserved_bit {
            write!(f, "use of reserved bits in the page table entry detected")
        } else if self.protection_keys_block_access {
            write!(f, "protection keys block access (needs more documentation)")
        } else {
            let data_or_instruction = match self.instruction_fetch {
                false => "data",
                true => "instruction fetch",
            };

            write!(
                f,
                "{} triggered by a {}-mode {} {}",
                self.reason, self.access_mode, data_or_instruction, self.access_type
            )
        }
    }
}

/// The type of Fatal Signal detected
/// Comprehensive list of POSIX signals in the linux kernel
/// can be found int he kernel source tree:
/// https://github.com/torvalds/linux/blob/master/include/linux/signal.h#L339
///
/// A bit more detail may be found in the man-pages:
/// http://man7.org/linux/man-pages/man7/signal.7.html
#[derive(
    Debug,
    PartialEq,
    EnumString,
    FromPrimitive,
    Display,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub enum FatalSignalType {
    /// Hangup detected on controlling terminal or death of controlling process
    SIGHUP = 1,

    /// Interrupt from keyboard
    SIGINT,

    /// Quit from keyboard
    SIGQUIT,

    /// Illegal Instruction
    SIGILL,

    /// Trace/breakpoint trap (typically used by debuggers)
    SIGTRAP,

    /// IOT trap or Abort signal from abort: http://man7.org/linux/man-pages/man3/abort.3.html. (synonym: SIGABRT)
    SIGIOT,

    /// Bus error (bad memory access)
    SIGBUS,

    /// Floating-point exception
    SIGFPE,

    /// Kill signal
    SIGKILL,

    /// User-defined signal 1
    SIGUSR1,

    /// Invalid memory reference
    SIGSEGV,

    /// User-defined signal 2
    SIGUSR2,

    /// Broken pipe: write to pipe with no readers; see: http://man7.org/linux/man-pages/man7/pipe.7.html
    SIGPIPE,

    /// Timer signal from alarm: http://man7.org/linux/man-pages/man2/alarm.2.html
    SIGALRM,

    /// Termination signal
    SIGTERM,

    /// Stack fault on coprocessor (unused)
    SIGSTKFLT,

    /// Child stopped or terminated (synonym: SIGCLD)
    SIGCHLD,

    /// Continue if stopped (typically used by debuggers)
    SIGCONT,

    /// Stop process (typically used by debuggers)
    SIGSTOP,

    /// Stop typed at terminal
    SIGTSTP,

    /// Terminal input for background process
    SIGTTIN,

    /// Terminal output for background process
    SIGTTOU,

    /// Urgent condition on socket (4.2BSD)
    SIGURG,

    /// CPU time limit exceeded (4.2BSD); See: http://man7.org/linux/man-pages/man2/setrlimit.2.html
    SIGXCPU,

    /// File size limit exceeded (4.2BSD); See: http://man7.org/linux/man-pages/man2/setrlimit.2.html
    SIGXFSZ,

    /// Virtual alarm clock (4.2BSD)
    SIGVTALRM,

    /// Profiling timer expired
    SIGPROF,

    /// Window resize signal (4.3BSD, Sun)
    SIGWINCH,

    /// I/O now possible (4.2BSD) or Pollable event (Sys V). (synonym: SIGPOLL)
    SIGIO,

    /// Power failure (System V) (synonym: SIGINFO)
    SIGPWR,
}

/**********************************************************************************/
// Tests! Tests! Tests!

#[cfg(test)]
mod test {
    use super::*;
    use schemars::schema_for;
    use serde_json;
    use std::fs;
    use std::mem;

    #[test]
    fn generate_reference_json_schema_file() {
        let schema_file = format!("{}{}", env!("CARGO_MANIFEST_DIR"), "/reference/schema.json");
        let schema = schema_for!(Version);
        let schema_json = serde_json::to_string_pretty(&schema).unwrap();
        eprintln!("Writing latest event schema to file: {}", schema_file);
        fs::write(schema_file, schema_json).expect("Unable to re-generate the event schema file.");
    }

    #[test]
    fn measure_size_of_event() {
        // You can decide when to use Version and when to use Event = Arc'd Version
        assert_eq!(168, mem::size_of::<Version>());
        assert_eq!(8, mem::size_of::<Event>());
    }
}
