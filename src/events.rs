// Copyright (c) 2019 Polyverse Corporation

use chrono::{DateTime, Utc};
use num_derive::FromPrimitive;
use schemars::JsonSchema;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};
use strum_macros::EnumString;
use typename::TypeName;

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
        #[cef_inherit(
            CefHeaderDeviceEventClassID,
            CefHeaderName,
            CefHeaderSeverity
        )]
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
    JsonSchema,
    CefHeaderDeviceEventClassID,
    CefHeaderName,
    CefHeaderSeverity,
    CefExtensions,
)]
#[serde(tag = "type")]
pub enum EventType {
    /// The Linux platform and event details in the Linux context
    /// A Kernel Trap event - the kernel stops process execution for attempting something stupid
    #[cef_values(
        CefHeaderDeviceEventClassID = "LinuxKernelTrap",
        CefHeaderName = "Linux Kernel Trap",
        CefHeaderSeverity = "10"
    )]
    LinuxKernelTrap {
        /// The type of kernel trap triggered
        /// A Log-level for this event - was it critical?
        level: LogLevel,

        /// A Log-facility - most OSes would have one, but this is Linux-specific for now
        facility: LogFacility,

        trap: KernelTrapType,

        /// Name of the process in which the trap occurred
        procname: String,

        /// Process ID
        pid: usize,

        /// Instruction Pointer (what memory address was executing)
        ip: usize,

        /// Stack Pointer
        sp: usize,

        /// The error code for the trap
        errcode: SegfaultErrorCode,

        /// (Optional) File in which the trap occurred (could be the main executable or library).
        file: Option<String>,

        /// (Optional) The Virtual Memory Address where this file (main executable or library) was mapped (with ASLR could be arbitrary).
        vmastart: Option<usize>,

        /// (Optional) The Virtual Memory Size of this file's mapping.
        vmasize: Option<usize>,
    },

    /// A Fatal Signal from the process because the process did something stupid
    #[cef_values(
        CefHeaderDeviceEventClassID = "LinuxFatalSignal",
        CefHeaderName = "Linux Fatal Signal",
        CefHeaderSeverity = "10"
    )]
    LinuxFatalSignal {
        /// A Log-level for this event - was it critical?
        level: LogLevel,

        /// A Log-facility - most OSes would have one, but this is Linux-specific for now
        facility: LogFacility,

        /// The type of Fatal triggered
        signal: FatalSignalType,

        /// An Optional Stack Dump if one was found and parsable.
        stack_dump: Option<StackDump>,
    },

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
    LinuxSuppressedCallback {
        /// A Log-level for this event - was it critical?
        level: LogLevel,

        /// A Log-facility - most OSes would have one, but this is Linux-specific for now
        facility: LogFacility,

        /// Name of the function being suppressed/folded.
        function_name: String,

        /// Number of times it was suppressed.
        count: usize,
    },

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
    ConfigMismatch {
        /// The key in question whose values mismatched.
        key: String,

        /// The value zerotect configured and thus expected.
        expected_value: String,

        /// The value zerotect observed.
        observed_value: String,
    },
}

impl Display for EventType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            EventType::LinuxKernelTrap {
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
            } => {
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
            EventType::LinuxFatalSignal {
                level,
                facility,
                signal,
                stack_dump,
            } => {
                let retval = write!(
                    f,
                    "<log_level: {}, log_facility: {}>Fatal Signal: {}({})",
                    level,
                    facility,
                    &signal,
                    signal.clone() as u8
                );

                if let Some(sd) = &stack_dump {
                    write!(f, ":: StackDump: {}", sd)
                } else {
                    retval
                }
            }
            EventType::LinuxSuppressedCallback {
                level,
                facility,
                function_name,
                count,
            } => write!(
                f,
                "<log_level: {}, log_facility: {}>Suppressed {} callbacks to {}",
                level, facility, count, &function_name,
            ),
            EventType::ConfigMismatch {
                key,
                expected_value,
                observed_value,
            } => write!(
                f,
                "Configuration key {} should have been {}, but found to be {}",
                &key, &expected_value, &observed_value
            ),
        }
    }
}

/// Linux kmesg (kernel message buffer) Log Facility.
#[derive(
    EnumString, Debug, PartialEq, TypeName, Display, FromPrimitive, Clone, Serialize, JsonSchema,
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
    EnumString, Debug, PartialEq, TypeName, Display, FromPrimitive, Clone, Serialize, JsonSchema,
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
#[derive(Debug, PartialEq, Clone, Serialize, JsonSchema)]
#[serde(tag = "type")]
pub enum KernelTrapType {
    /// This is type zerotect doesn't know how to parse. So it captures and stores the string description.
    Generic { description: String },

    /// Segfault occurs when an invalid memory access is performed (writing to read-only memory,
    /// executing non-executable memory, etc.)
    Segfault { location: usize },

    /// Invalid Opcode occurs when the processor doesn't understand an opcode. This usually occurs
    /// when execution jumps to an otherwise data segment, or in the wrong byte within an instruction.
    InvalidOpcode,
}

impl Display for KernelTrapType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            KernelTrapType::Segfault { location } => write!(f, "Segfault at location {}", location),
            KernelTrapType::InvalidOpcode => write!(f, "Invalid Opcode"),
            KernelTrapType::Generic { description } => {
                write!(f, "Please parse this kernel trap: {}", description)
            }
        }
    }
}

/// The reason for the Segmentation Fault
#[derive(EnumString, Debug, Display, PartialEq, Clone, Serialize, JsonSchema)]
pub enum SegfaultReason {
    /// The page attempted to access was not found (i.e. in invalid memory address)
    NoPageFound,

    /// The memory access was illegal (i.e. protection kicked in)
    /// For example, writing to read-only memory or executing non-executable memory.
    ProtectionFault,
}

/// The type of Access that triggered this Segmentation Fault
#[derive(EnumString, Debug, Display, PartialEq, Clone, Serialize, JsonSchema)]
pub enum SegfaultAccessType {
    /// Attempting to Read
    Read,

    /// Attempting to Write
    Write,
}

/// The context under which the Segmentation Fault was triggered
#[derive(EnumString, Debug, Display, PartialEq, Clone, Serialize, JsonSchema)]
pub enum SegfaultAccessMode {
    /// Process was in kernel mode (during a syscall, context switch, etc.)
    Kernel,
    /// Process was in user mode (userspace), i.e. the program was at fault.
    User,
}

/// Segmentation Fault ErrorCode flags parsed into a structure
/// See more: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/traps.h#n167
/// See more: https://utcc.utoronto.ca/~cks/space/blog/linux/KernelSegfaultMessageMeaning
#[derive(Debug, PartialEq, Clone, Serialize, JsonSchema)]
pub struct SegfaultErrorCode {
    /// The reason for the segmentation fault
    pub reason: SegfaultReason,
    /// The type of access causing the fault
    pub access_type: SegfaultAccessType,
    /// The mode under which access was performed
    pub access_mode: SegfaultAccessMode,
    /// use of reserved bits in the page table entry detected (the kernel will panic if this happens)
    pub use_of_reserved_bit: bool,
    /// fault was an instruction fetch, not data read or write
    pub instruction_fetch: bool,
    /// Memory Protection Keys related. Not sure what exactly triggers this.
    /// See more: https://lore.kernel.org/patchwork/patch/633070/
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
#[derive(Debug, PartialEq, EnumString, FromPrimitive, Display, Clone, Serialize, JsonSchema)]
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

/// Stack Dump (when parsed)
#[derive(Debug, PartialEq, Clone, Serialize, JsonSchema)]
pub struct StackDump {
    /// Which CPU/Core it dumped on
    pub cpu: usize,

    /// Process ID
    pub pid: usize,

    /// Command (how was the process executed)
    pub command: String,

    /// Kernel descriptor
    pub kernel: String,

    /// Hardware descriptor
    pub hardware: String,

    // Arbitrary task key-pairs
    pub taskinfo: HashMap<String, String>,

    /// Arbitrary register value key-pairs
    pub registers: HashMap<String, String>,
}

impl Display for StackDump {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "CPU: {} PID: {} Comm: {} {}",
            self.cpu, self.pid, self.command, self.kernel
        )
    }
}

/**********************************************************************************/
// Tests! Tests! Tests!

#[cfg(test)]
mod test {
    use super::*;
    use schemars::schema_for;
    use serde_json;
    use std::fs;

    #[test]
    fn generate_reference_json_schema_file() {
        let schema_file = format!("{}{}", env!("CARGO_MANIFEST_DIR"), "/reference/schema.json");
        let schema = schema_for!(Version);
        let schema_json = serde_json::to_string_pretty(&schema).unwrap();
        eprintln!("Writing latest event schema to file: {}", schema_file);
        fs::write(schema_file, schema_json).expect("Unable to re-generate the event schema file.");
    }
}
