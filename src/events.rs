use chrono::{DateTime, Utc};
use num_derive::FromPrimitive;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};
use strum_macros::EnumString;
use typename::TypeName;
use schemars::{JsonSchema};

#[derive(Debug, PartialEq, Clone, Serialize, JsonSchema)]
pub struct Event {
    pub version: Version,
    pub platform: Platform,
    pub timestamp: DateTime<Utc>,
    pub facility: LogFacility,
    pub level: LogLevel,
    // "type" is a reserved keyword, hence event_type
    pub event_type: EventType,
}

impl Display for Event {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "Event<{},{},{},{},{}>::{}",
            self.version,
            self.platform,
            self.facility,
            self.level,
            self.timestamp,
            match &self.event_type {
                EventType::KernelTrap(k) => format!("{}", k),
                EventType::FatalSignal(f) => format!("{}", f),
                EventType::SuppressedCallback(s) => format!("{}", s),
                EventType::ConfigMismatch(c) => format!("{}", c)
            }
        )
    }
}

#[derive(Debug, PartialEq, Display, Clone, Serialize, JsonSchema)]
pub enum Version {
    V1
}

#[derive(Debug, PartialEq, Display, Clone, Serialize, JsonSchema)]
pub enum Platform {
    Linux
}

#[derive(EnumString, Debug, PartialEq, TypeName, Display, FromPrimitive, Clone, Serialize, JsonSchema)]
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

    #[strum(serialize = "polytect")]
    Polytect,
}

#[derive(EnumString, Debug, PartialEq, TypeName, Display, FromPrimitive, Clone, Serialize, JsonSchema)]
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


#[derive(Debug, PartialEq, Clone, Serialize, JsonSchema)]
pub enum EventType {
    KernelTrap(KernelTrapInfo),
    FatalSignal(FatalSignalInfo),
    SuppressedCallback(SuppressedCallbackInfo),
    ConfigMismatch(ConfigMisMatchInfo),
}


#[derive(Debug, PartialEq, Clone, Serialize, JsonSchema)]
pub struct KernelTrapInfo {
    pub trap: KernelTrapType,
    pub procname: String,
    pub pid: usize,
    pub ip: usize,
    pub sp: usize,
    pub errcode: SegfaultErrorCode,
    pub file: Option<String>,
    pub vmastart: Option<usize>,
    pub vmasize: Option<usize>,
}

impl Display for KernelTrapInfo {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let location = if let (Some(file), Some(vmastart), Some(vmasize)) =
            (self.file.as_ref(), self.vmasize, self.vmasize)
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
            "{}:: {} by process {}(pid:{}, instruction pointer: {}, stack pointer: {}) {}.",
            self.trap,
            self.errcode,
            self.procname,
            self.pid,
            self.ip,
            self.sp,
            location.unwrap_or_default()
        )
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, JsonSchema)]
pub enum KernelTrapType {
    Generic(String),
    Segfault(usize),
    InvalidOpcode,
}
impl Display for KernelTrapType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            KernelTrapType::Segfault(location) => write!(f, "Segfault at location {}", location),
            KernelTrapType::InvalidOpcode => write!(f, "Invalid Opcode"),
            KernelTrapType::Generic(message) => {
                write!(f, "Please parse this kernel trap: {}", message)
            }
        }
    }
}

#[derive(EnumString, Debug, Display, PartialEq, Clone, Serialize, JsonSchema)]
pub enum SegfaultReason {
    NoPageFound,
    ProtectionFault,
}

#[derive(EnumString, Debug, Display, PartialEq, Clone, Serialize, JsonSchema)]
pub enum SegfaultAccessType {
    Read,
    Write,
}

#[derive(EnumString, Debug, Display, PartialEq, Clone, Serialize, JsonSchema)]
pub enum SegfaultAccessMode {
    Kernel,
    User,
}

// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/traps.h#n167
// https://utcc.utoronto.ca/~cks/space/blog/linux/KernelSegfaultMessageMeaning
#[derive(Debug, PartialEq, Clone, Serialize, JsonSchema)]
pub struct SegfaultErrorCode {
    pub reason: SegfaultReason,
    pub access_type: SegfaultAccessType,
    pub access_mode: SegfaultAccessMode,
    pub use_of_reserved_bit: bool,
    pub instruction_fetch: bool,
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

#[derive(Debug, PartialEq, Clone, Serialize, JsonSchema)]
pub struct FatalSignalInfo {
    pub signal: FatalSignalType,
    pub stack_dump: Option<StackDump>,
}

impl Display for FatalSignalInfo {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut retval = write!(
            f,
            "Fatal Signal: {}({})",
            self.signal,
            self.signal.clone() as u8
        );
        if self.stack_dump.is_some() {
            retval = write!(f, "{}", self.stack_dump.as_ref().unwrap());
        }

        retval
    }
}

// POSIX signals in the linux kernel: https://github.com/torvalds/linux/blob/master/include/linux/signal.h#L339
#[derive(Debug, PartialEq, EnumString, FromPrimitive, Display, Clone, Serialize, JsonSchema)]
pub enum FatalSignalType {
    SIGHUP = 1,
    SIGINT,
    SIGQUIT,
    SIGILL,
    SIGTRAP,
    SIGIOT,
    SIGBUS,
    SIGFPE,
    SIGKILL,
    SIGUSR1,
    SIGSEGV,
    SIGUSR2,
    SIGPIPE,
    SIGALRM,
    SIGTERM,
    SIGSTKFLT,
    SIGCHLD,
    SIGCONT,
    SIGSTOP,
    SIGTSTP,
    SIGTTIN,
    SIGTTOU,
    SIGURG,
    SIGXCPU,
    SIGXFSZ,
    SIGVTALRM,
    SIGPROF,
    SIGWINCH,
    SIGIO,
    SIGPWR,
}

#[derive(Debug, PartialEq, Clone, Serialize, JsonSchema)]
pub struct StackDump {
    pub cpu: usize,
    pub pid: usize,
    pub command: String,
    pub kernel: String,
    pub hardware: String,
    pub taskinfo: HashMap<String, String>,
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

#[derive(Debug, PartialEq, Clone, Serialize, JsonSchema)]
pub struct SuppressedCallbackInfo {
    pub function_name: String,
    pub count: usize,
}

impl Display for SuppressedCallbackInfo {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "Suppressed {} callbacks to {}",
            self.count, &self.function_name
        )
    }
}

// This value is set internally by the agent when it finds
// configuration it was asked to set, was reverted or changed.
#[derive(Debug, PartialEq, Clone, Serialize, JsonSchema)]
pub struct ConfigMisMatchInfo {
    pub key: String,
    pub expected_value: String,
    pub observed_value: String,
}


impl Display for ConfigMisMatchInfo {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "Configuration key {} should have been {}, but found to be {}",
            &self.key, &self.expected_value, &self.observed_value
        )
    }
}
