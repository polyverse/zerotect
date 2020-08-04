// Copyright (c) 2020 Polyverse Corporation

use crate::emitter;
use crate::events;
use crate::formatter::{new as new_formatter, Formatter as EventFormatter};
use crate::params::{LogFileConfig, OutputFormat};
use std::error;
use std::fmt::{Display, Formatter as FmtFormatter, Result as FmtResult};
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};

#[derive(Debug)]
pub enum FileLoggerError {
    MissingParameter(String),
    FileSystem(std::io::Error),
}

impl error::Error for FileLoggerError {}
impl Display for FileLoggerError {
    fn fmt(&self, f: &mut FmtFormatter) -> FmtResult {
        match self {
            Self::MissingParameter(s) => write!(f, "FileLoggerError::MissingParameter: {}", s),
            Self::FileSystem(e) => write!(f, "FileLoggerError::FileSystem internal error: {}", e),
        }
    }
}

impl std::convert::From<std::io::Error> for FileLoggerError {
    fn from(err: std::io::Error) -> FileLoggerError {
        FileLoggerError::FileSystem(err)
    }
}

pub struct FileLogger {
    output_format: OutputFormat,
    event_formatter: Box<dyn EventFormatter>,
    writer: Box<dyn Write>,
}

impl emitter::Emitter for FileLogger {
    fn emit(&mut self, event: &events::Version) {
        match self.event_formatter.format(event) {
            Ok(formattedstr) => match self.writer.write_fmt(format_args!("{}", formattedstr)) {
                Ok(()) => {},
                Err(e) => eprintln!("Error writing to file {}", e),
            },
            Err(e) => eprintln!("Error formatting event to {:?}: {}", self.output_format, e),
        }
    }
}

pub fn new(lfc: LogFileConfig) -> Result<FileLogger, FileLoggerError> {
    let event_formatter = new_formatter(&lfc.format);

    let file = match OpenOptions::new()
        .append(true)
        .create_new(true)
        .open("foo.txt")
    {
        Ok(file) => file,
        Err(err) => match err.kind() {
            ErrorKind::AlreadyExists => OpenOptions::new().append(true).open("foo.txt")?,
            _ => return Err(FileLoggerError::from(err)),
        },
    };

    Ok(FileLogger {
        output_format: lfc.format,
        event_formatter,
        writer: Box::new(file),
    })
}
