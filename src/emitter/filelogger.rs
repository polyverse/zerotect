// Copyright (c) 2020 Polyverse Corporation

use crate::emitter;
use crate::events;
use crate::formatter::{new as new_formatter, Formatter as EventFormatter};
use crate::params::{LogFileConfig, OutputFormat};
use file_rotation::asynchronous::{FileRotate, RotationMode};
use std::error;
use std::fmt::{Display, Formatter as FmtFormatter, Result as FmtResult};
use tokio::fs::OpenOptions;
use tokio::io::{ErrorKind, AsyncWrite};
use async_trait::async_trait;

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
    writer: Box<dyn AsyncWrite>,
}

#[async_trait]
impl emitter::Emitter for FileLogger {
    async fn emit(&mut self, event: &events::Event) {
        match self.event_formatter.format(event) {
            Ok(formattedstr) => match self.writer.write_fmt(format_args!("{}\n", formattedstr)) {
                Ok(()) => {}
                Err(e) => eprintln!("Error writing to file {}", e),
            },
            Err(e) => eprintln!("Error formatting event to {:?}: {}", self.output_format, e),
        }
    }
}

pub async fn new(lfc: LogFileConfig) -> Result<FileLogger, FileLoggerError> {
    let event_formatter = new_formatter(&lfc.format);

    let writer: Box<dyn AsyncWrite> = match lfc.rotation_file_count {
        Some(rfc) => match lfc.rotation_file_max_size {
            //wrap file in file-rotation
            Some(rfms) => Box::new(FileRotate::new(lfc.filepath, RotationMode::BytesSurpassed(rfms), rfc).await),
            None => return Err(FileLoggerError::MissingParameter("File Logger was provided a rotation_file_count parameter, but not a rotation_file_max_size parameter. Without knowing the maximum size of a file at which to rotate to the next one, the rotation count is meaningless.".to_owned())),
        },
        None => match lfc.rotation_file_max_size {
            Some(_) => return Err(FileLoggerError::MissingParameter("File Logger was provided a rotation_file_max_size parameter, but not a rotation_file_count parameter. Without knowing the number of files to rotate over, the max size is meaningless.".to_owned())),
            None => match OpenOptions::new()
                .append(true)
                .create_new(true)
                .open(&lfc.filepath).await
            {
                Ok(file) => Box::new(file),
                Err(err) => match err.kind() {
                    ErrorKind::AlreadyExists => Box::new(OpenOptions::new().append(true).open(lfc.filepath).await?),
                    _ => return Err(FileLoggerError::from(err)),
                },
            },
        },
    };

    Ok(FileLogger {
        output_format: lfc.format,
        event_formatter,
        writer,
    })
}
