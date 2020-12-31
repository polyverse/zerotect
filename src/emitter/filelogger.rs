// Copyright (c) 2020 Polyverse Corporation

use crate::emitter;
use crate::events;
use crate::formatter::new as new_formatter;
use crate::params::LogFileConfig;
use core::pin::Pin;
use file_rotation::asynchronous::{FileRotate, RotationMode};
use std::error;
use std::fmt::{Display, Formatter as FmtFormatter, Result as FmtResult};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncWrite, ErrorKind};
use tokio::sync::broadcast;

#[derive(Debug)]
pub enum FileLoggerError {
    MissingParameter(String),
    FileSystem(std::io::Error),
    FileRotation(file_rotation::error::Error),
}

impl error::Error for FileLoggerError {}
impl Display for FileLoggerError {
    fn fmt(&self, f: &mut FmtFormatter) -> FmtResult {
        match self {
            Self::MissingParameter(s) => write!(f, "FileLoggerError::MissingParameter: {}", s),
            Self::FileSystem(e) => write!(f, "FileLoggerError::FileSystem internal error: {}", e),
            Self::FileRotation(e) => {
                write!(f, "FileLoggerError::FileRotation internal error: {}", e)
            }
        }
    }
}

impl std::convert::From<std::io::Error> for FileLoggerError {
    fn from(err: std::io::Error) -> FileLoggerError {
        FileLoggerError::FileSystem(err)
    }
}
impl From<file_rotation::error::Error> for FileLoggerError {
    fn from(err: file_rotation::error::Error) -> FileLoggerError {
        FileLoggerError::FileRotation(err)
    }
}
pub async fn emit_forever(
    lfc: LogFileConfig,
    source: broadcast::Receiver<events::Event>,
) -> Result<(), emitter::EmitterError> {
    // value in having a local error instead of exposing emitter
    // to each implementation's errors
    Ok(emit_forever_filelogger_error(lfc, source).await?)
}

pub async fn emit_forever_filelogger_error(
    lfc: LogFileConfig,
    mut source: broadcast::Receiver<events::Event>,
) -> Result<(), FileLoggerError> {
    let event_formatter = new_formatter(&lfc.format);

    let mut writer: Pin<Box<dyn AsyncWrite>> = match lfc.rotation_file_count {
        Some(rfc) => match lfc.rotation_file_max_size {
            //wrap file in file-rotation
            Some(rfms) => Box::pin(FileRotate::new(lfc.filepath, RotationMode::BytesSurpassed(rfms), rfc).await?),
            None => return Err(FileLoggerError::MissingParameter("File Logger was provided a rotation_file_count parameter, but not a rotation_file_max_size parameter. Without knowing the maximum size of a file at which to rotate to the next one, the rotation count is meaningless.".to_owned()).into()),
        },
        None => match lfc.rotation_file_max_size {
            Some(_) => return Err(FileLoggerError::MissingParameter("File Logger was provided a rotation_file_max_size parameter, but not a rotation_file_count parameter. Without knowing the number of files to rotate over, the max size is meaningless.".to_owned()).into()),
            None => match OpenOptions::new()
                .append(true)
                .create_new(true)
                .open(&lfc.filepath).await
            {
                Ok(file) => Box::pin(file),
                Err(err) => match err.kind() {
                    ErrorKind::AlreadyExists => Box::pin(OpenOptions::new().append(true).open(lfc.filepath).await?),
                    _ => return Err(FileLoggerError::from(err).into()),
                },
            },
        },
    };

    loop {
        match source.recv().await {
            Ok(event) => match event_formatter.format(&event) {
                Ok(formattedstr) => {
                    match writer.write(format!("{}\n", formattedstr).as_bytes()).await {
                        Ok(_written) => {}
                        Err(e) => eprintln!("FileLogger: Ignoring error writing to file {}", e),
                    }
                }
                Err(e) => eprintln!(
                    "FileLogger: Ignoring error formatting event to {:?}: {}",
                    lfc.format, e
                ),
            },
            Err(broadcast::error::RecvError::Lagged(count)) => {
                eprintln!(
                    "FileLogger is lagging behind generated events. {} events have been dropped.",
                    count
                )
            }
            Err(broadcast::error::RecvError::Closed) => {
                panic!("FileLogger event source closed. Panicking and exiting.")
            }
        }
    }
}
