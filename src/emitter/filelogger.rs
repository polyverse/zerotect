// Copyright (c) 2020 Polyverse Corporation

use crate::emitter;
use crate::events;
use crate::formatter::new as new_formatter;
use crate::params::LogFileConfig;
use core::pin::Pin;
use file_rotation::asynchronous::{FileRotate, RotationMode};
use futures::task::{Context, Poll};
use pin_project::pin_project;
use std::error;
use std::fmt::{Display, Formatter as FmtFormatter, Result as FmtResult};
use tokio::fs::{File, OpenOptions};
use tokio::io::{self, AsyncWrite, AsyncWriteExt, ErrorKind};
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

#[pin_project(project = FileLoggerProjection)]
enum FileLogger {
    FileRotate(#[pin] FileRotate),
    File(#[pin] File),
}

impl AsyncWrite for FileLogger {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            FileLoggerProjection::FileRotate(fr) => fr.poll_write(cx, buf),
            FileLoggerProjection::File(f) => f.poll_write(cx, buf),
        }
    }

    // pass flush down to the current file
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            FileLoggerProjection::FileRotate(fr) => fr.poll_flush(cx),
            FileLoggerProjection::File(f) => f.poll_flush(cx),
        }
    }

    // pass shutdown down to the current file
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            FileLoggerProjection::FileRotate(fr) => fr.poll_shutdown(cx),
            FileLoggerProjection::File(f) => f.poll_shutdown(cx),
        }
    }
}

pub async fn emit_forever_filelogger_error(
    lfc: LogFileConfig,
    mut source: broadcast::Receiver<events::Event>,
) -> Result<(), FileLoggerError> {
    let event_formatter = new_formatter(&lfc.format);

    let mut writer = match lfc.rotation_file_count {
        Some(rfc) => match lfc.rotation_file_max_size {
            //wrap file in file-rotation
            Some(rfms) => FileLogger::FileRotate(FileRotate::new(lfc.filepath, RotationMode::BytesSurpassed(rfms), rfc).await?),
            None => return Err(FileLoggerError::MissingParameter("File Logger was provided a rotation_file_count parameter, but not a rotation_file_max_size parameter. Without knowing the maximum size of a file at which to rotate to the next one, the rotation count is meaningless.".to_owned())),
        },
        None => match lfc.rotation_file_max_size {
            Some(_) => return Err(FileLoggerError::MissingParameter("File Logger was provided a rotation_file_max_size parameter, but not a rotation_file_count parameter. Without knowing the number of files to rotate over, the max size is meaningless.".to_owned())),
            None => match OpenOptions::new()
                .append(true)
                .create_new(true)
                .open(&lfc.filepath).await
            {
                Ok(file) => FileLogger::File(file),
                Err(err) => match err.kind() {
                    ErrorKind::AlreadyExists => FileLogger::File(OpenOptions::new().append(true).open(lfc.filepath).await?),
                    _ => return Err(FileLoggerError::from(err)),
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
                eprintln!("FileLogger event source closed. Exiting.");
                return Ok(());
            }
        }
    }
}
