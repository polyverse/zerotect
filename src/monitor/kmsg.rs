// Copyright (c) 2019 Polyverse Corporation

use crate::events;
use chrono::{DateTime, Utc};

#[derive(PartialEq, Debug)]
pub struct KMsg {
    pub timestamp: DateTime<Utc>,
    pub facility: events::LogFacility,
    pub level: events::LogLevel,
    pub message: String,
}
