
use crate::events;

#[derive(PartialEq)]
#[derive(Debug)]
pub struct KMsg {
    pub timestamp: events::MicrosecondsFromSystemStart,
    pub facility: events::LogFacility,
    pub level: events::LogLevel,
    pub message: String,
}