
use crate::events;

#[derive(PartialEq)]
#[derive(Debug)]
pub struct KMsg {
    pub info: events::EventInfo,
    pub message: String,
}