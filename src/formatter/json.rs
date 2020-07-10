use crate::events::Version;
use crate::formatter::{FormatResult, Formatter};

pub struct JsonFormatter {}
impl Formatter for JsonFormatter {
    fn format(&self, event: &Version) -> FormatResult {
        Ok(serde_json::to_string(&event)?)
    }
}
