use crate::events::Version;
use crate::formatter::{FormatResult, Formatter};

pub struct TextFormatter {}
impl Formatter for TextFormatter {
    fn format(&self, event: &Version) -> FormatResult {
        Ok(format!("{}", event))
    }
}
