mod cef;
mod error;
mod json;
mod text;

use crate::events::Version;
use crate::params::OutputFormat;
pub use cef::CEFFormatter;
pub use error::FormatError;
pub use json::JsonFormatter;
pub use text::TextFormatter;

pub type FormatResult = Result<String, FormatError>;

pub trait Formatter {
    fn format(&self, value: &Version) -> FormatResult;
}

pub fn new(format: &OutputFormat) -> Box<dyn Formatter> {
    match format {
        OutputFormat::Text => Box::new(TextFormatter {}),
        OutputFormat::JSON => Box::new(JsonFormatter {}),
        OutputFormat::CEF => Box::new(CEFFormatter {}),
    }
}
