mod cef;
mod error;
mod json;
mod text;

use crate::events::Version;
use crate::params::OutputFormat;
pub use cef::CefFormatter;
pub use error::FormatError;
pub use json::JsonFormatter;
pub use text::TextFormatter;

pub type FormatResult = Result<String, FormatError>;

pub enum Formatter {
    Cef(CefFormatter),
    Json(JsonFormatter),
    Text(TextFormatter),
}
impl Formatter {
    pub fn format(&self, value: &Version) -> FormatResult {
        match self {
            Self::Cef(f) => f.format(value),
            Self::Json(f) => f.format(value),
            Self::Text(f) => f.format(value),
        }
    }
}

pub fn new(format: &OutputFormat) -> Formatter {
    match format {
        OutputFormat::Text => Formatter::Text(TextFormatter {}),
        OutputFormat::Json => Formatter::Json(JsonFormatter {}),
        OutputFormat::Cef => Formatter::Cef(CefFormatter {}),
    }
}
