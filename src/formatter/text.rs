use crate::events::Version;
use crate::formatter::{FormatResult, Formatter};

pub struct TextFormatter {}
impl Formatter for TextFormatter {
    fn format(&self, event: &Version) -> FormatResult {
        Ok(format!("{}", event))
    }
}

/**********************************************************************************/
// NO Tests! NO Tests! NO Tests!
// Text formatting is the Display trait. We make no guarantees on stability
// of text formatting. They are not meant to be parsable. Use JSON if you want
// backwards compatible, well-defined serializations that don't break arbitrarily.
/**********************************************************************************/
