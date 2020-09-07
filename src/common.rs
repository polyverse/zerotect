use std::any::type_name;
use std::fmt::Display;
use std::str::FromStr;

pub fn parse_fragment<N: FromStr>(frag: &str) -> Option<N>
where
    N::Err: Display,
{
    match frag.trim().parse() {
        Ok(f) => Some(f),
        Err(e) => {
            eprintln!("Unable to parse {} into {}: {}", frag, type_name::<N>(), e);
            None
        }
    }
}

pub fn parse_hex_usize(frag: &str) -> Option<usize> {
    // special case
    if frag == "(null)" || frag == "" {
        return Some(0);
    };

    // Some register values look like: 0033:0x7f883e3ad43
    // only parse the 7f883e3ad43
    let sanitized_frag = match frag.find(":0x") {
        Some(idx) => &frag[(idx + ":0x".len())..],
        None => frag,
    };

    match usize::from_str_radix(sanitized_frag.trim(), 16) {
        Ok(n) => Some(n),
        Err(e) => {
            eprintln!("Unable to parse {} into usize: {}", frag, e);
            None
        }
    }
}
