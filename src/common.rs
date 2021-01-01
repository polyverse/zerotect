use crate::events;
use futures::Stream;
use num::{Integer, Unsigned};
use std::any::type_name;
use std::error::Error;
use std::fmt::Display;
use std::str::FromStr;
use tokio_stream::StreamExt;

pub fn get_first_event_hostname(events: &[events::Event]) -> Option<String> {
    events
        .get(0)
        .map(|e| e.as_ref().get_hostname().to_owned())
        .flatten()
}

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

pub fn parse_hex<N: Integer + FromStr>(frag: &str) -> Option<N>
where
    N::FromStrRadixErr: Display,
{
    // special case
    if frag == "(null)" || frag == "" {
        return Some(N::zero());
    };

    // Some register values look like: 0033:0x7f883e3ad43
    // only parse the 7f883e3ad43
    let sanitized_frag = match frag.find(":0x") {
        Some(idx) => &frag[(idx + ":0x".len())..],
        None => frag,
    };

    match N::from_str_radix(sanitized_frag.trim(), 16) {
        Ok(n) => Some(n),
        Err(e) => {
            eprintln!("Unable to parse {} into {}: {}", frag, type_name::<N>(), e);
            None
        }
    }
}

// This will go away after this: https://github.com/rust-lang/rust/issues/62111
pub fn abs_diff<N: Unsigned + Integer>(u1: N, u2: N) -> N {
    if u1 > u2 {
        u1 - u2
    } else {
        u2 - u1
    }
}

pub fn result_stream_filter_error<E>(
    stream: impl Stream<Item = Result<events::Event, E>>,
    stream_name: &str,
) -> impl Stream<Item = events::Event>
where
    E: Error,
{
    let owned_stream_name = stream_name.to_owned();
    stream.filter_map(move |x| match x {
        Ok(ev) => Some(ev),
        Err(err) => {
            panic!("Error in stream {}: {:?}", owned_stream_name, err);
        }
    })
}
