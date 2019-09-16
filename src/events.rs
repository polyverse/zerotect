use std::fmt;

#[derive(Debug)]
pub enum Event {
    Segfault(SegfaultDetails)
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Event::Segfault(d) => write!(f, "Segfault: {}", d)
        }
    }
}

#[derive(Debug)]
pub struct SegfaultDetails {
    pub executable: String,
    pub pid: u64,
    pub message: String,
}

impl fmt::Display for SegfaultDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.executable)
    }
}

