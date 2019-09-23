use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration};
use std::io::prelude::*;

type LinesIterator = std::io::Lines<std::boxed::Box<dyn BufRead + Send>>;

pub enum TimeoutLineIteratorError {
    Timeout,
    Disconnected,
}

pub struct TimeoutLineIterator {
    source: Receiver<String>,
    buffer: Vec<String>,
    verbosity: u8,
}

impl TimeoutLineIterator {
    pub fn with_lines_iterator(reader: LinesIterator, verbosity: u8) -> TimeoutLineIterator {
        let (sink, source) : (Sender<String>, Receiver<String>) = mpsc::channel();


        thread::spawn(move || {
            for maybe_line in reader {
                match maybe_line {
                    Ok(line) => {
                        if let Err(e) = sink.send(line) {
                            eprintln!("Monitor::with_lines_iterator:: Internal kmsg-reader thread closing because outer kmsg reader has closed. Nobody left to send messages to. Error: {}", e);
                            return;
                        }
                    },
                    Err(e) => {
                        eprintln!("Monitor::with_lines_iterator:: Incoming line error. Closing thread. Error: {}", e);
                        return
                    }
                }
            }
        });

        TimeoutLineIterator {
            source,
            verbosity,
            buffer: Vec::new()
        }
    }

    pub fn next_timeout(&mut self, timeout: Duration) -> Result<String, TimeoutLineIteratorError> {
        if !self.buffer.is_empty() {
            return Ok(self.buffer.remove(0));
        };

        match self.source.recv_timeout(timeout) {
            Ok(item) => Ok(item),
            Err(e) => match e {
                mpsc::RecvTimeoutError::Timeout => Err(TimeoutLineIteratorError::Timeout),
                mpsc::RecvTimeoutError::Disconnected => Err(TimeoutLineIteratorError::Disconnected)
            }
        }            
    }

    pub fn peek_timeout(&mut self, timeout: Duration) -> Result<&String, TimeoutLineIteratorError> {
        if self.buffer.is_empty() {
            match self.source.recv_timeout(timeout) {
                Ok(item) => self.buffer.push(item),
                Err(e) => match e {
                    mpsc::RecvTimeoutError::Timeout => return Err(TimeoutLineIteratorError::Timeout),
                    mpsc::RecvTimeoutError::Disconnected => return Err(TimeoutLineIteratorError::Disconnected)
                }
            }   
        };

        Ok(self.buffer.first().unwrap())
    }
}

impl Iterator for TimeoutLineIterator {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        if !self.buffer.is_empty() {
            return Some(self.buffer.remove(0));
        };

        match self.source.recv() {
            Ok(item) => {
                Some(item)
            },
            Err(e) => {
                if self.verbosity > 0 {
                    eprintln!("TimedIterator:: Error occurred reading from source: {}.", e);
                }
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterates() {
        let realistic_message = 
r"1
2
3
4
5";
        let lines_iterator = (Box::new(realistic_message.as_bytes()) as Box<dyn BufRead + Send>).lines();

        let mut ti = TimeoutLineIterator::with_lines_iterator(lines_iterator, 0);

        assert_eq!(ti.next().unwrap(), "1");
        assert_eq!(ti.next().unwrap(), "2");
        assert_eq!(ti.next().unwrap(), "3");
        assert_eq!(ti.next().unwrap(), "4");
        assert_eq!(ti.next().unwrap(), "5");
    }

       #[test]
    fn next_timeout() {
        let realistic_message = 
r"1
2
3
4
5";
        let lines_iterator = (Box::new(realistic_message.as_bytes()) as Box<dyn BufRead + Send>).lines();

        let mut ti = TimeoutLineIterator::with_lines_iterator(lines_iterator, 0);

        assert_eq!(ti.next().unwrap(), "1");
        assert_eq!(ti.next().unwrap(), "2");
        assert_eq!(ti.next().unwrap(), "3");
        assert_eq!(ti.next().unwrap(), "4");
        assert_eq!(ti.next().unwrap(), "5");

        let timeout_result = ti.next_timeout(Duration::from_secs(1));
        assert!(timeout_result.is_err());
    }

           #[test]
    fn peek_doesnt_remove() {
        let realistic_message = 
r"1
2
3
4
5";
        let lines_iterator = (Box::new(realistic_message.as_bytes()) as Box<dyn BufRead + Send>).lines();

        let mut ti = TimeoutLineIterator::with_lines_iterator(lines_iterator, 0);

        assert_eq!(ti.next().unwrap(), "1");
        assert_eq!(ti.next().unwrap(), "2");
        assert_eq!(ti.peek_timeout(Duration::from_secs(1)).ok().unwrap(), "3");
        assert_eq!(ti.next().unwrap(), "3");
        assert_eq!(ti.next().unwrap(), "4");
        assert_eq!(ti.peek_timeout(Duration::from_secs(1)).ok().unwrap(), "5");
        assert_eq!(ti.peek_timeout(Duration::from_secs(1)).ok().unwrap(), "5");
        assert_eq!(ti.next().unwrap(), "5");

        let timeout_result = ti.next_timeout(Duration::from_secs(1));
        assert!(timeout_result.is_err());
    }
}


