use crate::events;

use std::collections::hash_map::IterMut;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Duration;
use time::OffsetDateTime;
use rmesg;

type TimestampedEvent = (OffsetDateTime, events::Event);
pub type TimestampedEventList = VecDeque<TimestampedEvent>;
type ProcNameToTimestampedEventsMap = HashMap<String, TimestampedEventList>;

/// A Hash(procname)->List(events) so we can look for closely-spaced events in the same procname
/// NOT threadsafe!! Please only operate (insert, remove, analyze, etc.) from a single thread.
pub struct EventBuffer {
    _verbosity: u8,
    list_capacity: usize,

    max_event_count: usize,
    event_lifetime: Duration,
    event_drop_count: usize,

    cached_len: usize,

    // HashMap can store references that don't outlive the hashlist
    hashlist: ProcNameToTimestampedEventsMap,
}

/// Primary structure to buffer events as they come in. They're stored against procname,
/// since an attack may be against a particular process.
///
impl EventBuffer {
    pub fn new(
        verbosity: u8,
        max_event_count: usize,
        event_drop_count: usize,
        event_lifetime: Duration,
    ) -> EventBuffer {
        EventBuffer {
            _verbosity: verbosity,
            list_capacity: max_event_count,
            max_event_count,
            event_lifetime,
            event_drop_count,
            cached_len: 0,
            hashlist: ProcNameToTimestampedEventsMap::with_capacity(max_event_count),
        }
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, String, VecDeque<(OffsetDateTime, events::Event)>> {
        self.hashlist.iter_mut()
    }

    pub fn is_full(&self) -> bool {
        self.len() >= self.max_event_count
    }

    pub fn len(&self) -> usize {
        self.cached_len
    }

    fn recompute_len(&mut self) -> usize {
        let mut total_len: usize = 0;
        for (_, list) in self.hashlist.iter() {
            total_len += list.len()
        }

        self.cached_len = total_len;

        total_len
    }

    pub fn insert(&mut self, timestamp: OffsetDateTime, procname: String, event: events::Event) {
        // so we don't double-borrow self
        let list_capacity = self.list_capacity;

        // Do we have a list for this proc?
        self.hashlist
            .entry(procname)
            .or_insert_with(|| TimestampedEventList::with_capacity(list_capacity))
            .push_back((timestamp, event));

        self.cached_len += 1;
    }

    /// Remove events older than allowed lifetime
    /// If total events count (i.e. cached_len) is greater than or
    /// equal to maximum allowed events, remove the oldest 'drop_event_count' events.
    pub fn cleanup(&mut self) -> usize {
        self.remove_expired_events();
        self.recompute_len();

        // fullness tells us when events are where they should be,
        // cleanup happens when they exceed fullness (hence > vs >=).
        if self.is_full() {
            self.drop_oldest_events();
        }

        // remove procnames whose lists are empty
        self.drop_empty_procs();

        self.recompute_len()
    }

    /// Drop 'drop_event_count' number of oldest events across all lists
    /// this is highly inefficient (iterating the hashmap multiple times)
    /// but we'll make it efficient after we make it work
    fn drop_oldest_events(&mut self) {
        // if there's only one list, optimize by draining events from it
        // and returning early
        if self.hashlist.len() == 1 {
            let (_, eventlist) = self.hashlist.iter_mut().next().unwrap();
            eventlist.drain(0..self.event_drop_count);
            return;
        }

        let mut priority_removal_map = BTreeMap::<OffsetDateTime, String>::new();

        // populate the removal map with timestamp -> procname (the oldest timestamp in each procname)
        for (procname, eventlist) in self.hashlist.iter() {
            if let Some((timestamp, _)) = eventlist.iter().next() {
                priority_removal_map.insert(*timestamp, procname.clone());
            }
        }

        // while we have events let to be dropped...
        let mut events_remaining_to_drop = self.event_drop_count;
        while events_remaining_to_drop > 0 && !priority_removal_map.is_empty() {
            // May become more efficient in the future. See: https://github.com/rust-lang/rust/issues/62924
            // Find procname having oldest event (since we've got oldest events by procname in BTreeMap)
            // Since BTreeMap is sorted ascending by keys, the oldest (i.e. lowest) datetime key will
            // come first.
            let (borrowed_timestamp, borrowed_procname) =
                priority_removal_map.iter().next().unwrap();
            // detach these from the iterator, and thus drop scope of the priority_removal_map borrow
            let (timestamp, procname) = (*borrowed_timestamp, borrowed_procname.clone());
            priority_removal_map.remove(&timestamp);

            // look up event list for that oldest timestamped event
            match self.hashlist.get_mut(&procname) {
                None => {}
                Some(eventlist) => {
                    // remove the front-most (oldest event)
                    eventlist.pop_front();
                    events_remaining_to_drop -= 1;

                    // add event from front (if any) to the BTreeMap priority list
                    match eventlist.front() {
                        None => {}
                        Some((timestamp, _)) => {
                            priority_removal_map.insert(*timestamp, procname);
                        }
                    }
                }
            }
        }
    }

    /// Remove events that are past lifetime. This one is easier.
    fn remove_expired_events(&mut self) {
        // At what time do events expire?
        // make this mutable so comparison below works
        let mut event_expiry_time = OffsetDateTime::now_utc() - self.event_lifetime;

        // for each procname in event list
        for (_, eventlist) in (&mut self.hashlist).iter_mut() {
            // let's go in the event list oldest to youngest and remove expired events...
            // iterating over VecDeque goes front to back.
            // https://doc.rust-lang.org/std/collections/struct.VecDeque.html
            let mut removal_count: usize = 0;
            for (timestamp, _) in eventlist.iter() {
                if timestamp <= &mut event_expiry_time {
                    // if current event has expired, remove another event from the front
                    removal_count += 1;
                } else {
                    // if we got to events which are newer than expiry, we break the loop
                    // since events go oldest->youngest from front to back
                    break;
                }
            }

            eventlist.drain(0..removal_count);
        }
    }

    /// Remove procname keys for which lists are empty.
    fn drop_empty_procs(&mut self) {
        let emptykeys: Vec<String> = self
            .hashlist
            .iter()
            .filter_map(|(key, value)| {
                if value.is_empty() {
                    // separate out of the iterator
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        for emptykey in emptykeys {
            self.hashlist.remove(&emptykey);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    macro_rules! map(
        { $($key:expr => $value:expr),+ } => {
            {
                let mut m = ::std::collections::BTreeMap::<String, String>::new();
                $(
                    m.insert(String::from($key), String::from($value));
                )+
                m
            }
         };
    );

    #[test]
    fn ensure_removal_when_beyond_full_single_proc_all_events() {
        let mut eb = EventBuffer::new(0, 10, 5, Duration::from_secs(100));

        // add 10 events
        for _ in 0..10 {
            let (ts, procname, event) = create_event("Test".to_owned());
            eb.insert(ts, procname, event);
        }
        assert_eq!(10, eb.len());

        // add one more event, and lenth should be 5 (drop 5 events)
        assert_eq!(5, eb.cleanup());

        let (ts, procname, event) = create_event("Test".to_owned());
        eb.insert(ts, procname, event);
        assert_eq!(6, eb.len());
        assert_eq!(6, eb.cleanup());
    }

    #[test]
    fn ensure_removal_when_beyond_full_multiple_procs_single_event() {
        let mut eb = EventBuffer::new(0, 10, 5, Duration::from_secs(100));

        // add 10 events
        for i in 0..10 {
            let (ts, procname, event) = create_event(format!("TestProc{}", i));
            eb.insert(ts, procname, event);
        }
        assert_eq!(10, eb.len());

        // add one more event, and lenth should be 5 (drop 5 events)
        assert_eq!(5, eb.cleanup());

        let (ts, procname, event) = create_event(format!("TestProc{}", 10));
        eb.insert(ts, procname, event);
        assert_eq!(6, eb.len());
        assert_eq!(6, eb.cleanup());
    }

    #[test]
    fn ensure_removal_when_beyond_full_multiple_procs_multiple_events() {
        let mut eb = EventBuffer::new(0, 10, 5, Duration::from_secs(100));

        // add 10 events
        for i in 0..5 {
            let (ts, procname, event) = create_event(format!("TestProc{}", i));
            eb.insert(ts, procname, event);
            let (ts, procname, event) = create_event(format!("TestProc{}", i));
            eb.insert(ts, procname, event);
        }
        assert!(eb.is_full());
        assert_eq!(10, eb.len());

        // add one more event, and lenth should be 5 (drop 5 events)
        assert_eq!(5, eb.cleanup());
        assert!(!eb.is_full());

        let (ts, procname, event) = create_event(format!("TestProc{}", 10));
        eb.insert(ts, procname, event);
        assert_eq!(6, eb.len());
        assert_eq!(6, eb.cleanup());
        assert!(!eb.is_full());

        // We expect only oldest events removed - so none of TestProc0-TestProc1, and one of TestProc2.
        assert!(eb.hashlist.get("TestProc0").is_none());
        assert!(eb.hashlist.get("TestProc1").is_none());

        assert_eq!(4, eb.hashlist.len());
        assert_eq!(1, eb.hashlist.get("TestProc2").unwrap().len());
        assert_eq!(2, eb.hashlist.get("TestProc3").unwrap().len());
        assert_eq!(2, eb.hashlist.get("TestProc4").unwrap().len());
        assert_eq!(1, eb.hashlist.get("TestProc10").unwrap().len());
    }

    #[test]
    fn ensure_expiry_multiple_procs_multiple_events() {
        let mut eb = EventBuffer::new(0, 10, 5, Duration::from_secs(100));

        // add 10 events
        for i in 0..9 {
            let (ts, procname, event) = create_event(format!("TestProc{}", i));
            eb.insert(ts, procname, event);
        }
        assert!(!eb.is_full());

        //immediate cleanup removes nothing.
        assert_eq!(9, eb.cleanup());
        sleep(Duration::from_secs(2));

        // remove after 2 seconds
        assert_eq!(0, eb.cleanup());

        assert_eq!(0, eb.hashlist.len());
    }

    fn create_event(procname: String) -> (OffsetDateTime, String, events::Event) {
        let timestamp = OffsetDateTime::now_utc();
        let event = match rand::random::<bool>() {
            true => Arc::new(events::Version::V1 {
                timestamp,
                hostname: Some("analyzerhost".to_owned()),
                event: events::EventType::LinuxKernelTrap(events::LinuxKernelTrap {
                    facility: rmesg::entry::LogFacility::User,
                    level: rmesg::entry::LogLevel::Info,
                    procname: procname.clone(),
                    pid: 1800,
                    ip: 0x5000,
                    sp: 0x6000,
                    trap: events::KernelTrapType::GeneralProtectionFault,
                    errcode: events::SegfaultErrorCode::from_error_code(6),
                    file: None,
                    vmasize: None,
                    vmastart: None,
                }),
            }),
            false => Arc::new(events::Version::V1 {
                timestamp,
                hostname: Some("analyzerhost".to_owned()),
                event: events::EventType::LinuxFatalSignal(events::LinuxFatalSignal {
                    facility: rmesg::entry::LogFacility::User,
                    level: rmesg::entry::LogLevel::Info,
                    signal: events::FatalSignalType::SIGIOT,
                    stack_dump: map!("Comm" => procname.clone()),
                }),
            }),
        };

        (timestamp, procname, event)
    }
}
