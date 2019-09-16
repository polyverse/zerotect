#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_parse_dmesg_entries() {
        DMesgPoller::parse_dmesg_entries();
    }
}