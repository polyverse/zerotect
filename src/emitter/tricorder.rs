
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;
use crate::emitter;
use crate::events;
use reqwest;


const TRICORDER_PUBLISH_ENDPOINT: &str = "https://tricorder.polyverse.com/v1/publish";

pub struct TricorderConfig {
    pub auth_key: String,
}

pub struct Tricorder {
    sender: Sender<events::Event>,
}

impl emitter::Emitter for Tricorder {
    fn emit(&self, event: &events::Event) {
        let movable_copy = (*event).clone();
        if let Err(e) = self.sender.send(movable_copy) {
            eprintln!("Error queing event to tricorder: {}", e);
        }
    }
}

pub fn new(config: TricorderConfig) -> Tricorder {
    let (sender, receiver) : (Sender<events::Event>, Receiver<events::Event>) = channel();

    thread::spawn(move || {
        eprintln!("Emitter to Tricorder initialized.");
        let client = reqwest::Client::new();

        // This live-tests the built-in URL early.
        if let Err(e) = reqwest::Url::parse(TRICORDER_PUBLISH_ENDPOINT) {
            eprintln!("Tricorder: Aborting. Unable to parse built-in tricorder URL into a reqwest library url: {}", e);
            return;
        };

        loop {
            match receiver.recv() {
                Ok(event) => {
                    let res = client.post(TRICORDER_PUBLISH_ENDPOINT)
                        .bearer_auth(&config.auth_key)
                        .json(&event)
                        .send();
                    match res {
                        Ok(r) => eprintln!("Response from tricorder: {:?}", r),
                        Err(e) => eprintln!("Tricorder: error publishing event to service {}: {}", TRICORDER_PUBLISH_ENDPOINT, e)
                    }
                },
                Err(e) => eprintln!("Tricorder: Error receiving message from monitor: {}", e)
            }
        }
    });
    
    Tricorder{
        sender,
    }
}