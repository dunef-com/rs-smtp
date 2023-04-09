use std::sync::{Mutex};
use std::collections::HashMap;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Sender;

pub struct Pipeline {
    id: Mutex<u64>,
    request: Sequencer,
    response: Sequencer,
}

impl Pipeline {
    pub fn new() -> Self {
        Self {
            id: Mutex::new(0),
            request: Sequencer::new(),
            response: Sequencer::new(),
        }
    }

    pub fn next(&mut self) -> u64 {
        let mut this_id = self.id.lock().unwrap();
        let id = *this_id;
        *this_id += 1;
        drop(this_id);
        id
    }

    pub async fn start_request(&mut self, id: u64) {
        self.request.start(id).await;
    }

    pub fn end_request(&mut self, id: u64) {
        self.request.end(id);
    }

    pub async fn start_response(&mut self, id: u64) {
        self.response.start(id).await;
    }

    pub fn end_response(&mut self, id: u64) {
        self.response.end(id);
    }
}

struct Sequencer {
    id: Mutex<u64>,
    wait: HashMap<u64, Sender<()>>
}

impl Sequencer {
    pub fn new() -> Self {
        Self {
            id: Mutex::new(0),
            wait: HashMap::new(),
        }
    }

    pub async fn start(&mut self, id: u64) {
        let this_id = self.id.lock().unwrap();
        if *this_id == id {
            return;
        }

        let (tx, rx) = oneshot::channel();
        self.wait.insert(id, tx);
        drop(this_id);
        rx.await;
    }

    pub fn end(&mut self, mut id: u64) {
        let mut this_id = self.id.lock().unwrap();
        if *this_id != id {
            panic!("out of sync");
        }
        id += 1;
        *this_id = id;
        let val = self.wait.remove(&id);
        drop(this_id);
        if let Some(tx) = val {
            tx.send(()).unwrap();
        }
    }
}