use std::collections::HashMap;
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::protocol;

type ClientMap = Arc<Mutex<HashMap<usize, UnixStream>>>;

/// Message relay that broadcasts each incoming message to every other connected stream.
pub struct Relay {
    clients: ClientMap,
    next_id: AtomicUsize,
    shutdown: Arc<AtomicBool>,
}

impl Relay {
    pub fn new(shutdown: Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicUsize::new(0),
            shutdown,
        })
    }

    /// Number of currently connected clients.
    pub fn client_count(&self) -> usize {
        self.clients.lock().unwrap().len()
    }

    /// Register a new stream. Spawns a reader thread that forwards every
    /// incoming message to all *other* registered streams.
    pub fn add_client(self: &Arc<Self>, stream: UnixStream) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let write_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("relay: failed to clone stream: {e}");
                return;
            }
        };
        self.clients.lock().unwrap().insert(id, write_stream);

        let relay = Arc::clone(self);
        thread::spawn(move || {
            relay.reader(stream, id);
            relay.clients.lock().unwrap().remove(&id);
        });
    }

    /// Shut down all client connections so reader threads exit.
    pub fn shutdown_all(&self) {
        let mut clients = self.clients.lock().unwrap();
        for (_, stream) in clients.drain() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    fn reader(&self, stream: UnixStream, id: usize) {
        let mut reader = BufReader::new(&stream);
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            match protocol::read_message(&mut reader) {
                Ok(Some((msg_type, data))) => self.broadcast(msg_type, &data, id),
                Ok(None) => break,
                Err(e) => {
                    if self.shutdown.load(Ordering::Relaxed)
                        || !e.to_string().contains("Interrupted")
                    {
                        break;
                    }
                }
            }
        }
    }

    fn broadcast(&self, msg_type: protocol::MessageType, data: &[u8], sender_id: usize) {
        let mut clients = self.clients.lock().unwrap();
        let mut dead = Vec::new();
        for (&id, stream) in clients.iter_mut() {
            if id == sender_id {
                continue;
            }
            if protocol::write_message(stream, msg_type, data).is_err() {
                dead.push(id);
            }
        }
        for id in dead {
            clients.remove(&id);
        }
    }
}
