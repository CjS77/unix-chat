use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};


/// Returns true if a shutdown signal (SIGINT/SIGTERM) has been received.
pub fn shutdown_requested(flag: &AtomicBool) -> bool {
    flag.load(Ordering::Relaxed)
}

/// Install signal handlers for SIGINT and SIGTERM that set the shutdown flag
/// instead of terminating the process. 
pub fn install_handlers(flag: Arc<AtomicBool>) {
    // SAFETY: The closure only sets an AtomicBool, which is async-signal-safe.
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag))
        .expect("failed to register SIGINT handler");
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&flag))
        .expect("failed to register SIGTERM handler");
}
