use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use crate::config::SOCKET_DIR;
use crate::error::{IoResultExt, Result};

pub fn run() -> Result<()> {
    println!("Scanning for active chat servers...");

    let dir = Path::new(SOCKET_DIR);
    if !dir.exists() {
        println!("No active chat servers found.");
        return Ok(());
    }

    let mut found = false;

    let entries = std::fs::read_dir(dir).io_path_context(dir, "listing socket directory")?;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_socket = entry.file_type().is_ok_and(|ft| ft.is_socket());
        let is_sock_file = path.extension().is_some_and(|ext| ext == "sock");

        if is_socket && is_sock_file {
            if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                println!("  {name}");
                found = true;
            }
        }
    }

    if !found {
        println!("No active chat servers found.");
    }

    Ok(())
}
