use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::config::{SOCKET_DIR, SOCKET_GROUP};
use crate::error::{IoResultExt, Result};

/// Print copyable admin instructions for creating the group and/or adding a user.
pub fn print_admin_instructions(username: &str, group_missing: bool) {
    eprintln!();
    eprintln!("Ask your system administrator to run:");
    eprintln!();
    if group_missing {
        eprintln!("  sudo groupadd {SOCKET_GROUP}");
    }
    eprintln!("  sudo usermod -aG {SOCKET_GROUP} {username}");
    eprintln!();
    eprintln!("Then log out and back in for the change to take effect.");
    eprintln!("Alternatively, use --world for unrestricted access.");
}

/// Look up the GID for the `unixchat` group, returning `None` if it doesn't exist.
pub fn get_group_gid(name: &str) -> Option<u32> {
    let c_name = CString::new(name).ok()?;
    // SAFETY: getgrnam is safe with a valid C string; we check for null.
    let grp = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if grp.is_null() {
        None
    } else {
        Some(unsafe { (*grp).gr_gid })
    }
}

/// Returns true if the `unixchat` group exists on this system.
pub fn group_exists() -> bool {
    get_group_gid(SOCKET_GROUP).is_some()
}

/// Create the socket directory with appropriate permissions.
///
/// If the `unixchat` group exists, the directory is set to 0770 with group ownership.
/// Otherwise it falls back to 0755 and prints a warning.
pub fn ensure_socket_dir() -> Result<()> {
    let dir = Path::new(SOCKET_DIR);

    // Create with a restrictive umask (owner-only) so no window exists where
    // the directory is world-accessible before we set final permissions.
    // SAFETY: umask is always safe; we restore the original value immediately.
    let old_mask = unsafe { libc::umask(0o077) };
    let create_result = std::fs::create_dir_all(dir);
    unsafe { libc::umask(old_mask) };
    create_result.io_path_context(dir, "creating socket directory")?;

    if let Some(gid) = get_group_gid(SOCKET_GROUP) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o770))
            .io_path_context(dir, "setting permissions on socket directory")?;
        set_group_owner(dir, gid)?;
    } else {
        // No group — make directory world-accessible so other users can still
        // connect when using --world mode or after key exchange.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
            .io_path_context(dir, "setting permissions on socket directory")?;
    }

    Ok(())
}

/// Set socket (or file) permissions based on the `world` flag.
///
/// - `world = true`: mode 0666 (any local user can connect)
/// - `world = false`: mode 0660 + group ownership set to `unixchat`
///
/// If the `unixchat` group doesn't exist and `world` is false, a warning is
/// printed and mode 0660 is still applied (connections will only work for the owner).
pub fn set_socket_permissions(path: &Path, world: bool) -> Result<()> {
    if world {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
            .io_path_context(path, "setting permissions on")?;
    } else {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
            .io_path_context(path, "setting permissions on")?;
        if let Some(gid) = get_group_gid(SOCKET_GROUP) {
            set_group_owner(path, gid)?;
        } else {
            let username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
            eprintln!(
                "Warning: '{SOCKET_GROUP}' group not found. Socket is restricted to your user only."
            );
            print_admin_instructions(&username, true);
        }
    }
    Ok(())
}

/// Set the group owner of a path via `lchown` (does not follow symlinks).
fn set_group_owner(path: &Path, gid: u32) -> Result<()> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: valid C string, -1 means "don't change owner uid".
    let ret = unsafe { libc::lchown(c_path.as_ptr(), u32::MAX, gid) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::PermissionDenied {
            return Err(crate::error::ChatError::PermissionDenied {
                path: path.display().to_string(),
                operation: "setting group ownership on".into(),
            });
        }
        return Err(crate::error::ChatError::Io {
            context: format!("setting group ownership on '{}'", path.display()),
            source: err,
        });
    }
    Ok(())
}
