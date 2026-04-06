use std::process::Command;

use crate::config::{APP_NAME, SOCKET_GROUP, ssh_key_path};
use crate::error::{IoResultExt, Result};
use crate::permissions;

pub fn run() -> Result<()> {
    println!("Checking environment...");

    // Check for ssh-keygen
    let has_ssh_keygen = Command::new("which").arg("ssh-keygen").output().is_ok_and(|o| o.status.success());
    if has_ssh_keygen {
        println!("  [ok] ssh-keygen");
    } else {
        println!("  [missing] ssh-keygen -- install openssh-client");
    }

    // Check for / generate SSH key
    let key_path = ssh_key_path();
    if key_path.exists() {
        println!("  [ok] SSH key at {}", key_path.display());
    } else {
        println!("  [missing] SSH key at {}", key_path.display());
        if !has_ssh_keygen {
            eprintln!("Cannot generate SSH key: ssh-keygen not found.");
            return Ok(());
        }
        eprint!("Generate a new SSH key? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).io_context("reading user input from stdin")?;
        if answer.trim().eq_ignore_ascii_case("y") {
            if let Some(parent) = key_path.parent() {
                std::fs::create_dir_all(parent)
                    .io_path_context(parent, "creating SSH key directory")?;
            }
            let username = current_username();
            let status = Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-f"])
                .arg(&key_path)
                .args(["-N", "", "-C"])
                .arg(format!("{APP_NAME}_{username}"))
                .status()
                .io_context("running ssh-keygen")?;
            if status.success() {
                println!("SSH key generated at {}", key_path.display());
            } else {
                eprintln!("ssh-keygen failed with exit code {status}");
            }
        } else {
            println!("Skipping key generation. You will need a key at {} before using chat.", key_path.display());
        }
    }

    // Check / create the unixchat group
    setup_group()?;

    // Ensure socket directory exists with correct permissions
    permissions::ensure_socket_dir()?;
    println!("  [ok] socket directory configured");

    println!("\nInit complete.");
    Ok(())
}

fn setup_group() -> Result<()> {
    let username = current_username();

    if permissions::group_exists() {
        println!("  [ok] '{SOCKET_GROUP}' group");
        if !user_in_group(&username, SOCKET_GROUP) {
            eprintln!("  [warn] user '{username}' is not in the '{SOCKET_GROUP}' group");
            permissions::print_admin_instructions(&username, false);
        }
    } else {
        println!("  [missing] '{SOCKET_GROUP}' group");
        permissions::print_admin_instructions(&username, true);
    }

    Ok(())
}

/// Check whether `username` is a member of `group` by inspecting group membership via libc.
fn user_in_group(username: &str, group: &str) -> bool {
    // Fast path: check if the user's current effective GID matches the group
    if let Some(gid) = permissions::get_group_gid(group) {
        // SAFETY: getegid is always safe
        if unsafe { libc::getegid() } == gid {
            return true;
        }
        // Check supplementary groups
        let mut ngroups: libc::c_int = 64;
        let mut groups = vec![0 as libc::gid_t; ngroups as usize];
        // SAFETY: getgrouplist is safe with valid pointers and correct size
        let c_username = std::ffi::CString::new(username).unwrap_or_default();
        let primary_gid = unsafe { libc::getegid() };
        let ret = unsafe { libc::getgrouplist(c_username.as_ptr(), primary_gid, groups.as_mut_ptr(), &mut ngroups) };
        if ret == -1 {
            groups.resize(ngroups as usize, 0);
            unsafe { libc::getgrouplist(c_username.as_ptr(), primary_gid, groups.as_mut_ptr(), &mut ngroups) };
        }
        groups.truncate(ngroups as usize);
        return groups.contains(&gid);
    }
    false
}

fn current_username() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".into())
}
