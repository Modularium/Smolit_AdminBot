use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

#[derive(Debug, Clone)]
pub struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub supplementary_gids: Vec<u32>,
    pub unix_user: Option<String>,
}

impl PeerCredentials {
    pub fn all_gids(&self) -> Vec<u32> {
        let mut gids = vec![self.gid];
        for gid in &self.supplementary_gids {
            if !gids.contains(gid) {
                gids.push(*gid);
            }
        }
        gids
    }
}

pub fn get_peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    let mut creds = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let fd = stream.as_raw_fd();
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut creds as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(PeerCredentials {
        uid: creds.uid,
        gid: creds.gid,
        pid: creds.pid as u32,
        supplementary_gids: read_supplementary_gids(creds.pid as u32)?,
        unix_user: username_from_uid(creds.uid),
    })
}

pub fn gid_from_group_name(name: &str) -> io::Result<Option<u32>> {
    let c_name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid group name"))?;
    let group = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if group.is_null() {
        return Ok(None);
    }

    let gid = unsafe { (*group).gr_gid };
    Ok(Some(gid))
}

pub fn set_socket_group(path: &std::path::Path, group_name: &str) -> io::Result<()> {
    let Some(gid) = gid_from_group_name(group_name)? else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("group {group_name} not found"),
        ));
    };

    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket path"))?;

    let result = unsafe { libc::chown(c_path.as_ptr(), u32::MAX, gid) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn read_supplementary_gids(pid: u32) -> io::Result<Vec<u32>> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let groups_line = status
        .lines()
        .find(|line| line.starts_with("Groups:"))
        .unwrap_or("Groups:");

    let groups = groups_line
        .split_whitespace()
        .skip(1)
        .filter_map(|value| value.parse::<u32>().ok())
        .collect();
    Ok(groups)
}

fn username_from_uid(uid: u32) -> Option<String> {
    let passwd = unsafe { libc::getpwuid(uid) };
    if passwd.is_null() {
        return None;
    }

    let name = unsafe { CStr::from_ptr((*passwd).pw_name) };
    Some(name.to_string_lossy().into_owned())
}
