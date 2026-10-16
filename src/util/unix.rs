//! Unix process identity helpers shared by the sockets keepassxcr listens on.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

/// The real user id of this process.
pub fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// The user id of the process on the other end of `stream`.
///
/// # Errors
///
/// Fails when the kernel cannot report the peer's credentials.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid for writes of the sizes passed.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// The user id of the process on the other end of `stream`.
///
/// # Errors
///
/// Fails when the kernel cannot report the peer's credentials.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut uid = u32::MAX;
    let mut gid = u32::MAX;
    // SAFETY: uid and gid are valid for writes.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}
