use std::{
    fs,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use nix::{
    poll::{PollFd, PollFlags, PollTimeout, poll},
    unistd::Pid,
};

pub(crate) struct ProcessHandle {
    pid: Pid,
    fd: OwnedFd,
}

impl ProcessHandle {
    #[allow(unsafe_code)]
    pub(crate) fn open(pid: Pid) -> Result<Self> {
        // SAFETY: pidfd_open takes a numeric PID and zero flags and returns a new descriptor.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
        if fd == -1 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to open pidfd for PID {pid}"));
        }
        let fd = i32::try_from(fd).context("pidfd does not fit in a file descriptor")?;
        // SAFETY: pidfd_open returned a new descriptor owned by this process.
        Ok(Self {
            pid,
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    pub(crate) const fn pid(&self) -> Pid {
        self.pid
    }

    #[allow(unsafe_code)]
    pub(crate) fn send_signal_raw(&self, signal: i32) -> Result<()> {
        // SAFETY: the pidfd is live, siginfo is null, and flags must be zero.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result == -1 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to signal PID {} through pidfd", self.pid));
        }
        Ok(())
    }

    pub(crate) fn send_signal(&self, signal: nix::sys::signal::Signal) -> Result<()> {
        self.send_signal_raw(signal as i32)
    }

    pub(crate) fn wait_for_exit(&self, timeout: Duration) -> Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let milliseconds = remaining.as_millis().min(100) as u16;
            let mut descriptors = [PollFd::new(
                self.fd.as_fd(),
                PollFlags::POLLIN | PollFlags::POLLHUP,
            )];
            match poll(&mut descriptors, PollTimeout::from(milliseconds)) {
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(error).context("failed to poll pidfd"),
            }
            if descriptors[0]
                .revents()
                .is_some_and(|events| events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP))
            {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
        }
    }
}

pub(crate) fn require_handle(pid: i32) -> Result<ProcessHandle> {
    if pid <= 0 {
        bail!("invalid process PID {pid}");
    }
    ProcessHandle::open(Pid::from_raw(pid))
}

pub(crate) fn parent_pid(pid: i32) -> Result<i32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(") ")
        .context("invalid proc stat")?
        .1
        .split_whitespace()
        .nth(1)
        .context("proc stat is missing parent PID")?
        .parse()
        .context("invalid process parent PID")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_and_probes_current_process() {
        let process = ProcessHandle::open(nix::unistd::getpid()).unwrap();
        process.send_signal_raw(0).unwrap();
        assert_eq!(process.pid(), nix::unistd::getpid());
        assert!(!process.wait_for_exit(Duration::ZERO).unwrap());
    }
}
