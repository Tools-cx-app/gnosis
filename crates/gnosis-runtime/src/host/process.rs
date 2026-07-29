use std::{
    os::fd::{AsFd, AsRawFd, OwnedFd},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use gnosis_helper::{Signal, is_interrupted, pidfd_open, pidfd_send_signal};
use mio::{Events, Interest, Poll, Token, unix::SourceFd};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcessId(i32);

impl ProcessId {
    pub(crate) const fn as_raw(self) -> i32 {
        self.0
    }
}

pub(crate) struct ProcessHandle {
    pid: ProcessId,
    fd: OwnedFd,
}

impl ProcessHandle {
    pub(crate) fn open(pid: i32) -> Result<Self> {
        let fd = pidfd_open(pid).with_context(|| format!("failed to open pidfd for PID {pid}"))?;
        Ok(Self {
            pid: ProcessId(pid),
            fd,
        })
    }

    pub(crate) const fn pid(&self) -> ProcessId {
        self.pid
    }

    pub(crate) fn send_signal_raw(&self, signal: i32) -> Result<()> {
        pidfd_send_signal(self.fd.as_fd(), signal)
            .with_context(|| format!("failed to signal PID {} through pidfd", self.pid.as_raw()))
    }

    pub(crate) fn send_signal(&self, signal: Signal) -> Result<()> {
        self.send_signal_raw(signal as i32)
    }

    pub(crate) fn wait_for_exit(&self, timeout: Duration) -> Result<bool> {
        let mut poll = Poll::new().context("failed to create pidfd poller")?;
        poll.registry()
            .register(
                &mut SourceFd(&self.fd.as_raw_fd()),
                Token(0),
                Interest::READABLE,
            )
            .context("failed to register pidfd")?;
        let mut events = Events::with_capacity(1);
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match poll.poll(&mut events, Some(remaining.min(Duration::from_millis(100)))) {
                Ok(()) => {}
                Err(error) if is_interrupted(&error) => continue,
                Err(error) => return Err(error).context("failed to poll pidfd"),
            }
            if !events.is_empty() {
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
    ProcessHandle::open(pid)
}

pub(crate) fn parent_pid(pid: i32) -> Result<i32> {
    Ok(procfs::process::Process::new(pid)?.stat()?.ppid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_and_probes_current_process() {
        let pid = gnosis_helper::current_pid();
        let process = ProcessHandle::open(pid).unwrap();
        process.send_signal_raw(0).unwrap();
        assert_eq!(process.pid().as_raw(), pid);
        assert!(!process.wait_for_exit(Duration::ZERO).unwrap());
    }
}
