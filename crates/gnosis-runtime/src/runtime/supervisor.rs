use std::{fs::File, os::fd::AsFd};

use anyhow::{Context, Result};
use nix::{
    sys::{
        signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction},
        wait::{WaitStatus, waitpid},
    },
    unistd::Pid,
};

pub(super) fn is_reboot_status(status: WaitStatus) -> bool {
    matches!(status, WaitStatus::Signaled(_, Signal::SIGHUP, _))
}

pub(super) fn waitpid_retry(pid: Pid) -> nix::Result<WaitStatus> {
    loop {
        match waitpid(pid, None) {
            Err(nix::errno::Errno::EINTR) => {}
            result => return result,
        }
    }
}

pub(super) fn read_retry<Fd: AsFd>(fd: Fd, buffer: &mut [u8]) -> nix::Result<usize> {
    loop {
        match nix::unistd::read(&fd, buffer) {
            Err(nix::errno::Errno::EINTR) => {}
            result => return result,
        }
    }
}

pub(super) fn wait_status_code(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
        _ => 125,
    }
}

pub(super) fn redirect_stdio_to_null() {
    if let Ok(null) = File::options().read(true).write(true).open("/dev/null") {
        let _ = nix::unistd::dup2_stdin(&null);
        let _ = nix::unistd::dup2_stdout(&null);
        let _ = nix::unistd::dup2_stderr(&null);
    }
}

#[allow(unsafe_code)]
pub(super) fn configure_monitor_signals() -> Result<()> {
    let action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
    for signal in [
        Signal::SIGTERM,
        Signal::SIGINT,
        Signal::SIGQUIT,
        Signal::SIGHUP,
        Signal::SIGPIPE,
        Signal::SIGUSR1,
        Signal::SIGUSR2,
    ] {
        // SAFETY: action contains SIG_IGN and an initialized empty signal mask.
        unsafe { sigaction(signal, &action) }
            .with_context(|| format!("failed to ignore monitor signal {signal}"))?;
    }
    Ok(())
}

#[allow(unsafe_code)]
pub(super) fn ignore_foreground_parent_signals() -> Result<()> {
    let action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
    for signal in [Signal::SIGINT, Signal::SIGTERM] {
        // SAFETY: action contains SIG_IGN and an initialized empty signal mask.
        unsafe { sigaction(signal, &action) }
            .with_context(|| format!("failed to ignore foreground parent signal {signal}"))?;
    }
    Ok(())
}

#[allow(unsafe_code)]
pub(super) fn reset_init_signals() {
    let action = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
    for signal in [
        Signal::SIGTERM,
        Signal::SIGINT,
        Signal::SIGQUIT,
        Signal::SIGHUP,
        Signal::SIGPIPE,
        Signal::SIGUSR1,
        Signal::SIGUSR2,
    ] {
        // SAFETY: action contains SIG_DFL and an initialized empty signal mask.
        let _ = unsafe { sigaction(signal, &action) };
    }
}

#[allow(unsafe_code)]
pub(super) fn configure_parent_death_signal(expected_parent: Pid) {
    // SAFETY: PR_SET_PDEATHSIG takes integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == -1 {
        std::process::exit(125);
    }
    if nix::unistd::getppid() != expected_parent {
        std::process::exit(125);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_namespace_reboot_signal() {
        let pid = Pid::from_raw(42);
        assert!(is_reboot_status(WaitStatus::Signaled(
            pid,
            Signal::SIGHUP,
            false
        )));
        assert!(!is_reboot_status(WaitStatus::Exited(pid, 0)));
        assert!(!is_reboot_status(WaitStatus::Exited(pid, 249)));
    }
}
