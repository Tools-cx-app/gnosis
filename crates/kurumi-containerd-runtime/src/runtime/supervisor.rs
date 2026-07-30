use std::{fs::File, io, os::fd::AsFd};

use anyhow::{Context, Result};
use kurumi_containerd_helper::{
    Signal, SignalHandler, WaitStatus, dup_stdio, is_interrupted, read, set_signal_handler, waitpid,
};

pub(super) fn is_reboot_status(status: WaitStatus) -> bool {
    matches!(status, WaitStatus::Signaled(_, signal, _) if signal.raw() == Signal::Hangup as i32)
}

pub(super) fn waitpid_retry(pid: i32) -> io::Result<WaitStatus> {
    loop {
        match waitpid(pid, false) {
            Err(error) if is_interrupted(&error) => {}
            result => return result,
        }
    }
}

pub(super) fn read_retry<Fd: AsFd>(fd: Fd, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match read(&fd, buffer) {
            Err(error) if is_interrupted(&error) => {}
            result => return result,
        }
    }
}

pub(super) fn wait_status_code(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, signal, _) => 128 + signal.raw(),
        _ => 125,
    }
}

pub(super) fn redirect_stdio_to_null() {
    if let Ok(null) = File::options().read(true).write(true).open("/dev/null") {
        let _ = dup_stdio(&null);
    }
}

pub(super) fn configure_monitor_signals() -> Result<()> {
    for signal in [
        Signal::Terminate,
        Signal::Interrupt,
        Signal::Quit,
        Signal::Hangup,
        Signal::Pipe,
        Signal::User1,
        Signal::User2,
    ] {
        set_signal_handler(signal, SignalHandler::Ignore, false)
            .with_context(|| format!("failed to ignore monitor signal {signal}"))?;
    }
    Ok(())
}

pub(super) fn ignore_foreground_parent_signals() -> Result<()> {
    for signal in [Signal::Interrupt, Signal::Terminate] {
        set_signal_handler(signal, SignalHandler::Ignore, false)
            .with_context(|| format!("failed to ignore foreground parent signal {signal}"))?;
    }
    Ok(())
}

pub(super) fn reset_init_signals() {
    for signal in [
        Signal::Terminate,
        Signal::Interrupt,
        Signal::Quit,
        Signal::Hangup,
        Signal::Pipe,
        Signal::User1,
        Signal::User2,
    ] {
        let _ = set_signal_handler(signal, SignalHandler::Default, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    #[allow(clippy::zombie_processes)] // Reaped through kurumi_containerd_helper::waitpid below.
    fn recognizes_only_namespace_reboot_signal() {
        let child = Command::new("sh")
            .args(["-c", "kill -HUP $$"])
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        assert!(is_reboot_status(waitpid(pid, false).unwrap()));

        let pid = 42;
        assert!(!is_reboot_status(WaitStatus::Exited(pid, 0)));
        assert!(!is_reboot_status(WaitStatus::Exited(pid, 249)));
    }
}
