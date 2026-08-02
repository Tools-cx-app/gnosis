use std::{
    io::Write,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    sync::atomic::{AtomicI32, Ordering},
};

use anyhow::{Context, Result, bail};
use kurumi_containerd_helper::{
    ForkResult, PtyPair, Signal, SignalActionFlags, SignalHandler, SignalNumber, TerminalSettings,
    WaitStatus, WindowSize, dup_stdio, effective_uid, fork, is_interrupted, is_io_error,
    is_terminal, is_would_block, make_raw, open_pty, pty_number, read, receive_fds, send_fds,
    set_controlling_terminal, set_file_mode, set_gid, set_groups, set_signal_handler,
    set_terminal_settings, set_terminal_size, set_uid, setsid, socket_pair, terminal_settings,
    terminal_size, waitpid, write,
};
use mio::{Events, Interest, Poll, Token, unix::SourceFd};

use super::process::ProcessHandle;
use crate::container::init::{self, InitSystem};

static FORWARDED_SIGNAL: AtomicI32 = AtomicI32::new(0);
const PTY_MODE: u32 = 0o620;

pub(crate) struct Console {
    pub(crate) master: OwnedFd,
    pub(crate) slave_path: String,
}

impl Console {
    pub(crate) fn open() -> Result<Self> {
        let winsize = terminal_size(std::io::stdin().as_fd()).ok();
        let PtyPair { master, slave } = if effective_uid() == 0 {
            open_console_pty_unprivileged(winsize.as_ref())?
        } else {
            open_console_pty(winsize.as_ref())?
        };
        // Keep the broker-owned UID on the host PTY, but pin the expected tty mode.
        let _ = set_file_mode(slave.as_fd(), PTY_MODE);
        Ok(Self {
            slave_path: tty_path(&master)?,
            master,
        })
    }

    pub(crate) fn open_slave(&self) -> Result<OwnedFd> {
        open_pty_slave(&self.slave_path)
    }
}

fn open_pty_slave(path: &str) -> Result<OwnedFd> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open PTY slave {path}"))
        .map(Into::into)
}

fn tty_path(master: &OwnedFd) -> Result<String> {
    let number = pty_number(master.as_fd()).context("failed to resolve PTY slave path")?;
    Ok(format!("/dev/pts/{number}"))
}

#[allow(unsafe_code)]
fn open_console_pty_unprivileged(winsize: Option<&WindowSize>) -> Result<PtyPair> {
    let (parent, child) = socket_pair().context("failed to create PTY broker channel")?;
    // SAFETY: this runtime is single-threaded at PTY allocation. The child only
    // drops credentials, allocates descriptors, sends them, and exits.
    match unsafe { fork() }.context("failed to fork PTY broker")? {
        ForkResult::Child => {
            drop(parent);
            let code = match drop_pty_broker_privileges()
                .and_then(|()| open_console_pty(winsize))
                .and_then(|pty| send_pty(&child, &pty))
            {
                Ok(()) => 0,
                Err(error) => {
                    tracing::error!("PTY broker failed: {error:#}");
                    1
                }
            };
            std::process::exit(code);
        }
        ForkResult::Parent { child: broker } => {
            drop(child);
            let received = receive_pty(&parent);
            drop(parent);
            let status = waitpid(broker, false).context("failed waiting for PTY broker")?;
            ensure_broker_success(status)?;
            received
        }
    }
}

fn drop_pty_broker_privileges() -> Result<()> {
    let id = pty_broker_id();
    set_groups(&[]).context("failed to clear PTY broker supplementary groups")?;
    set_gid(id).context("failed to drop PTY broker GID")?;
    set_uid(id).context("failed to drop PTY broker UID")?;
    Ok(())
}

#[cfg(target_os = "android")]
const fn pty_broker_id() -> u32 {
    9_999
}

#[cfg(not(target_os = "android"))]
const fn pty_broker_id() -> u32 {
    65_534
}

fn send_pty(socket: &OwnedFd, pty: &PtyPair) -> Result<()> {
    let descriptors = [pty.master.as_raw_fd(), pty.slave.as_raw_fd()];
    send_fds(socket.as_fd(), &descriptors).context("failed to send PTY descriptors")?;
    Ok(())
}

fn receive_pty(socket: &OwnedFd) -> Result<PtyPair> {
    let mut descriptors = receive_fds(socket.as_fd(), 2)
        .context("PTY broker exited without providing two descriptors")?
        .into_iter();
    Ok(PtyPair {
        master: descriptors.next().expect("helper returned two descriptors"),
        slave: descriptors.next().expect("helper returned two descriptors"),
    })
}

fn ensure_broker_success(status: WaitStatus) -> Result<()> {
    match status {
        WaitStatus::Exited(_, 0) => Ok(()),
        WaitStatus::Exited(_, code) => bail!("PTY broker exited with status {code}"),
        WaitStatus::Signaled(_, signal, _) => bail!("PTY broker terminated by {signal}"),
        status => bail!("unexpected PTY broker status: {status:?}"),
    }
}

fn open_console_pty(winsize: Option<&WindowSize>) -> Result<PtyPair> {
    open_pty(winsize).context("failed to allocate foreground console PTY")
}

pub(crate) fn configure_child(slave: &OwnedFd) -> Result<()> {
    setsid().context("failed to create terminal session")?;
    set_controlling_terminal(slave.as_fd()).context("failed to set controlling terminal")?;
    dup_stdio(slave).context("failed to connect console stdio")?;
    Ok(())
}

pub(crate) fn ignore_hangup() -> Result<()> {
    set_signal_handler(
        Signal::Hangup,
        SignalHandler::Ignore,
        SignalActionFlags::empty(),
    )
    .context("failed to ignore interactive SIGHUP")?;
    Ok(())
}

pub(crate) fn send_fd(socket: &OwnedFd, fd: &OwnedFd) -> Result<()> {
    let descriptors = [fd.as_raw_fd()];
    send_fds(socket.as_fd(), &descriptors).context("failed to send interactive PTY")?;
    Ok(())
}

pub(crate) fn receive_fd(socket: &OwnedFd) -> Result<OwnedFd> {
    receive_fds(socket.as_fd(), 1)
        .context("namespace worker exited before providing an interactive PTY")?
        .into_iter()
        .next()
        .context("helper returned no interactive PTY descriptor")
}

pub(crate) fn proxy(
    master: &OwnedFd,
    child: i32,
    shutdown_target: Option<(&ProcessHandle, InitSystem)>,
) -> Result<WaitStatus> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    let _raw_terminal = RawTerminal::enable(stdin.as_fd())?;
    let _signal_forwarding = shutdown_target
        .map(|_| ForwardSignals::install())
        .transpose()?;
    let mut stdin_open = true;
    let mut child_status = None;
    let mut quiet_polls_after_exit = 0_u8;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        if let Some((target, _)) = shutdown_target {
            let signal = FORWARDED_SIGNAL.swap(0, Ordering::Relaxed);
            if let Some(signal) = SignalNumber::new(signal) {
                target
                    .send_signal(signal)
                    .context("failed to forward foreground signal")?;
            }
        }
        let mut read_output = false;
        sync_terminal_size(stdin.as_fd(), master.as_fd())?;
        let (output_ready, read_input) = poll_terminal(master.as_fd(), stdin.as_fd(), stdin_open)?;

        if output_ready {
            match read(master, &mut buffer) {
                Ok(0) => {
                    if let Some(status) = child_status {
                        stdout.flush()?;
                        return Ok(status);
                    }
                }
                Err(error) if is_io_error(&error) => {
                    if let Some(status) = child_status {
                        stdout.flush()?;
                        return Ok(status);
                    }
                }
                Ok(length) => {
                    read_output = true;
                    stdout.write_all(&buffer[..length])?;
                    stdout.flush()?;
                }
                Err(error) if is_interrupted(&error) || is_would_block(&error) => {}
                Err(error) => return Err(error).context("failed to read PTY output"),
            }
        }
        if read_input {
            match read(&stdin, &mut buffer) {
                Ok(0) => stdin_open = false,
                Ok(length) => {
                    let input = &buffer[..length];
                    if let Some((target, system)) = shutdown_target
                        && input.starts_with(&[0x1b, 0x11])
                    {
                        init::request_shutdown(target, system)
                            .context("failed to request foreground shutdown")?;
                        if length > 2 {
                            write_all(master, &input[2..])?;
                        }
                    } else {
                        write_all(master, input)?;
                    }
                }
                Err(error) if is_interrupted(&error) || is_would_block(&error) => {}
                Err(error) => return Err(error).context("failed to read terminal input"),
            }
        }
        if child_status.is_none() {
            match waitpid(child, true)? {
                WaitStatus::StillAlive => {}
                status => child_status = Some(status),
            }
        }
        if let Some(status) = child_status {
            if read_output {
                quiet_polls_after_exit = 0;
            } else {
                quiet_polls_after_exit += 1;
                if quiet_polls_after_exit >= 2 {
                    stdout.flush()?;
                    return Ok(status);
                }
            }
        }
    }
}

fn poll_terminal(
    master: BorrowedFd<'_>,
    stdin: BorrowedFd<'_>,
    stdin_open: bool,
) -> Result<(bool, bool)> {
    let mut poll = Poll::new().context("failed to create terminal poller")?;
    let master_fd = master.as_raw_fd();
    poll.registry()
        .register(&mut SourceFd(&master_fd), Token(0), Interest::READABLE)
        .context("failed to register terminal output")?;
    let stdin_fd = stdin.as_raw_fd();
    if stdin_open {
        poll.registry()
            .register(&mut SourceFd(&stdin_fd), Token(1), Interest::READABLE)
            .context("failed to register terminal input")?;
    }
    let mut events = Events::with_capacity(2);
    if let Err(error) = poll.poll(&mut events, Some(std::time::Duration::from_millis(100)))
        && !is_interrupted(&error)
    {
        return Err(error).context("failed to poll terminal proxy");
    }
    Ok(events
        .iter()
        .fold((false, false), |ready, event| match event.token() {
            Token(0) => (true, ready.1),
            Token(1) => (ready.0, true),
            _ => ready,
        }))
}

fn write_all(fd: &OwnedFd, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        match write(fd, bytes) {
            Ok(0) => bail!("PTY stopped accepting input"),
            Ok(length) => bytes = &bytes[length..],
            Err(error) if is_interrupted(&error) => {}
            Err(error) => return Err(error).context("failed to write PTY input"),
        }
    }
    Ok(())
}

struct RawTerminal {
    original: Option<TerminalSettings>,
}

impl RawTerminal {
    fn enable(fd: std::os::fd::BorrowedFd<'_>) -> Result<Self> {
        if !is_terminal(fd)? {
            return Ok(Self { original: None });
        }
        let original = terminal_settings(fd)?;
        let mut raw = original.clone();
        make_raw(&mut raw);
        set_terminal_settings(fd, &raw)?;
        Ok(Self {
            original: Some(original),
        })
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            let _ = set_terminal_settings(std::io::stdin().as_fd(), original);
        }
    }
}

struct ForwardSignals;

impl ForwardSignals {
    fn install() -> Result<Self> {
        extern "C" fn record(signal: i32) {
            FORWARDED_SIGNAL.store(signal, Ordering::Relaxed);
        }

        for signal in [Signal::Interrupt, Signal::Terminate] {
            set_signal_handler(
                signal,
                SignalHandler::Handler(record),
                SignalActionFlags::RESTART,
            )
            .with_context(|| format!("failed to capture foreground signal {signal}"))?;
        }
        Ok(Self)
    }
}

impl Drop for ForwardSignals {
    fn drop(&mut self) {
        for signal in [Signal::Interrupt, Signal::Terminate] {
            let _ = set_signal_handler(signal, SignalHandler::Ignore, SignalActionFlags::empty());
        }
    }
}

fn sync_terminal_size(
    source: std::os::fd::BorrowedFd<'_>,
    target: std::os::fd::BorrowedFd<'_>,
) -> Result<()> {
    if is_terminal(source)? {
        let size = terminal_size(source)?;
        set_terminal_size(target, &size).context("failed to resize PTY")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "android")]
    #[test]
    fn uses_android_nobody_for_pty_broker() {
        assert_eq!(pty_broker_id(), 9_999);
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn uses_linux_nobody_for_pty_broker() {
        assert_eq!(pty_broker_id(), 65_534);
    }

    #[test]
    fn allocates_terminal_pair() {
        let console = Console::open().expect("PTY allocation should work");
        let slave = console.open_slave().expect("PTY slave should reopen");
        assert!(is_terminal(console.master.as_fd()).unwrap());
        assert!(is_terminal(slave.as_fd()).unwrap());
    }

    #[test]
    fn transfers_terminal_descriptor() {
        let (sender, receiver) = socket_pair().unwrap();
        let console = Console::open().unwrap();
        send_fd(&sender, &console.master).unwrap();
        let transferred = receive_fd(&receiver).unwrap();
        assert!(is_terminal(transferred.as_fd()).unwrap());
    }
}
