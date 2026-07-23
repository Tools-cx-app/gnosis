use std::{
    io::{self, IoSlice, IoSliceMut, Write},
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicI32, Ordering},
};

use anyhow::{Context, Result, bail};
#[cfg(not(target_os = "android"))]
use nix::pty::openpty;
use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    pty::{OpenptyResult, Winsize},
    sys::{
        socket::{
            AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
            recvmsg, sendmsg, socketpair,
        },
        stat::{Mode, fchmod},
        termios::{SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{
        ForkResult, Gid, Pid, Uid, dup2_stderr, dup2_stdin, dup2_stdout, fork, read, setgid,
        setgroups, setsid, setuid, write,
    },
};

use super::process::ProcessHandle;
use crate::container::init::{self, InitSystem};

static FORWARDED_SIGNAL: AtomicI32 = AtomicI32::new(0);

pub(crate) struct Console {
    pub(crate) master: OwnedFd,
    pub(crate) slave: OwnedFd,
}

impl Console {
    pub(crate) fn open() -> Result<Self> {
        let winsize = terminal_size(std::io::stdin().as_fd()).ok();
        let OpenptyResult { master, slave } = if Uid::effective().is_root() {
            open_console_pty_unprivileged(winsize.as_ref())?
        } else {
            open_console_pty(winsize.as_ref())?
        };
        let _ = nix::unistd::fchown(
            &slave,
            Some(nix::unistd::Uid::from_raw(0)),
            Some(nix::unistd::Gid::from_raw(5)),
        );
        let _ = fchmod(&slave, Mode::from_bits_truncate(0o620));
        Ok(Self { master, slave })
    }
}

#[allow(unsafe_code)]
fn open_console_pty_unprivileged(winsize: Option<&Winsize>) -> Result<OpenptyResult> {
    let (parent, child) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .context("failed to create PTY broker channel")?;
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
                    eprintln!("gnosis PTY broker: {error:#}");
                    1
                }
            };
            std::process::exit(code);
        }
        ForkResult::Parent { child: broker } => {
            drop(child);
            let received = receive_pty(&parent);
            drop(parent);
            let status = waitpid(broker, None).context("failed waiting for PTY broker")?;
            ensure_broker_success(status)?;
            received
        }
    }
}

fn drop_pty_broker_privileges() -> Result<()> {
    let id = pty_broker_id();
    setgroups(&[]).context("failed to clear PTY broker supplementary groups")?;
    setgid(Gid::from_raw(id)).context("failed to drop PTY broker GID")?;
    setuid(Uid::from_raw(id)).context("failed to drop PTY broker UID")?;
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

fn send_pty(socket: &OwnedFd, pty: &OpenptyResult) -> Result<()> {
    let payload = [IoSlice::new(b"P")];
    let descriptors = [pty.master.as_raw_fd(), pty.slave.as_raw_fd()];
    let control = [ControlMessage::ScmRights(&descriptors)];
    sendmsg::<()>(
        socket.as_raw_fd(),
        &payload,
        &control,
        MsgFlags::empty(),
        None,
    )
    .context("failed to send PTY descriptors")?;
    Ok(())
}

#[allow(unsafe_code)]
fn receive_pty(socket: &OwnedFd) -> Result<OpenptyResult> {
    let mut payload = [0_u8; 1];
    let mut vectors = [IoSliceMut::new(&mut payload)];
    let mut control = nix::cmsg_space!([std::os::fd::RawFd; 2]);
    let message = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut vectors,
        Some(&mut control),
        MsgFlags::empty(),
    )
    .context("failed to receive PTY descriptors")?;
    let descriptors = message
        .cmsgs()?
        .find_map(|message| match message {
            ControlMessageOwned::ScmRights(fds) if fds.len() == 2 => Some(fds),
            _ => None,
        })
        .context("PTY broker exited without providing two descriptors")?;
    // SAFETY: SCM_RIGHTS created two new descriptors owned by this process.
    Ok(OpenptyResult {
        master: unsafe { OwnedFd::from_raw_fd(descriptors[0]) },
        slave: unsafe { OwnedFd::from_raw_fd(descriptors[1]) },
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

#[cfg(not(target_os = "android"))]
fn open_console_pty(winsize: Option<&Winsize>) -> Result<OpenptyResult> {
    openpty(winsize, None).context("failed to allocate foreground console PTY")
}

#[cfg(target_os = "android")]
#[allow(unsafe_code)]
fn open_console_pty(winsize: Option<&Winsize>) -> Result<OpenptyResult> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    const TIOCSPTLCK: libc::c_int = libc::_IOW::<libc::c_int>('T' as libc::c_uint, 0x31);
    const TIOCGPTPEER: libc::c_int = libc::_IO('T' as libc::c_uint, 0x41);
    const TIOCGPTN: libc::c_int = libc::_IOR::<libc::c_int>('T' as libc::c_uint, 0x30);

    let flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;
    let master = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
        .open("/dev/ptmx")
        .context("failed to open Android PTY master")?;
    let unlock = 0;
    let _ = unsafe { libc::ioctl(master.as_raw_fd(), TIOCSPTLCK, &unlock) };

    let peer = unsafe { libc::ioctl(master.as_raw_fd(), TIOCGPTPEER, flags) };
    let slave: OwnedFd = if peer >= 0 {
        // SAFETY: TIOCGPTPEER returned a new descriptor owned by this process.
        unsafe { OwnedFd::from_raw_fd(peer) }
    } else {
        let mut number = 0_u32;
        if unsafe { libc::ioctl(master.as_raw_fd(), TIOCGPTN, &mut number) } < 0 {
            return Err(io::Error::last_os_error()).context("failed to resolve Android PTY number");
        }
        let path = format!("/dev/pts/{number}");
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| format!("failed to open Android PTY slave {path}"))?
            .into()
    };
    if let Some(winsize) = winsize {
        let result = unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ, winsize) };
        if result < 0 {
            return Err(io::Error::last_os_error()).context("failed to set Android PTY size");
        }
    }
    Ok(OpenptyResult {
        master: master.into(),
        slave,
    })
}

#[allow(unsafe_code)]
pub(crate) fn configure_child(slave: &OwnedFd) -> Result<()> {
    setsid().context("failed to create terminal session")?;
    // SAFETY: TIOCSCTTY only associates this open PTY slave with the new session.
    let result = unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY, 0) };
    if result == -1 {
        return Err(io::Error::last_os_error()).context("failed to set controlling terminal");
    }
    dup2_stdin(slave).context("failed to connect console stdin")?;
    dup2_stdout(slave).context("failed to connect console stdout")?;
    dup2_stderr(slave).context("failed to connect console stderr")?;
    Ok(())
}

#[allow(unsafe_code)]
pub(crate) fn ignore_hangup() -> Result<()> {
    use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};

    let action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
    // SAFETY: action contains SIG_IGN and an initialized empty signal mask.
    unsafe { sigaction(Signal::SIGHUP, &action) }.context("failed to ignore interactive SIGHUP")?;
    Ok(())
}

pub(crate) fn send_fd(socket: &OwnedFd, fd: &OwnedFd) -> Result<()> {
    let payload = [IoSlice::new(b"P")];
    let descriptors = [fd.as_raw_fd()];
    let control = [ControlMessage::ScmRights(&descriptors)];
    sendmsg::<()>(
        socket.as_raw_fd(),
        &payload,
        &control,
        MsgFlags::empty(),
        None,
    )
    .context("failed to send interactive PTY")?;
    Ok(())
}

#[allow(unsafe_code)]
pub(crate) fn receive_fd(socket: &OwnedFd) -> Result<OwnedFd> {
    let mut payload = [0_u8; 1];
    let mut vectors = [IoSliceMut::new(&mut payload)];
    let mut control = nix::cmsg_space!([std::os::fd::RawFd; 1]);
    let message = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut vectors,
        Some(&mut control),
        MsgFlags::empty(),
    )
    .context("failed to receive interactive PTY")?;
    let raw_fd = message
        .cmsgs()?
        .find_map(|message| match message {
            ControlMessageOwned::ScmRights(fds) => fds.into_iter().next(),
            _ => None,
        })
        .context("namespace worker exited before providing an interactive PTY")?;
    // SAFETY: SCM_RIGHTS returned a new descriptor owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

#[allow(unsafe_code)]
pub(crate) fn proxy(
    master: &OwnedFd,
    child: Pid,
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
            if signal != 0 {
                target
                    .send_signal_raw(signal)
                    .context("failed to forward foreground signal")?;
            }
        }
        let mut read_output = false;
        sync_terminal_size(stdin.as_fd(), master.as_fd())?;
        let stdin_events = if stdin_open {
            PollFlags::POLLIN
        } else {
            PollFlags::empty()
        };
        let mut fds = [
            PollFd::new(master.as_fd(), PollFlags::POLLIN),
            PollFd::new(stdin.as_fd(), stdin_events),
        ];
        match poll(&mut fds, PollTimeout::from(100_u16)) {
            Ok(_) | Err(Errno::EINTR) => {}
            Err(error) => return Err(error).context("failed to poll terminal proxy"),
        }

        if fds[0]
            .revents()
            .is_some_and(|events| events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP))
        {
            match read(master, &mut buffer) {
                Ok(0) | Err(Errno::EIO) => {
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
                Err(Errno::EINTR | Errno::EAGAIN) => {}
                Err(error) => return Err(error).context("failed to read PTY output"),
            }
        }
        if stdin_open
            && fds[1]
                .revents()
                .is_some_and(|events| events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP))
        {
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
                Err(Errno::EINTR | Errno::EAGAIN) => {}
                Err(error) => return Err(error).context("failed to read terminal input"),
            }
        }
        if child_status.is_none() {
            match waitpid(child, Some(WaitPidFlag::WNOHANG))? {
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

fn write_all(fd: &OwnedFd, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        match write(fd, bytes) {
            Ok(0) => bail!("PTY stopped accepting input"),
            Ok(length) => bytes = &bytes[length..],
            Err(Errno::EINTR) => {}
            Err(error) => return Err(error).context("failed to write PTY input"),
        }
    }
    Ok(())
}

struct RawTerminal {
    original: Option<Termios>,
}

impl RawTerminal {
    fn enable(fd: std::os::fd::BorrowedFd<'_>) -> Result<Self> {
        if !nix::unistd::isatty(fd)? {
            return Ok(Self { original: None });
        }
        let original = tcgetattr(fd)?;
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        tcsetattr(fd, SetArg::TCSANOW, &raw)?;
        Ok(Self {
            original: Some(original),
        })
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            let _ = tcsetattr(std::io::stdin(), SetArg::TCSANOW, original);
        }
    }
}

struct ForwardSignals;

impl ForwardSignals {
    #[allow(unsafe_code)]
    fn install() -> Result<Self> {
        use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};

        extern "C" fn record(signal: libc::c_int) {
            FORWARDED_SIGNAL.store(signal, Ordering::Relaxed);
        }

        let action = SigAction::new(
            SigHandler::Handler(record),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );
        for signal in [Signal::SIGINT, Signal::SIGTERM] {
            // SAFETY: record only stores an integer in a lock-free atomic.
            unsafe { sigaction(signal, &action) }
                .with_context(|| format!("failed to capture foreground signal {signal}"))?;
        }
        Ok(Self)
    }
}

impl Drop for ForwardSignals {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};

        let action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
        for signal in [Signal::SIGINT, Signal::SIGTERM] {
            // SAFETY: action contains SIG_IGN and an initialized empty signal mask.
            let _ = unsafe { sigaction(signal, &action) };
        }
    }
}

#[allow(unsafe_code)]
fn sync_terminal_size(
    source: std::os::fd::BorrowedFd<'_>,
    target: std::os::fd::BorrowedFd<'_>,
) -> Result<()> {
    if nix::unistd::isatty(source)? {
        let size = terminal_size(source)?;
        // SAFETY: target is an open PTY master and size points to a valid winsize value.
        let result = unsafe { libc::ioctl(target.as_raw_fd(), libc::TIOCSWINSZ, &size) };
        if result == -1 {
            return Err(io::Error::last_os_error()).context("failed to resize PTY");
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
fn terminal_size(fd: std::os::fd::BorrowedFd<'_>) -> Result<Winsize> {
    let mut size = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: fd is borrowed for this call and size is valid writable storage.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGWINSZ, &mut size) };
    if result == -1 {
        return Err(io::Error::last_os_error()).context("failed to read terminal size");
    }
    Ok(size)
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
        assert!(nix::unistd::isatty(&console.master).unwrap());
        assert!(nix::unistd::isatty(&console.slave).unwrap());
    }

    #[test]
    fn transfers_terminal_descriptor() {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

        let (sender, receiver) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        let console = Console::open().unwrap();
        send_fd(&sender, &console.master).unwrap();
        let transferred = receive_fd(&receiver).unwrap();
        assert!(nix::unistd::isatty(transferred).unwrap());
    }
}
