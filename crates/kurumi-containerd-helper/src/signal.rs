use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

use crate::syscall::{cvt, cvt_long};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Signal {
    Hangup = libc::SIGHUP,
    Interrupt = libc::SIGINT,
    Quit = libc::SIGQUIT,
    Kill = libc::SIGKILL,
    User1 = libc::SIGUSR1,
    User2 = libc::SIGUSR2,
    Pipe = libc::SIGPIPE,
    Continue = libc::SIGCONT,
    Power = libc::SIGPWR,
    Terminate = libc::SIGTERM,
}

impl Signal {
    pub const fn raw(self) -> libc::c_int {
        self as libc::c_int
    }
}

impl std::fmt::Display for Signal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.raw())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalNumber(libc::c_int);

impl SignalNumber {
    pub const NONE: Self = Self(0);

    pub fn new(raw: libc::c_int) -> Option<Self> {
        (raw >= 0 && raw <= libc::SIGRTMAX()).then_some(Self(raw))
    }

    pub fn realtime(offset: libc::c_int) -> Option<Self> {
        let raw = libc::SIGRTMIN().checked_add(offset)?;
        Self::new(raw).filter(|signal| signal.raw() >= libc::SIGRTMIN())
    }

    pub const fn raw(self) -> libc::c_int {
        self.0
    }

    pub fn name(self) -> &'static str {
        match self.0 {
            value if value == libc::SIGHUP => "SIGHUP",
            value if value == libc::SIGINT => "SIGINT",
            value if value == libc::SIGQUIT => "SIGQUIT",
            value if value == libc::SIGILL => "SIGILL",
            value if value == libc::SIGTRAP => "SIGTRAP",
            value if value == libc::SIGABRT => "SIGABRT",
            value if value == libc::SIGBUS => "SIGBUS",
            value if value == libc::SIGFPE => "SIGFPE",
            value if value == libc::SIGKILL => "SIGKILL",
            value if value == libc::SIGUSR1 => "SIGUSR1",
            value if value == libc::SIGSEGV => "SIGSEGV",
            value if value == libc::SIGUSR2 => "SIGUSR2",
            value if value == libc::SIGPIPE => "SIGPIPE",
            value if value == libc::SIGALRM => "SIGALRM",
            value if value == libc::SIGTERM => "SIGTERM",
            value if value == libc::SIGSTKFLT => "SIGSTKFLT",
            value if value == libc::SIGCHLD => "SIGCHLD",
            value if value == libc::SIGCONT => "SIGCONT",
            value if value == libc::SIGSTOP => "SIGSTOP",
            value if value == libc::SIGTSTP => "SIGTSTP",
            value if value == libc::SIGTTIN => "SIGTTIN",
            value if value == libc::SIGTTOU => "SIGTTOU",
            value if value == libc::SIGURG => "SIGURG",
            value if value == libc::SIGXCPU => "SIGXCPU",
            value if value == libc::SIGXFSZ => "SIGXFSZ",
            value if value == libc::SIGVTALRM => "SIGVTALRM",
            value if value == libc::SIGPROF => "SIGPROF",
            value if value == libc::SIGWINCH => "SIGWINCH",
            value if value == libc::SIGIO => "SIGIO",
            value if value == libc::SIGPWR => "SIGPWR",
            value if value == libc::SIGSYS => "SIGSYS",
            _ => "unknown signal",
        }
    }

    pub(crate) const fn from_kernel(raw: libc::c_int) -> Self {
        Self(raw)
    }
}

impl From<Signal> for SignalNumber {
    fn from(signal: Signal) -> Self {
        Self(signal.raw())
    }
}

impl std::fmt::Display for SignalNumber {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct SignalActionFlags: libc::c_int {
        const RESTART = libc::SA_RESTART;
    }
}

#[derive(Clone, Copy)]
pub enum SignalHandler {
    Default,
    Ignore,
    Handler(extern "C" fn(libc::c_int)),
}

pub fn kill(pid: libc::pid_t, signal: impl Into<SignalNumber>) -> io::Result<()> {
    // SAFETY: kill accepts a numeric pid and validated signal number.
    cvt(unsafe { libc::kill(pid, signal.into().raw()) }).map(drop)
}

pub fn kill_process_group(pid: libc::pid_t, signal: impl Into<SignalNumber>) -> io::Result<()> {
    // SAFETY: a negative pid selects the process group and the signal is validated.
    cvt(unsafe { libc::kill(-pid, signal.into().raw()) }).map(drop)
}

pub fn pidfd_send_signal(fd: BorrowedFd<'_>, signal: SignalNumber) -> io::Result<()> {
    // SAFETY: fd is live, signal is validated, siginfo is null, and flags is zero.
    cvt_long(unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal.raw(),
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    })
    .map(drop)
}

pub fn set_signal_handler(
    signal: Signal,
    handler: SignalHandler,
    flags: SignalActionFlags,
) -> io::Result<()> {
    // Zero initialization matches sigemptyset plus zeroed platform padding.
    // SAFETY: sigaction is a plain C struct and zero is a valid initial mask.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = match handler {
        SignalHandler::Default => libc::SIG_DFL,
        SignalHandler::Ignore => libc::SIG_IGN,
        SignalHandler::Handler(handler) => handler as usize,
    };
    action.sa_flags = flags.bits();
    // SAFETY: action is initialized and its mask is made empty.
    cvt(unsafe { libc::sigemptyset(&mut action.sa_mask) })?;
    // SAFETY: action remains live and contains a valid handler representation.
    cvt(unsafe { libc::sigaction(signal.raw(), &action, std::ptr::null_mut()) }).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_signal_numbers_and_flags() {
        assert_eq!(SignalNumber::from(Signal::Kill).raw(), libc::SIGKILL);
        assert_eq!(SignalNumber::new(0), Some(SignalNumber::NONE));
        assert_eq!(SignalNumber::new(-1), None);
        assert_eq!(SignalNumber::new(libc::SIGRTMAX() + 1), None);
        assert_eq!(
            SignalNumber::realtime(3).unwrap().raw(),
            libc::SIGRTMIN() + 3
        );
        assert_eq!(SignalActionFlags::RESTART.bits(), libc::SA_RESTART);
    }
}
