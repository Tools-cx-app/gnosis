use std::{
    ffi::{CStr, CString},
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    path::Path,
};

use crate::syscall::{cvt, cvt_long, cvt_ssize, path_cstring};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct NamespaceFlags: i32 {
        const CGROUP = libc::CLONE_NEWCGROUP;
        const IPC = libc::CLONE_NEWIPC;
        const MOUNT = libc::CLONE_NEWNS;
        const NETWORK = libc::CLONE_NEWNET;
        const PID = libc::CLONE_NEWPID;
        const USER = libc::CLONE_NEWUSER;
        const UTS = libc::CLONE_NEWUTS;
    }
}

impl NamespaceFlags {
    pub const EMPTY: Self = Self::empty();
}

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

impl std::fmt::Display for Signal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", *self as i32)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitStatus {
    Exited(i32, i32),
    Signaled(i32, SignalNumber, bool),
    Stopped(i32, SignalNumber),
    Continued(i32),
    StillAlive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalNumber(i32);

impl SignalNumber {
    pub const fn raw(self) -> i32 {
        self.0
    }
}

impl std::fmt::Display for SignalNumber {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

#[derive(Debug)]
pub enum ForkResult {
    Parent { child: i32 },
    Child,
}

pub fn current_pid() -> i32 {
    // SAFETY: getpid has no preconditions.
    unsafe { libc::getpid() }
}

pub fn parent_pid() -> i32 {
    // SAFETY: getppid has no preconditions.
    unsafe { libc::getppid() }
}

/// # Safety
///
/// The caller must ensure the process is single-threaded or otherwise obey
/// `fork(2)`'s restrictions before invoking this function.
pub unsafe fn fork() -> io::Result<ForkResult> {
    // SAFETY: upheld by the caller.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(ForkResult::Child),
        child => Ok(ForkResult::Parent { child }),
    }
}

pub fn unshare(flags: NamespaceFlags) -> io::Result<()> {
    // SAFETY: flags are Linux CLONE_NEW* bits accepted by unshare.
    cvt(unsafe { libc::unshare(flags.bits()) }).map(drop)
}

pub fn setns(fd: BorrowedFd<'_>, namespace: NamespaceFlags) -> io::Result<()> {
    // SAFETY: fd remains live and namespace is a valid namespace type or zero.
    cvt(unsafe { libc::setns(fd.as_raw_fd(), namespace.bits()) }).map(drop)
}

pub fn waitpid(pid: i32, nohang: bool) -> io::Result<WaitStatus> {
    let mut status = 0;
    // SAFETY: status points to writable storage and options is valid.
    let result = unsafe { libc::waitpid(pid, &mut status, if nohang { libc::WNOHANG } else { 0 }) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if result == 0 {
        return Ok(WaitStatus::StillAlive);
    }
    if libc::WIFEXITED(status) {
        Ok(WaitStatus::Exited(result, libc::WEXITSTATUS(status)))
    } else if libc::WIFSIGNALED(status) {
        Ok(WaitStatus::Signaled(
            result,
            SignalNumber(libc::WTERMSIG(status)),
            libc::WCOREDUMP(status),
        ))
    } else if libc::WIFSTOPPED(status) {
        Ok(WaitStatus::Stopped(
            result,
            SignalNumber(libc::WSTOPSIG(status)),
        ))
    } else {
        Ok(WaitStatus::Continued(result))
    }
}

pub fn kill(pid: i32, signal: Signal) -> io::Result<()> {
    // SAFETY: kill accepts a numeric pid and signal.
    cvt(unsafe { libc::kill(pid, signal as i32) }).map(drop)
}

pub fn kill_process_group(pid: i32, signal: Signal) -> io::Result<()> {
    // SAFETY: a negative pid selects the process group.
    cvt(unsafe { libc::kill(-pid, signal as i32) }).map(drop)
}

pub fn setsid() -> io::Result<i32> {
    // SAFETY: setsid has no memory-safety preconditions.
    cvt(unsafe { libc::setsid() })
}

pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: fds has storage for both returned descriptors.
    cvt(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    // SAFETY: pipe2 initialized two newly owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

pub fn read(fd: impl AsFd, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: buffer is valid writable storage and fd remains borrowed.
    cvt_ssize(unsafe {
        libc::read(
            fd.as_fd().as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    })
}

pub fn write(fd: impl AsFd, buffer: &[u8]) -> io::Result<usize> {
    // SAFETY: buffer is valid readable storage and fd remains borrowed.
    cvt_ssize(unsafe { libc::write(fd.as_fd().as_raw_fd(), buffer.as_ptr().cast(), buffer.len()) })
}

pub fn dup_stdio(fd: impl AsFd) -> io::Result<()> {
    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: fd remains live and target is a standard descriptor number.
        cvt(unsafe { libc::dup2(fd.as_fd().as_raw_fd(), target) })?;
    }
    Ok(())
}

pub fn chdir(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path_cstring(path.as_ref())?;
    // SAFETY: path is NUL-terminated.
    cvt(unsafe { libc::chdir(path.as_ptr()) }).map(drop)
}

pub fn fchdir(fd: impl AsFd) -> io::Result<()> {
    // SAFETY: fd remains live for the call.
    cvt(unsafe { libc::fchdir(fd.as_fd().as_raw_fd()) }).map(drop)
}

pub fn chroot(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path_cstring(path.as_ref())?;
    // SAFETY: path is NUL-terminated.
    cvt(unsafe { libc::chroot(path.as_ptr()) }).map(drop)
}

pub fn pivot_root(new_root: impl AsRef<Path>, put_old: impl AsRef<Path>) -> io::Result<()> {
    let new_root = path_cstring(new_root.as_ref())?;
    let put_old = path_cstring(put_old.as_ref())?;
    // SAFETY: both paths are NUL-terminated.
    cvt_long(unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), put_old.as_ptr()) })
        .map(drop)
}

pub fn set_hostname(hostname: &str) -> io::Result<()> {
    // sethostname takes an explicit byte length and does not require a trailing NUL.
    #[cfg(target_os = "android")]
    // SAFETY: hostname's byte slice is live and SYS_sethostname accepts its explicit length.
    return cvt_long(unsafe {
        libc::syscall(
            libc::SYS_sethostname,
            hostname.as_ptr().cast::<libc::c_char>(),
            hostname.len(),
        )
    })
    .map(drop);
    #[cfg(not(target_os = "android"))]
    // SAFETY: hostname's byte slice is live for the duration of the call.
    cvt(unsafe { libc::sethostname(hostname.as_ptr().cast(), hostname.len()) }).map(drop)
}

pub fn execve(program: &CStr, arguments: &[CString], environment: &[CString]) -> io::Result<()> {
    let mut argv = arguments
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null());
    let mut envp = environment
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    envp.push(std::ptr::null());
    // SAFETY: all pointers are NUL-terminated and both pointer arrays end in null.
    cvt(unsafe { libc::execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr()) }).map(drop)
}

pub fn set_uid(uid: u32) -> io::Result<()> {
    // SAFETY: setuid accepts a numeric uid.
    cvt(unsafe { libc::setuid(uid) }).map(drop)
}

pub fn set_gid(gid: u32) -> io::Result<()> {
    // SAFETY: setgid accepts a numeric gid.
    cvt(unsafe { libc::setgid(gid) }).map(drop)
}

pub fn set_groups(groups: &[u32]) -> io::Result<()> {
    // libc::gid_t is u32 on all CI targets.
    // SAFETY: groups is valid for groups.len() gid_t values.
    cvt(unsafe { libc::setgroups(groups.len(), groups.as_ptr()) }).map(drop)
}

pub fn init_groups(user: &CStr, gid: u32) -> io::Result<()> {
    // SAFETY: user is NUL-terminated and gid is numeric.
    cvt(unsafe { libc::initgroups(user.as_ptr(), gid) }).map(drop)
}

pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

pub fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open accepts a numeric pid and zero flags.
    let fd = cvt_long(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) })?;
    let fd = i32::try_from(fd).map_err(io::Error::other)?;
    // SAFETY: pidfd_open returned a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn pidfd_send_signal(fd: BorrowedFd<'_>, signal: i32) -> io::Result<()> {
    // SAFETY: fd is live, siginfo is null, and flags is zero.
    cvt_long(unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    })
    .map(drop)
}

pub fn poll(fds: &mut [PollFd], timeout_ms: i32) -> io::Result<usize> {
    let mut raw = fds
        .iter()
        .map(|fd| libc::pollfd {
            fd: fd.fd.as_raw_fd(),
            events: fd.events,
            revents: 0,
        })
        .collect::<Vec<_>>();
    // SAFETY: raw points to raw.len() initialized pollfd values.
    let count =
        cvt(unsafe { libc::poll(raw.as_mut_ptr(), raw.len() as libc::nfds_t, timeout_ms) })?;
    for (fd, raw) in fds.iter_mut().zip(raw) {
        fd.revents = raw.revents;
    }
    Ok(count as usize)
}

#[derive(Debug)]
pub struct PollFd<'fd> {
    fd: BorrowedFd<'fd>,
    events: i16,
    revents: i16,
}

impl<'fd> PollFd<'fd> {
    pub fn new(fd: BorrowedFd<'fd>, events: i16) -> Self {
        Self {
            fd,
            events,
            revents: 0,
        }
    }

    pub const fn revents(&self) -> i16 {
        self.revents
    }
}

pub const POLL_IN: i16 = libc::POLLIN;
pub const POLL_HANGUP: i16 = libc::POLLHUP;

#[derive(Clone, Copy)]
pub enum SignalHandler {
    Default,
    Ignore,
    Handler(extern "C" fn(i32)),
}

pub fn set_signal_handler(signal: Signal, handler: SignalHandler, restart: bool) -> io::Result<()> {
    // Zero initialization matches sigemptyset plus zeroed platform padding.
    // SAFETY: sigaction is a plain C struct and zero is a valid initial mask.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = match handler {
        SignalHandler::Default => libc::SIG_DFL,
        SignalHandler::Ignore => libc::SIG_IGN,
        SignalHandler::Handler(handler) => handler as usize,
    };
    action.sa_flags = if restart { libc::SA_RESTART } else { 0 };
    // SAFETY: action is initialized and its mask is made empty.
    cvt(unsafe { libc::sigemptyset(&mut action.sa_mask) })?;
    // SAFETY: action remains live and contains a valid handler representation.
    cvt(unsafe { libc::sigaction(signal as i32, &action, std::ptr::null_mut()) }).map(drop)
}

pub fn is_interrupted(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EINTR)
}

pub fn is_would_block(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EAGAIN))
}

pub fn is_io_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EIO)
}

pub fn realtime_min() -> i32 {
    libc::SIGRTMIN()
}
