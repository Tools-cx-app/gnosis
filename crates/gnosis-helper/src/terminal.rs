use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
};

#[cfg(target_os = "android")]
use std::{
    fs::OpenOptions,
    os::{fd::AsFd, unix::fs::OpenOptionsExt},
};

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct WindowSize {
    pub rows: u16,
    pub columns: u16,
    pub x_pixels: u16,
    pub y_pixels: u16,
}

pub struct PtyPair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

#[cfg(not(target_os = "android"))]
pub fn open_pty(size: Option<&WindowSize>) -> io::Result<PtyPair> {
    let mut master = -1;
    let mut slave = -1;
    let raw_size = size.map(|size| libc::winsize {
        ws_row: size.rows,
        ws_col: size.columns,
        ws_xpixel: size.x_pixels,
        ws_ypixel: size.y_pixels,
    });
    // SAFETY: descriptor pointers are writable and optional winsize is initialized.
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            raw_size.as_ref().map_or(std::ptr::null(), |value| value),
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openpty returned two newly owned descriptors.
    Ok(unsafe {
        PtyPair {
            master: OwnedFd::from_raw_fd(master),
            slave: OwnedFd::from_raw_fd(slave),
        }
    })
}

#[cfg(target_os = "android")]
pub fn open_pty(size: Option<&WindowSize>) -> io::Result<PtyPair> {
    const UNLOCK_REQUEST: libc::Ioctl = libc::_IOW::<libc::c_int>(b'T' as libc::c_uint, 0x31);
    const PEER_REQUEST: libc::Ioctl = libc::_IO(b'T' as libc::c_uint, 0x41);
    let flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;
    let master = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
        .open("/dev/ptmx")?;
    let unlock = 0;
    // SAFETY: unlock points to a live c_int and master is an open PTY master.
    if unsafe { libc::ioctl(master.as_raw_fd(), UNLOCK_REQUEST, &unlock) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: TIOCGPTPEER consumes an integer open flag value and returns a new descriptor.
    let peer = unsafe { libc::ioctl(master.as_raw_fd(), PEER_REQUEST, flags) };
    let slave: OwnedFd = if peer >= 0 {
        // SAFETY: TIOCGPTPEER returned a newly owned descriptor.
        unsafe { OwnedFd::from_raw_fd(peer) }
    } else {
        let path = format!("/dev/pts/{}", pty_number(master.as_fd())?);
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
            .open(path)?
            .into()
    };
    if let Some(size) = size {
        set_terminal_size(slave.as_fd(), size)?;
    }
    Ok(PtyPair {
        master: master.into(),
        slave,
    })
}

pub fn socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: fds has room for two descriptors.
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair returned two newly owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

pub fn send_fds(socket: BorrowedFd<'_>, fds: &[RawFd]) -> io::Result<()> {
    let mut byte = b'P';
    let mut vector = libc::iovec {
        iov_base: std::ptr::from_mut(&mut byte).cast(),
        iov_len: 1,
    };
    let space = cmsg_space(fds.len());
    let mut control = vec![0_u8; space];
    // SAFETY: msghdr is a C POD type and zero is a valid initial state.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control
        .len()
        .try_into()
        .map_err(|_| io::Error::other("descriptor control buffer is too large"))?;
    // SAFETY: message owns a control buffer large enough for one SCM_RIGHTS header and all fds.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as _) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), fds.len());
        message.msg_controllen = (*header).cmsg_len;
        if libc::sendmsg(socket.as_raw_fd(), &message, 0) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn receive_fds(socket: BorrowedFd<'_>, count: usize) -> io::Result<Vec<OwnedFd>> {
    let mut byte = 0_u8;
    let mut vector = libc::iovec {
        iov_base: std::ptr::from_mut(&mut byte).cast(),
        iov_len: 1,
    };
    let mut control = vec![0_u8; cmsg_space(count)];
    // SAFETY: msghdr is a C POD type and zero is a valid initial state.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control
        .len()
        .try_into()
        .map_err(|_| io::Error::other("descriptor control buffer is too large"))?;
    // SAFETY: all message pointers reference live writable buffers.
    if unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut descriptors = Vec::new();
    // SAFETY: recvmsg initialized ancillary headers within message's control buffer.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        // SAFETY: CMSG_FIRSTHDR/CMSG_NXTHDR only return headers inside the control buffer.
        let (length, level, kind) = unsafe {
            (
                (*header).cmsg_len as usize,
                (*header).cmsg_level,
                (*header).cmsg_type,
            )
        };
        // SAFETY: CMSG_LEN(0) returns the target ABI's ancillary-header size.
        let header_length = unsafe { libc::CMSG_LEN(0) as usize };
        let control_length = usize::try_from(message.msg_controllen)
            .map_err(|_| io::Error::other("descriptor control length does not fit usize"))?;
        if length < header_length || length > control_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid descriptor message length",
            ));
        }
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
            let payload = length - header_length;
            if payload % std::mem::size_of::<RawFd>() != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unaligned descriptor message",
                ));
            }
            let received = payload / std::mem::size_of::<RawFd>();
            // SAFETY: the validated SCM_RIGHTS payload contains `received` RawFd values.
            let raw = unsafe {
                std::slice::from_raw_parts(libc::CMSG_DATA(header).cast::<RawFd>(), received)
            };
            descriptors.extend(raw.iter().map(|fd| {
                // SAFETY: every descriptor in an SCM_RIGHTS payload is newly owned.
                unsafe { OwnedFd::from_raw_fd(*fd) }
            }));
        }
        // SAFETY: message and the current header describe the live control buffer.
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated descriptor message",
        ));
    }
    if descriptors.len() != count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected descriptor count",
        ));
    }
    Ok(descriptors)
}

pub fn is_terminal(fd: BorrowedFd<'_>) -> io::Result<bool> {
    // SAFETY: fd remains live.
    let result = unsafe { libc::isatty(fd.as_raw_fd()) };
    if result == 1 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOTTY) {
        Ok(false)
    } else {
        Err(error)
    }
}

pub struct TerminalSettings(libc::termios);

impl Clone for TerminalSettings {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

pub fn terminal_settings(fd: BorrowedFd<'_>) -> io::Result<TerminalSettings> {
    let mut settings = std::mem::MaybeUninit::uninit();
    // SAFETY: settings points to writable termios storage.
    if unsafe { libc::tcgetattr(fd.as_raw_fd(), settings.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: tcgetattr initialized settings.
    Ok(TerminalSettings(unsafe { settings.assume_init() }))
}

pub fn make_raw(settings: &mut TerminalSettings) {
    // SAFETY: settings points to a valid initialized termios value.
    unsafe { libc::cfmakeraw(&mut settings.0) };
}

pub fn set_terminal_settings(fd: BorrowedFd<'_>, settings: &TerminalSettings) -> io::Result<()> {
    // SAFETY: fd is live and settings is initialized.
    if unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSANOW, &settings.0) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn terminal_size(fd: BorrowedFd<'_>) -> io::Result<WindowSize> {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: size points to writable winsize storage.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGWINSZ, &mut size) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowSize {
        rows: size.ws_row,
        columns: size.ws_col,
        x_pixels: size.ws_xpixel,
        y_pixels: size.ws_ypixel,
    })
}

pub fn set_terminal_size(fd: BorrowedFd<'_>, size: &WindowSize) -> io::Result<()> {
    let size = libc::winsize {
        ws_row: size.rows,
        ws_col: size.columns,
        ws_xpixel: size.x_pixels,
        ws_ypixel: size.y_pixels,
    };
    // SAFETY: size points to a readable winsize value.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &size) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn set_controlling_terminal(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: TIOCSCTTY takes an integer argument and fd remains live.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSCTTY, 0) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn pty_number(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut number = 0_u32;
    #[cfg(target_os = "android")]
    const REQUEST: libc::Ioctl = libc::_IOR::<libc::c_int>(b'T' as libc::c_uint, 0x30);
    #[cfg(not(target_os = "android"))]
    const REQUEST: libc::Ioctl = libc::TIOCGPTN;
    // SAFETY: number points to writable u32 storage.
    if unsafe { libc::ioctl(fd.as_raw_fd(), REQUEST, &mut number) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(number)
    }
}

fn cmsg_space(count: usize) -> usize {
    // SAFETY: the requested payload is a bounded count of RawFd values.
    unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32 * count as u32) as usize }
}
