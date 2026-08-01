use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::fs::OpenOptionsExt,
    },
    path::{Path, PathBuf},
};

use crate::syscall::{cvt, path_cstring};

const LOOP_ATTACH_ATTEMPTS: usize = 8;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct MountFlags: libc::c_ulong {
        const BIND = libc::MS_BIND;
        const DIRSYNC = libc::MS_DIRSYNC;
        const NODEV = libc::MS_NODEV;
        const NODIRATIME = libc::MS_NODIRATIME;
        const NOATIME = libc::MS_NOATIME;
        const NOEXEC = libc::MS_NOEXEC;
        const NOSUID = libc::MS_NOSUID;
        const PRIVATE = libc::MS_PRIVATE;
        const RDONLY = libc::MS_RDONLY;
        const REC = libc::MS_REC;
        const REMOUNT = libc::MS_REMOUNT;
    }
}

impl MountFlags {
    pub const EMPTY: Self = Self::empty();
}

pub fn mount(
    source: Option<&Path>,
    target: &Path,
    filesystem: Option<&str>,
    flags: MountFlags,
    data: Option<&str>,
) -> io::Result<()> {
    let source = source.map(path_cstring).transpose()?;
    let target = path_cstring(target)?;
    let filesystem = filesystem
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)?;
    let data = data
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)?;
    // SAFETY: each optional pointer is null or points to a live NUL-terminated string.
    let result = unsafe {
        libc::mount(
            source
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            target.as_ptr(),
            filesystem
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            flags.bits(),
            data.as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    };
    cvt(result).map(drop)
}

pub fn unmount(path: &Path, detach: bool) -> io::Result<()> {
    let path = path_cstring(path)?;
    // SAFETY: path is NUL-terminated and flags is a valid umount2 bitmask.
    cvt(unsafe { libc::umount2(path.as_ptr(), if detach { libc::MNT_DETACH } else { 0 }) })
        .map(drop)
}

pub fn filesystem_type(path: &Path) -> io::Result<i64> {
    let path = path_cstring(path)?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: path is NUL-terminated and stat points to writable storage.
    cvt(unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) })?;
    // SAFETY: statfs succeeded and initialized stat.
    let stat = unsafe { stat.assume_init() };
    Ok(stat.f_type as i64)
}

pub const TMPFS_MAGIC: i64 = 0x0102_1994;

#[repr(C)]
struct LoopInfo64 {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    size_limit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; 64],
    crypt_name: [u8; 64],
    encrypt_key: [u8; 32],
    init: [u64; 2],
}

const LOOP_SET_FD: libc::Ioctl = 0x4c00;
const LOOP_CLR_FD: libc::Ioctl = 0x4c01;
const LOOP_SET_STATUS64: libc::Ioctl = 0x4c04;
const LOOP_CTL_GET_FREE: libc::Ioctl = 0x4c82;
const LO_FLAGS_AUTOCLEAR: u32 = 4;

pub struct LoopController {
    file: File,
}

impl LoopController {
    pub fn open() -> io::Result<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/loop-control")
            .map(|file| Self { file })
    }

    pub fn attach(&self, backing_path: &Path) -> io::Result<LoopDevice> {
        for _ in 0..LOOP_ATTACH_ATTEMPTS {
            let index = loop_control_get_free(self.file.as_fd())?;
            let path = [
                PathBuf::from(format!("/dev/loop{index}")),
                PathBuf::from(format!("/dev/block/loop{index}")),
            ]
            .into_iter()
            .find(|candidate| candidate.exists())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "loop device node is unavailable")
            })?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC)
                .open(&path)?;
            let backing = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(backing_path)?;
            match configure_loop_device(file.as_fd(), backing.as_fd(), backing_path) {
                Ok(()) => {
                    return Ok(LoopDevice {
                        file,
                        path,
                        attached: true,
                    });
                }
                Err(error) => {
                    if error.raw_os_error() != Some(libc::EBUSY) {
                        return Err(error);
                    }
                }
            }
        }
        Err(io::Error::from_raw_os_error(libc::EBUSY))
    }
}

pub struct LoopDevice {
    file: File,
    path: PathBuf,
    attached: bool,
}

impl LoopDevice {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn clear(&mut self) -> io::Result<()> {
        if self.attached {
            clear_loop_device(self.file.as_fd())?;
            self.attached = false;
        }
        Ok(())
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}

pub fn loop_control_get_free(fd: BorrowedFd<'_>) -> io::Result<i32> {
    // SAFETY: LOOP_CTL_GET_FREE takes no variadic argument and fd remains live.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), LOOP_CTL_GET_FREE) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub fn configure_loop_device(
    device: BorrowedFd<'_>,
    backing: BorrowedFd<'_>,
    backing_path: &Path,
) -> io::Result<()> {
    // SAFETY: both descriptors remain live and LOOP_SET_FD consumes the integer fd value.
    if unsafe { libc::ioctl(device.as_raw_fd(), LOOP_SET_FD, backing.as_raw_fd()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut info = LoopInfo64 {
        device: 0,
        inode: 0,
        rdevice: 0,
        offset: 0,
        size_limit: 0,
        number: 0,
        encrypt_type: 0,
        encrypt_key_size: 0,
        flags: LO_FLAGS_AUTOCLEAR,
        file_name: [0; 64],
        crypt_name: [0; 64],
        encrypt_key: [0; 32],
        init: [0; 2],
    };
    let name = backing_path.as_os_str().as_encoded_bytes();
    let length = name.len().min(info.file_name.len() - 1);
    info.file_name[..length].copy_from_slice(&name[..length]);
    // SAFETY: info exactly matches Linux's loop_info64 layout on every CI ABI.
    if unsafe { libc::ioctl(device.as_raw_fd(), LOOP_SET_STATUS64, &info) } == -1 {
        let error = io::Error::last_os_error();
        let _ = clear_loop_device(device);
        return Err(error);
    }
    Ok(())
}

pub fn clear_loop_device(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: LOOP_CLR_FD takes no variadic argument and fd remains live.
    cvt(unsafe { libc::ioctl(fd.as_raw_fd(), LOOP_CLR_FD) }).map(drop)
}

pub fn rename_exchange(left: &Path, right: &Path) -> io::Result<()> {
    let left = path_cstring(left)?;
    let right = path_cstring(right)?;
    // SAFETY: both paths are live NUL-terminated strings and flags is valid for renameat2.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            left.as_ptr(),
            libc::AT_FDCWD,
            right.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn sync_filesystem(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: SYS_syncfs accepts one live file descriptor and does not retain it.
    let result = unsafe { libc::syscall(libc::SYS_syncfs, fd.as_raw_fd()) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn set_file_mode(fd: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
    let mode = libc::mode_t::try_from(mode)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file mode exceeds mode_t"))?;
    // SAFETY: fd remains live and mode has the target's exact mode_t type.
    cvt(unsafe { libc::fchmod(fd.as_raw_fd(), mode) }).map(drop)
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[test]
    fn exchanges_paths_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let left = directory.path().join("left");
        let right = directory.path().join("right");
        fs::write(&left, "left").unwrap();
        fs::write(&right, "right").unwrap();

        super::rename_exchange(&left, &right).unwrap();

        assert_eq!(fs::read_to_string(left).unwrap(), "right");
        assert_eq!(fs::read_to_string(right).unwrap(), "left");
    }
}
