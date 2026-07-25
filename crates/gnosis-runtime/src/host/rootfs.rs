use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, RawFd},
        unix::fs::{FileTypeExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use gnosis_config::Config;
use nix::mount::{MntFlags, MsFlags, mount, umount2};

#[cfg(target_os = "android")]
mod magic {
    pub const LOOP_SET_FD: libc::c_int = 0x4c00;
    pub const LOOP_CLR_FD: libc::c_int = 0x4c01;
    pub const LOOP_SET_STATUS64: libc::c_int = 0x4c04;
    pub const LOOP_CTL_GET_FREE: libc::c_int = 0x4c82;
}

#[cfg(all(not(target_os = "android"), not(target_env = "musl")))]
mod magic {
    pub const LOOP_SET_FD: libc::c_ulong = 0x4c00;
    pub const LOOP_CLR_FD: libc::c_ulong = 0x4c01;
    pub const LOOP_SET_STATUS64: libc::c_ulong = 0x4c04;
    pub const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4c82;
}

#[cfg(all(not(target_os = "android"), target_env = "musl"))]
mod magic {
    pub const LOOP_SET_FD: libc::c_int = 0x4c00;
    pub const LOOP_CLR_FD: libc::c_int = 0x4c01;
    pub const LOOP_SET_STATUS64: libc::c_int = 0x4c04;
    pub const LOOP_CTL_GET_FREE: libc::c_int = 0x4c82;
}

use magic::{LOOP_CLR_FD, LOOP_CTL_GET_FREE, LOOP_SET_FD, LOOP_SET_STATUS64};
const LO_FLAGS_AUTOCLEAR: u32 = 4;

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

impl Default for LoopInfo64 {
    fn default() -> Self {
        Self {
            device: 0,
            inode: 0,
            rdevice: 0,
            offset: 0,
            size_limit: 0,
            number: 0,
            encrypt_type: 0,
            encrypt_key_size: 0,
            flags: 0,
            file_name: [0; 64],
            crypt_name: [0; 64],
            encrypt_key: [0; 32],
            init: [0; 2],
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rootfs {
    configured: Option<PathBuf>,
    image: Option<PathBuf>,
    mountpoint: PathBuf,
}

struct PreparedRootfs {
    path: PathBuf,
    loop_device: Option<File>,
    mounted: bool,
}

impl Rootfs {
    pub(crate) fn new(config: &Config, mount_dir: &Path) -> Self {
        Self {
            configured: config.container.rootfs.clone(),
            image: config.container.rootfs_image.clone(),
            mountpoint: mount_dir.join(&config.container.name),
        }
    }

    pub fn prepare(&self) -> Result<impl AsRef<Path> + use<>> {
        if let Some(path) = &self.configured {
            return Ok(PreparedRootfs {
                path: path.clone(),
                loop_device: None,
                mounted: false,
            });
        }
        let image = self
            .image
            .as_ref()
            .context("rootfs image is not configured")?;
        let filesystem = detect_filesystem(image)?;
        let mountpoint = self.mountpoint.clone();
        fs::create_dir_all(&mountpoint)?;

        let metadata = fs::metadata(image)?;
        let (source, loop_device) = if metadata.file_type().is_block_device() {
            (image.clone(), None)
        } else {
            let (path, device) = attach_loop(image)?;
            (path, Some(device))
        };
        if let Err(error) = mount(
            Some(&source),
            &mountpoint,
            Some(filesystem),
            MsFlags::MS_NOATIME | MsFlags::MS_NODIRATIME,
            None::<&str>,
        ) {
            if let Some(device) = &loop_device {
                clear_loop(device.as_raw_fd());
            }
            return Err(error).context("failed to mount rootfs image");
        }
        Ok(PreparedRootfs {
            path: mountpoint,
            loop_device,
            mounted: true,
        })
    }
}

impl AsRef<Path> for PreparedRootfs {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for PreparedRootfs {
    fn drop(&mut self) {
        if self.mounted {
            let _ = umount2(&self.path, MntFlags::MNT_DETACH);
        }
        if let Some(device) = &self.loop_device {
            clear_loop(device.as_raw_fd());
        }
        if self.mounted {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

#[allow(unsafe_code)]
fn attach_loop(image: &Path) -> Result<(PathBuf, File)> {
    let control = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/loop-control")
        .context("failed to open /dev/loop-control")?;
    // SAFETY: LOOP_CTL_GET_FREE takes no pointer argument and returns a loop index.
    let index = unsafe { libc::ioctl(control.as_raw_fd(), LOOP_CTL_GET_FREE) };
    if index < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to allocate loop device");
    }
    let path = [
        PathBuf::from(format!("/dev/loop{index}")),
        PathBuf::from(format!("/dev/block/loop{index}")),
    ]
    .into_iter()
    .find(|candidate| candidate.exists())
    .context("allocated loop device node is unavailable")?;
    let device = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(&path)?;
    let backing = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(image)
        .context("failed to open writable rootfs image backing file")?;
    // SAFETY: both descriptors are live and LOOP_SET_FD consumes only the integer fd value.
    if unsafe { libc::ioctl(device.as_raw_fd(), LOOP_SET_FD, backing.as_raw_fd()) } < 0 {
        return Err(std::io::Error::last_os_error()).context("LOOP_SET_FD failed");
    }
    let mut info = LoopInfo64 {
        flags: LO_FLAGS_AUTOCLEAR,
        ..LoopInfo64::default()
    };
    let name = image.as_os_str().as_encoded_bytes();
    let length = name.len().min(info.file_name.len() - 1);
    info.file_name[..length].copy_from_slice(&name[..length]);
    // SAFETY: info is a correctly laid out loop_info64 value valid for this ioctl call.
    if unsafe { libc::ioctl(device.as_raw_fd(), LOOP_SET_STATUS64, &info) } < 0 {
        clear_loop(device.as_raw_fd());
        return Err(std::io::Error::last_os_error()).context("LOOP_SET_STATUS64 failed");
    }
    Ok((path, device))
}

#[allow(unsafe_code)]
fn clear_loop(fd: RawFd) {
    // SAFETY: LOOP_CLR_FD takes no pointer argument; errors are best-effort during cleanup.
    let _ = unsafe { libc::ioctl(fd, LOOP_CLR_FD) };
}

fn detect_filesystem(path: &Path) -> Result<&'static str> {
    let mut file = File::open(path)?;
    let mut header = vec![0_u8; 0x10048];
    let read = file.read(&mut header)?;
    if read >= 0x43a && header[0x438..0x43a] == [0x53, 0xef] {
        return Ok("ext4");
    }
    if read >= 0x10048 && &header[0x10040..0x10048] == b"_BHRfS_M" {
        return Ok("btrfs");
    }
    bail!("unsupported rootfs image filesystem; expected ext4 or btrfs")
}
