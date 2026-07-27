use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsFd,
        unix::fs::{FileTypeExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use gnosis_config::Config;
use gnosis_helper::{
    MountFlags, OPEN_CLOEXEC, OPEN_NOFOLLOW, clear_loop_device, configure_loop_device,
    loop_control_get_free, mount, unmount,
};

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
            MountFlags::NOATIME | MountFlags::NODIRATIME,
            None,
        ) {
            if let Some(device) = &loop_device {
                clear_loop(device);
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
            let _ = unmount(&self.path, true);
        }
        if let Some(device) = &self.loop_device {
            clear_loop(device);
        }
        if self.mounted {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn attach_loop(image: &Path) -> Result<(PathBuf, File)> {
    let control = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(OPEN_CLOEXEC)
        .open("/dev/loop-control")
        .context("failed to open /dev/loop-control")?;
    let index = loop_control_get_free(control.as_fd()).context("failed to allocate loop device")?;
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
        .custom_flags(OPEN_CLOEXEC)
        .open(&path)?;
    let backing = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(OPEN_CLOEXEC | OPEN_NOFOLLOW)
        .open(image)
        .context("failed to open writable rootfs image backing file")?;
    configure_loop_device(device.as_fd(), backing.as_fd(), image)
        .context("failed to configure loop device")?;
    Ok((path, device))
}

fn clear_loop(fd: &File) {
    let _ = clear_loop_device(fd.as_fd());
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
