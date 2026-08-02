use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use kurumi_containerd_config::Config;
use kurumi_containerd_helper::fs::{LoopController, LoopDevice, MountFlags, mount, unmount};

mod install;

#[derive(Debug, Clone)]
pub struct Rootfs {
    configured: Option<PathBuf>,
    image: Option<PathBuf>,
    mountpoint: PathBuf,
}

struct PreparedRootfs {
    path: PathBuf,
    loop_device: Option<LoopDevice>,
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
        let (source, mut loop_device) = if metadata.file_type().is_block_device() {
            (image.clone(), None)
        } else {
            let device = LoopController::open()
                .context("failed to open /dev/loop-control")?
                .attach(image)
                .context("failed to attach rootfs image")?;
            (device.path().to_path_buf(), Some(device))
        };
        if let Err(error) = mount(
            Some(&source),
            &mountpoint,
            Some(filesystem),
            MountFlags::NOATIME | MountFlags::NODIRATIME,
            None,
        ) {
            if let Some(device) = &mut loop_device {
                let _ = device.clear();
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
        if let Some(device) = &mut self.loop_device {
            let _ = device.clear();
        }
        if self.mounted {
            let _ = fs::remove_dir(&self.path);
        }
    }
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
