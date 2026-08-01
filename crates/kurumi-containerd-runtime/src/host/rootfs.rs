use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail, ensure};
use kurumi_containerd_config::Config;
use kurumi_containerd_helper::{
    LoopController, LoopDevice, MountFlags, effective_uid, mount, rename_exchange, sync_filesystem,
    unmount,
};
use uuid::Uuid;

use super::archive;

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

    pub(crate) fn install(
        &self,
        archive: &Path,
        size: Option<u64>,
        force: bool,
        validate: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            archive.is_file(),
            "rootfs archive is not a file: {}",
            archive.display()
        );
        match (&self.configured, &self.image) {
            (Some(target), None) => {
                ensure!(
                    size.is_none(),
                    "--size is only valid with container.rootfs_image"
                );
                install_directory(archive, target, force, validate)
            }
            (None, Some(target)) => {
                let size = size.context("--size is required with container.rootfs_image")?;
                install_image(archive, target, size, &self.mountpoint, force, validate)
            }
            _ => bail!("configure exactly one rootfs target"),
        }
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

fn install_directory(
    archive_path: &Path,
    target: &Path,
    force: bool,
    validate: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    ensure_trusted_parent(target)?;
    reject_unsafe_target(target, force, true)?;
    let staged = sibling(target, "install");
    fs::create_dir(&staged)
        .with_context(|| format!("failed to create temporary rootfs {}", staged.display()))?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o700))?;
    let result = (|| {
        archive::extract(archive_path, &staged)?;
        validate(&staged)?;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;
        commit(&staged, target, force)
    })();
    if staged.exists() {
        let _ = fs::remove_dir_all(&staged);
    }
    result
}

fn install_image(
    archive_path: &Path,
    target: &Path,
    size: u64,
    mount_base: &Path,
    force: bool,
    validate: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    ensure!(size > 0, "rootfs image size must be greater than zero");
    ensure_trusted_parent(target)?;
    reject_unsafe_target(target, force, false)?;
    let staged = sibling(target, "install");
    let result = (|| {
        let image = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged)?;
        image.set_len(size)?;
        image.sync_all()?;
        format_ext4(&staged)?;

        let mountpoint = mount_base.with_extension(format!("install-{}", Uuid::new_v4()));
        let mut mounted = MountedImage::mount(&staged, &mountpoint)?;
        archive::extract(archive_path, mounted.path())?;
        validate(mounted.path())?;
        mounted.finish()?;
        commit(&staged, target, force)
    })();
    if staged.exists() {
        let _ = fs::remove_file(&staged);
    }
    result
}

fn format_ext4(path: &Path) -> Result<()> {
    let formatter = [
        "/usr/sbin/mke2fs",
        "/sbin/mke2fs",
        "/system/bin/mke2fs",
        "/usr/sbin/mkfs.ext4",
        "/sbin/mkfs.ext4",
        "/system/bin/mkfs.ext4",
    ]
    .into_iter()
    .find(|candidate| Path::new(candidate).is_file())
    .context("mke2fs or mkfs.ext4 was not found")?;
    let output = Command::new(formatter)
        .args(["-q", "-F", "-t", "ext4"])
        .arg(path)
        .env_clear()
        .output()
        .context("failed to execute ext4 formatter")?;
    ensure!(
        output.status.success(),
        "ext4 formatter failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

struct MountedImage {
    path: PathBuf,
    loop_device: Option<LoopDevice>,
    mounted: bool,
}

impl MountedImage {
    fn mount(image: &Path, path: &Path) -> Result<Self> {
        fs::create_dir_all(path)?;
        let mut device = LoopController::open()
            .context("failed to open /dev/loop-control")?
            .attach(image)
            .context("failed to attach temporary rootfs image")?;
        if let Err(error) = mount(
            Some(device.path()),
            path,
            Some("ext4"),
            MountFlags::NOATIME | MountFlags::NODIRATIME,
            None,
        ) {
            let _ = device.clear();
            let _ = fs::remove_dir(path);
            return Err(error).context("failed to mount temporary rootfs image");
        }
        Ok(Self {
            path: path.to_path_buf(),
            loop_device: Some(device),
            mounted: true,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn finish(&mut self) -> Result<()> {
        let root = File::open(&self.path)?;
        sync_filesystem(root.as_fd())?;
        unmount(&self.path, false).context("failed to unmount temporary rootfs image")?;
        self.mounted = false;
        if let Some(device) = self.loop_device.take() {
            let mut device = device;
            device.clear()?;
        }
        fs::remove_dir(&self.path)?;
        Ok(())
    }
}

impl Drop for MountedImage {
    fn drop(&mut self) {
        if self.mounted {
            let _ = unmount(&self.path, true);
        }
        self.loop_device.take();
        let _ = fs::remove_dir(&self.path);
    }
}

fn reject_unsafe_target(target: &Path, force: bool, directory: bool) -> Result<()> {
    if let Ok(metadata) = target.symlink_metadata() {
        ensure!(
            !metadata.file_type().is_symlink(),
            "rootfs target cannot be a symlink"
        );
        ensure!(
            if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
            "existing rootfs target has the wrong file type: {}",
            target.display()
        );
        ensure!(force, "rootfs target already exists: {}", target.display());
    }
    Ok(())
}

fn commit(staged: &Path, target: &Path, force: bool) -> Result<()> {
    let parent = target.parent().context("rootfs target has no parent")?;
    if !target.exists() {
        fs::rename(staged, target)
            .with_context(|| format!("failed to install rootfs at {}", target.display()))?;
        return File::open(parent)?.sync_all().map_err(Into::into);
    }
    ensure!(force, "rootfs target already exists: {}", target.display());
    rename_exchange(staged, target).context("failed to atomically replace rootfs")?;
    File::open(parent)?.sync_all()?;
    if let Err(error) = remove_path(staged) {
        tracing::warn!(path = %staged.display(), %error, "failed to remove replaced rootfs");
    } else {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn remove_path(path: &Path) -> Result<()> {
    if path.symlink_metadata()?.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn sibling(target: &Path, kind: &str) -> PathBuf {
    let name = target.file_name().unwrap_or_default().to_string_lossy();
    target.with_file_name(format!(".{name}.{kind}-{}", Uuid::new_v4()))
}

fn ensure_trusted_parent(target: &Path) -> Result<()> {
    let parent = target.parent().context("rootfs target has no parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir(),
        "rootfs parent is not a directory: {}",
        parent.display()
    );
    ensure!(
        !metadata.file_type().is_symlink(),
        "rootfs parent must not be a symlink"
    );
    ensure!(
        metadata.uid() == effective_uid(),
        "rootfs parent has an untrusted owner"
    );
    ensure!(
        metadata.mode() & 0o022 == 0,
        "rootfs parent must not be group/world writable"
    );
    for ancestor in parent.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0,
            "rootfs ancestor is writable by an untrusted user: {}",
            ancestor.display()
        );
    }
    Ok(())
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

#[cfg(test)]
mod install_tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn directory_install_commits_valid_archive() {
        let directory = tempdir().unwrap();
        let archive = make_archive(directory.path());
        let target = directory.path().join("rootfs");

        install_directory(&archive, &target, false, validate_init).unwrap();

        assert_eq!(fs::read(target.join("sbin/init")).unwrap(), b"init");
    }

    #[test]
    fn existing_directory_requires_force() {
        let directory = tempdir().unwrap();
        let archive = make_archive(directory.path());
        let target = directory.path().join("rootfs");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("old"), "old").unwrap();

        assert!(install_directory(&archive, &target, false, validate_init).is_err());
        assert!(target.join("old").exists());
        install_directory(&archive, &target, true, validate_init).unwrap();
        assert!(!target.join("old").exists());
        assert!(target.join("sbin/init").exists());
    }

    #[test]
    fn failed_validation_preserves_existing_directory() {
        let directory = tempdir().unwrap();
        let archive = make_archive(directory.path());
        let target = directory.path().join("rootfs");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("old"), "old").unwrap();

        assert!(install_directory(&archive, &target, true, |_| bail!("invalid")).is_err());
        assert_eq!(fs::read_to_string(target.join("old")).unwrap(), "old");
    }

    #[test]
    fn rejects_symlink_target_even_with_force() {
        let directory = tempdir().unwrap();
        let archive = make_archive(directory.path());
        let outside = directory.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let target = directory.path().join("rootfs");
        std::os::unix::fs::symlink(&outside, &target).unwrap();

        assert!(install_directory(&archive, &target, true, validate_init).is_err());
    }

    #[test]
    fn directory_install_rejects_existing_file() {
        let directory = tempdir().unwrap();
        let archive = make_archive(directory.path());
        let target = directory.path().join("rootfs");
        fs::write(&target, "not a directory").unwrap();

        assert!(install_directory(&archive, &target, true, validate_init).is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "not a directory");
    }

    #[test]
    fn committed_directory_is_traversable() {
        let directory = tempdir().unwrap();
        let archive = make_archive(directory.path());
        let target = directory.path().join("rootfs");

        install_directory(&archive, &target, false, validate_init).unwrap();

        assert_eq!(
            fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn rejects_world_writable_target_parent() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let archive = make_archive(directory.path());
        let target = directory.path().join("rootfs");

        assert!(install_directory(&archive, &target, false, validate_init).is_err());
    }

    #[test]
    fn sparse_file_has_requested_logical_size() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("image");
        let file = File::create(&path).unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();
        let metadata = file.metadata().unwrap();

        assert_eq!(metadata.len(), 64 * 1024 * 1024);
        assert!(std::os::unix::fs::MetadataExt::blocks(&metadata) * 512 < metadata.len());
    }

    #[test]
    fn formatted_sparse_file_is_ext4() {
        if ![
            "/usr/sbin/mke2fs",
            "/sbin/mke2fs",
            "/system/bin/mke2fs",
            "/usr/sbin/mkfs.ext4",
            "/sbin/mkfs.ext4",
            "/system/bin/mkfs.ext4",
        ]
        .iter()
        .any(|path| Path::new(path).is_file())
        {
            return;
        }
        let directory = tempdir().unwrap();
        let path = directory.path().join("rootfs.img");
        let file = File::create(&path).unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();

        format_ext4(&path).unwrap();

        assert_eq!(detect_filesystem(&path).unwrap(), "ext4");
        let metadata = fs::metadata(path).unwrap();
        assert_eq!(metadata.len(), 64 * 1024 * 1024);
        assert!(std::os::unix::fs::MetadataExt::blocks(&metadata) * 512 < metadata.len());
    }

    #[test]
    fn size_matches_configured_target_type() {
        let directory = tempdir().unwrap();
        let archive = make_archive(directory.path());
        let rootfs = Rootfs {
            configured: Some(directory.path().join("rootfs")),
            image: None,
            mountpoint: directory.path().join("mount"),
        };
        assert!(
            rootfs
                .install(&archive, Some(1024), false, validate_init)
                .is_err()
        );

        let rootfs = Rootfs {
            configured: None,
            image: Some(directory.path().join("rootfs.img")),
            mountpoint: directory.path().join("mount"),
        };
        assert!(
            rootfs
                .install(&archive, None, false, validate_init)
                .is_err()
        );
    }

    fn validate_init(path: &Path) -> Result<()> {
        ensure!(path.join("sbin/init").is_file(), "missing init");
        Ok(())
    }

    fn make_archive(directory: &Path) -> PathBuf {
        let path = directory.join(format!("rootfs-{}.tar", Uuid::new_v4()));
        let file = File::create(&path).unwrap();
        let mut archive = tar::Builder::new(file);
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o755);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        archive
            .append_data(&mut header, "sbin/init", &b"init"[..])
            .unwrap();
        archive.finish().unwrap();
        path
    }
}
