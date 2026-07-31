use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use kurumi_containerd_helper::{
    MountFlags, NamespaceFlags, chdir, execve, mount, pivot_root, set_hostname, unmount, unshare,
};
use uuid::Uuid;

#[cfg(target_os = "android")]
use crate::host::android;
use crate::{
    Runtime,
    container::{environment, init, security},
    host::{network::Network, terminal},
};

impl Runtime {
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(super) fn boot(
        &self,
        _boot_status: &std::os::fd::OwnedFd,
        network_status: std::os::fd::OwnedFd,
        configured_rootfs: &Path,
        console: Option<&terminal::Console>,
        init_system: init::InitSystem,
        host_cgroup_v2: bool,
        uuid: Uuid,
    ) -> Result<()> {
        if let Some(console) = console {
            let slave = console.open_slave()?;
            terminal::configure_child(&slave)?;
        }
        let mut status = String::new();
        File::from(network_status).read_to_string(&mut status)?;
        ensure!(!status.is_empty(), "host network setup did not complete");
        Network::setup_child(&self.config, &status)?;
        if init_system == init::InitSystem::Systemd && host_cgroup_v2 {
            unshare(NamespaceFlags::CGROUP).context("failed to create systemd cgroup namespace")?;
        }
        unshare(NamespaceFlags::MOUNT).context("failed to create mount namespace")?;
        mount(
            None,
            Path::new("/"),
            None,
            MountFlags::REC | MountFlags::PRIVATE,
            None,
        )
        .context("failed to make mount tree private")?;
        let lower_rootfs = configured_rootfs;
        mount(
            Some(lower_rootfs),
            lower_rootfs,
            None,
            MountFlags::BIND | MountFlags::REC,
            None,
        )
        .context("failed to bind rootfs")?;
        // Directory rootfs paths commonly live below a nosuid host mount (notably
        // /data on Android). Keep those host flags from disabling setuid tools such
        // as chsh inside this private mount namespace.
        mount(
            None,
            lower_rootfs,
            None,
            MountFlags::BIND | MountFlags::REMOUNT,
            None,
        )
        .context("failed to enable rootfs execution privileges")?;
        let volatile_root;
        let rootfs = if self.config.container.volatile {
            volatile_root = self.setup_volatile_root(lower_rootfs)?;
            &volatile_root
        } else {
            lower_rootfs
        };
        for dir in [".old_root", "proc", "sys", "dev", "run", "tmp"] {
            fs::create_dir_all(rootfs.join(dir))
                .with_context(|| format!("failed to create rootfs/{dir}"))?;
        }
        #[cfg(target_os = "android")]
        android::setup_before_pivot(rootfs, &self.config.container.android)?;
        self.validate_bind_targets(rootfs)?;
        if let Some(console) = console {
            let target = rootfs.join("dev/console");
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            File::create(&target).context("failed to create rootfs/dev/console")?;
            mount(
                Some(Path::new(&console.slave_path)),
                &target,
                None,
                MountFlags::BIND,
                None,
            )
            .context("failed to bind foreground PTY to rootfs/dev/console")?;
        }
        chdir(rootfs).context("failed to enter rootfs")?;
        pivot_root(Path::new("."), Path::new(".old_root")).context("pivot_root failed")?;
        chdir("/").context("failed to enter new root")?;

        mount(
            Some(Path::new("proc")),
            Path::new("/proc"),
            Some("proc"),
            MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            None,
        )
        .context("failed to mount proc")?;
        mount(
            Some(Path::new("sysfs")),
            Path::new("/sys"),
            Some("sysfs"),
            MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            None,
        )
        .context("failed to mount sysfs")?;
        if init_system == init::InitSystem::Systemd {
            fs::create_dir_all("/sys/fs/cgroup")?;
            mount(
                Some(Path::new("none")),
                Path::new("/sys/fs/cgroup"),
                Some("tmpfs"),
                MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                Some("mode=755,size=16M"),
            )
            .context("failed to mount systemd cgroup tmpfs base")?;
            if host_cgroup_v2 {
                mount(
                    Some(Path::new("cgroup2")),
                    Path::new("/sys/fs/cgroup"),
                    Some("cgroup2"),
                    MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                    None,
                )
                .context("failed to mount systemd cgroup2 hierarchy")?;
            } else {
                fs::create_dir_all("/sys/fs/cgroup/systemd")?;
                mount(
                    Some(Path::new("cgroup")),
                    Path::new("/sys/fs/cgroup/systemd"),
                    Some("cgroup"),
                    MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                    Some("none,name=systemd"),
                )
                .context("failed to mount legacy systemd cgroup hierarchy")?;
            }
        }
        mount(
            Some(Path::new("tmpfs")),
            Path::new("/run"),
            Some("tmpfs"),
            MountFlags::NOSUID | MountFlags::NODEV,
            Some("mode=755"),
        )
        .context("failed to mount /run")?;
        mount(
            Some(Path::new("tmpfs")),
            Path::new("/tmp"),
            Some("tmpfs"),
            MountFlags::NOSUID | MountFlags::NODEV,
            Some("mode=1777"),
        )
        .context("failed to mount /tmp")?;
        mount(
            Some(Path::new("tmpfs")),
            Path::new("/dev"),
            Some("tmpfs"),
            MountFlags::NOSUID | MountFlags::NOEXEC,
            Some("mode=755"),
        )
        .context("failed to mount /dev")?;
        fs::create_dir_all("/dev/pts")?;
        mount(
            Some(Path::new("devpts")),
            Path::new("/dev/pts"),
            Some("devpts"),
            MountFlags::NOSUID | MountFlags::NOEXEC,
            Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
        )
        .context("failed to mount private devpts")?;
        for device in ["null", "zero", "full", "random", "urandom", "tty"] {
            let old = PathBuf::from("/.old_root/dev").join(device);
            let target = PathBuf::from("/dev").join(device);
            File::create(&target)
                .with_context(|| format!("failed to create {}", target.display()))?;
            mount(Some(&old), &target, None, MountFlags::BIND, None)
                .with_context(|| format!("failed to bind {}", target.display()))?;
        }
        std::os::unix::fs::symlink("pts/ptmx", "/dev/ptmx")?;
        std::os::unix::fs::symlink("/proc/self/fd", "/dev/fd")?;
        std::os::unix::fs::symlink("/proc/self/fd/0", "/dev/stdin")?;
        std::os::unix::fs::symlink("/proc/self/fd/1", "/dev/stdout")?;
        std::os::unix::fs::symlink("/proc/self/fd/2", "/dev/stderr")?;
        #[cfg(target_os = "android")]
        android::setup_after_pivot(&self.config.container.android)?;
        self.mount_binds_inside()?;
        unmount(Path::new("/.old_root"), true).context("failed to detach old root")?;
        fs::remove_dir("/.old_root").ok();
        Network::setup_dhcp(&self.config)?;
        Network::write_dns(&self.config, Path::new("/"))?;
        set_container_hostname(&self.config.container.hostname)?;

        fs::create_dir_all("/run/kurumi-containerd")?;
        fs::write("/run/kurumi-containerd/name", &self.config.container.name)?;
        fs::write("/run/kurumi-containerd/uuid", uuid.to_string())?;
        fs::write("/run/kurumi-containerd/version", env!("CARGO_PKG_VERSION"))?;
        fs::write(
            "/run/kurumi-containerd/container.toml",
            toml::to_string(&self.config)?,
        )?;
        init::prepare_runtime(init_system)?;
        environment::write_profile_environment(
            &self.config.container.environment,
            &self.config.container.android,
        )?;
        security::harden_mounts(&self.config.container.security)?;
        security::install_seccomp(&self.config.container.security)?;

        let init =
            std::ffi::CString::new(self.config.container.init.as_os_str().as_encoded_bytes())?;
        let argv = [init.clone()];
        let env = environment::container_environment(
            &self.config.container.environment,
            &self.config.container.android,
        )?;
        execve(&init, &argv, &env).context("failed to execute init")?;
        Ok(())
    }

    fn validate_bind_targets(&self, rootfs: &Path) -> Result<()> {
        for bind in &self.config.container.mounts {
            ensure_no_symlink_components(rootfs, &bind.target)?;
        }
        Ok(())
    }

    fn mount_binds_inside(&self) -> Result<()> {
        let mut binds = self.config.container.mounts.iter().collect::<Vec<_>>();
        binds.sort_by(|left, right| {
            left.target
                .components()
                .count()
                .cmp(&right.target.components().count())
                .then_with(|| left.target.cmp(&right.target))
        });
        for bind in binds {
            ensure_no_symlink_components(Path::new("/"), &bind.target)?;
            let source = Path::new("/.old_root").join(strip_root(&bind.source));
            let target = Path::new("/").join(strip_root(&bind.target));
            if !source.exists() {
                bail!(
                    "bind mount source does not exist: {} -> {}",
                    source.display(),
                    target.display()
                );
            }
            if source.is_dir() {
                fs::create_dir_all(&target)?;
            } else {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                create_mountpoint_file(&target)?;
            }
            mount(
                Some(&source),
                &target,
                None,
                MountFlags::BIND | MountFlags::REC,
                None,
            )?;
            if bind.read_only {
                mount(
                    None,
                    &target,
                    None,
                    MountFlags::BIND | MountFlags::REMOUNT | MountFlags::RDONLY,
                    None,
                )?;
            }
        }
        Ok(())
    }

    fn setup_volatile_root(&self, lower: &Path) -> Result<PathBuf> {
        tracing::debug!(lower = %lower.display(), "setting up volatile rootfs");
        let base = self.volatile_dir.join(&self.config.container.name);
        fs::create_dir_all(&base)?;
        mount(
            Some(Path::new("tmpfs")),
            &base,
            Some("tmpfs"),
            MountFlags::NOSUID | MountFlags::NODEV,
            Some("mode=700"),
        )
        .context("failed to mount volatile tmpfs")?;
        let upper = base.join("upper");
        let work = base.join("work");
        let merged = base.join("merged");
        for directory in [&upper, &work, &merged] {
            fs::create_dir_all(directory)?;
        }
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.display(),
            upper.display(),
            work.display()
        );
        mount(
            Some(Path::new("overlay")),
            &merged,
            Some("overlay"),
            MountFlags::EMPTY,
            Some(options.as_str()),
        )
        .context("failed to mount volatile overlay")?;
        Ok(merged)
    }
}

fn strip_root(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

fn create_mountpoint_file(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        File::create_new(path)?;
    }
    Ok(())
}

fn set_container_hostname(hostname: &str) -> Result<()> {
    set_hostname(hostname).context("failed to set hostname")
}

fn ensure_no_symlink_components(rootfs: &Path, target: &Path) -> Result<()> {
    let mut current = rootfs.to_path_buf();
    for component in strip_root(target).components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "bind target traverses symlink: {}",
                current.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", current.display()));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::create_mountpoint_file;

    #[test]
    fn existing_mountpoint_file_is_not_truncated() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("target");
        std::fs::write(&path, "existing content").unwrap();

        create_mountpoint_file(&path).unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "existing content");
    }
}
