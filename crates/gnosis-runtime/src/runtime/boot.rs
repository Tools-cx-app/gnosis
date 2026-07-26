use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use nix::{
    mount::{MntFlags, MsFlags, mount, umount2},
    sched::{CloneFlags, unshare},
    unistd::{chdir, execve, pivot_root},
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
            unshare(CloneFlags::CLONE_NEWCGROUP)
                .context("failed to create systemd cgroup namespace")?;
        }
        unshare(CloneFlags::CLONE_NEWNS).context("failed to create mount namespace")?;
        mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)
            .context("failed to make mount tree private")?;
        let lower_rootfs = configured_rootfs;
        mount(
            Some(lower_rootfs),
            lower_rootfs,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .context("failed to bind rootfs")?;
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
                Some(console.slave_path.as_str()),
                &target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .context("failed to bind foreground PTY to rootfs/dev/console")?;
        }
        chdir(rootfs).context("failed to enter rootfs")?;
        pivot_root(Path::new("."), Path::new(".old_root")).context("pivot_root failed")?;
        chdir("/").context("failed to enter new root")?;

        mount(
            Some("proc"),
            "/proc",
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .context("failed to mount proc")?;
        mount(
            Some("sysfs"),
            "/sys",
            Some("sysfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .context("failed to mount sysfs")?;
        if init_system == init::InitSystem::Systemd {
            fs::create_dir_all("/sys/fs/cgroup")?;
            mount(
                Some("none"),
                "/sys/fs/cgroup",
                Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                Some("mode=755,size=16M"),
            )
            .context("failed to mount systemd cgroup tmpfs base")?;
            if host_cgroup_v2 {
                mount(
                    Some("cgroup2"),
                    "/sys/fs/cgroup",
                    Some("cgroup2"),
                    MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                    None::<&str>,
                )
                .context("failed to mount systemd cgroup2 hierarchy")?;
            } else {
                fs::create_dir_all("/sys/fs/cgroup/systemd")?;
                mount(
                    Some("cgroup"),
                    "/sys/fs/cgroup/systemd",
                    Some("cgroup"),
                    MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                    Some("none,name=systemd"),
                )
                .context("failed to mount legacy systemd cgroup hierarchy")?;
            }
        }
        mount(
            Some("tmpfs"),
            "/run",
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("mode=755"),
        )
        .context("failed to mount /run")?;
        mount(
            Some("tmpfs"),
            "/tmp",
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("mode=1777"),
        )
        .context("failed to mount /tmp")?;
        mount(
            Some("tmpfs"),
            "/dev",
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("mode=755"),
        )
        .context("failed to mount /dev")?;
        fs::create_dir_all("/dev/pts")?;
        mount(
            Some("devpts"),
            "/dev/pts",
            Some("devpts"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
        )
        .context("failed to mount private devpts")?;
        for device in ["null", "zero", "full", "random", "urandom", "tty"] {
            let old = PathBuf::from("/.old_root/dev").join(device);
            let target = PathBuf::from("/dev").join(device);
            File::create(&target)
                .with_context(|| format!("failed to create {}", target.display()))?;
            mount(
                Some(&old),
                &target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
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
        umount2("/.old_root", MntFlags::MNT_DETACH).context("failed to detach old root")?;
        fs::remove_dir("/.old_root").ok();
        Network::write_dns(&self.config, Path::new("/"))?;
        set_container_hostname(&self.config.container.hostname)?;

        fs::create_dir_all("/run/gnosis")?;
        fs::write("/run/gnosis/name", &self.config.container.name)?;
        fs::write("/run/gnosis/uuid", uuid.to_string())?;
        fs::write("/run/gnosis/version", env!("CARGO_PKG_VERSION"))?;
        fs::write("/run/gnosis/container.toml", toml::to_string(&self.config)?)?;
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
                File::create(&target)?;
            }
            mount(
                Some(&source),
                &target,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )?;
            if bind.read_only {
                mount::<Path, Path, str, str>(
                    None,
                    &target,
                    None,
                    MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                    None,
                )?;
            }
        }
        Ok(())
    }

    fn setup_volatile_root(&self, lower: &Path) -> Result<PathBuf> {
        let base = self.volatile_dir.join(&self.config.container.name);
        fs::create_dir_all(&base)?;
        mount(
            Some("tmpfs"),
            &base,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
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
            Some("overlay"),
            &merged,
            Some("overlay"),
            MsFlags::empty(),
            Some(options.as_str()),
        )
        .context("failed to mount volatile overlay")?;
        Ok(merged)
    }
}

fn strip_root(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

#[cfg(not(target_os = "android"))]
fn set_container_hostname(hostname: &str) -> Result<()> {
    nix::unistd::sethostname(hostname).context("failed to set hostname")
}

#[cfg(target_os = "android")]
#[allow(unsafe_code)]
fn set_container_hostname(hostname: &str) -> Result<()> {
    let hostname = std::ffi::CString::new(hostname)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_sethostname,
            hostname.as_ptr(),
            hostname.as_bytes().len(),
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set hostname");
    }
    Ok(())
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
