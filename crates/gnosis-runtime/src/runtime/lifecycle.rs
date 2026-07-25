use std::{
    fs::{self, File},
    io::Read,
    os::fd::{AsRawFd, OwnedFd},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use gnosis_config::{NetworkMode, strip_root};
use nix::{
    fcntl::OFlag,
    mount::{MntFlags, MsFlags, mount, umount2},
    sched::{CloneFlags, unshare},
    sys::{
        signal::{Signal, kill},
        wait::{WaitStatus, waitpid},
    },
    unistd::{ForkResult, Pid, chdir, execve, fork, getpid, pivot_root, setsid},
};
use uuid::Uuid;

#[cfg(target_os = "android")]
use crate::host::android;
use crate::{
    ContainerState, Runtime,
    container::{environment, init, security},
    host::{
        cgroup::Cgroup,
        network::Network,
        process::{ProcessHandle, parent_pid as process_parent, require_handle},
        rootfs::Rootfs,
        terminal,
    },
    runtime::state::{
        host_boot_id, namespace_inode, process_start_time, validate_process_identity,
    },
};

use super::supervisor::{
    configure_monitor_signals, configure_parent_death_signal, ignore_foreground_parent_signals,
    is_reboot_status, read_retry, redirect_stdio_to_null, reset_init_signals, wait_status_code,
    waitpid_retry,
};

impl Runtime {
    /// Starts the configured container and returns its persisted runtime state.
    ///
    /// # Errors
    ///
    /// Returns an error when privileges, namespace support, mounts, rootfs
    /// setup, or init execution are unavailable.
    #[allow(unsafe_code)]
    pub fn start(&self, foreground_override: bool) -> Result<ContainerState> {
        Self::ensure_root()?;
        self.ensure_layout()?;
        let lock = self.lock()?;
        ensure!(
            self.state()?.is_none(),
            "container '{}' is already running",
            self.config.container.name
        );

        let (reader, writer) = nix::unistd::pipe().context("failed to create startup pipe")?;
        // SAFETY: the CLI is single-threaded at this point and the child immediately enters the monitor path.
        match unsafe { fork() }.context("failed to fork monitor")? {
            ForkResult::Parent { child } => {
                drop(writer);
                let mut file = File::from(reader);
                let mut payload = String::new();
                file.read_to_string(&mut payload)
                    .context("failed to read monitor startup result")?;
                let state: ContainerState = serde_json::from_str(&payload)
                    .with_context(|| format!("container failed to start: {payload}"))?;
                drop(lock);
                if foreground_override || self.config.container.foreground {
                    ignore_foreground_parent_signals()?;
                    let status = waitpid(child, None).context("failed waiting for monitor")?;
                    ensure!(
                        matches!(status, WaitStatus::Exited(_, 0)),
                        "container exited with {status:?}"
                    );
                }
                Ok(state)
            }
            ForkResult::Child => {
                drop(lock);
                drop(reader);
                let foreground = foreground_override || self.config.container.foreground;
                let result = self.monitor(writer, foreground);
                if let Err(error) = result {
                    self.remove_state().ok();
                    eprintln!("gnosis monitor: {error:#}");
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
        }
    }

    #[allow(unsafe_code)]
    #[allow(clippy::too_many_lines)]
    fn monitor(&self, startup: OwnedFd, foreground: bool) -> Result<()> {
        let mut startup = Some(startup);
        if !foreground {
            setsid().context("failed to detach monitor session")?;
        }
        configure_monitor_signals()?;
        let console = terminal::Console::open()?;
        #[cfg(target_os = "android")]
        let _selinux = android::SelinuxGuard::apply(
            &self.config.container.android,
            &self.config.runtime.workdir,
        )?;
        let host_netns = File::open("/proc/self/ns/net")?;
        unshare(CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWIPC)
            .context("failed to create UTS/IPC namespaces")?;
        let rootfs = Rootfs::prepare(&self.config)?;
        let init_system = init::detect(rootfs.path(), &self.config.container.init);
        let uuid = self.config.container.uuid.unwrap_or_else(Uuid::new_v4);
        let mut cgroup = Cgroup::create(
            &self.config.runtime.workdir,
            &self.config.container.name,
            uuid,
            &self.config.container.resources,
        )?;
        let host_boot_id = host_boot_id()?;
        let monitor_pid = getpid().as_raw();
        let monitor_start_time = process_start_time(monitor_pid)?;
        let mut generation = 0_u64;
        let mut first_boot = true;
        let mut generation_lock = None;

        loop {
            let (boot_reader, boot_writer) =
                nix::unistd::pipe2(OFlag::O_CLOEXEC).context("failed to create boot pipe")?;
            let (network_reader, mut network_writer) =
                nix::unistd::pipe2(OFlag::O_CLOEXEC).context("failed to create network pipe")?;
            let (pid_reader, mut pid_writer) =
                nix::unistd::pipe2(OFlag::O_CLOEXEC).context("failed to create PID pipe")?;
            let (result_reader, mut result_writer) =
                nix::unistd::pipe2(OFlag::O_CLOEXEC).context("failed to create result pipe")?;

            // SAFETY: the single-threaded monitor forks a generation worker which only unshares and forks init.
            let intermediate =
                match unsafe { fork() }.context("failed to fork generation worker")? {
                    ForkResult::Parent { child } => child,
                    ForkResult::Child => {
                        drop(startup.take());
                        drop(generation_lock.take());
                        drop(pid_reader);
                        drop(result_reader);
                        let mut flags = CloneFlags::CLONE_NEWPID;
                        if self.config.container.network != NetworkMode::Host {
                            flags |= CloneFlags::CLONE_NEWNET;
                        }
                        unshare(flags).unwrap_or_else(|error| {
                            eprintln!(
                                "gnosis generation: failed to create PID/network namespace: {error}"
                            );
                            std::process::exit(125);
                        });
                        let generation_parent = getpid();
                        // SAFETY: the generation worker is single-threaded and the child immediately boots.
                        match unsafe { fork() }.unwrap_or_else(|error| {
                            eprintln!("gnosis generation: failed to fork init: {error}");
                            std::process::exit(125);
                        }) {
                            ForkResult::Parent { child } => {
                                drop(network_reader);
                                drop(network_writer);
                                drop(boot_reader);
                                drop(boot_writer);
                                nix::unistd::write(&mut pid_writer, &child.as_raw().to_ne_bytes())
                                    .unwrap_or_else(|_| std::process::exit(125));
                                drop(pid_writer);
                                if !foreground {
                                    redirect_stdio_to_null();
                                }
                                let status = waitpid_retry(child)
                                    .unwrap_or_else(|_| std::process::exit(125));
                                let result = if is_reboot_status(status) { b'R' } else { b'E' };
                                nix::unistd::write(&mut result_writer, &[result])
                                    .unwrap_or_else(|_| std::process::exit(125));
                                std::process::exit(wait_status_code(status));
                            }
                            ForkResult::Child => {
                                drop(pid_writer);
                                drop(result_writer);
                                drop(network_writer);
                                drop(boot_reader);
                                configure_parent_death_signal(generation_parent);
                                reset_init_signals();
                                self.boot(
                                    &boot_writer,
                                    network_reader,
                                    rootfs.path(),
                                    Some(&console.slave),
                                    uuid,
                                )
                                .unwrap_or_else(|error| {
                                    let message = format!("{error:#}");
                                    let _ = nix::unistd::write(&boot_writer, message.as_bytes());
                                    eprintln!("gnosis boot: {error:#}");
                                    std::process::exit(127);
                                });
                                unreachable!();
                            }
                        }
                    }
                };

            drop(pid_writer);
            drop(result_writer);
            drop(network_reader);
            drop(boot_writer);
            let mut pid_bytes = [0_u8; std::mem::size_of::<i32>()];
            File::from(pid_reader)
                .read_exact(&mut pid_bytes)
                .context("generation worker failed to report init PID")?;
            let init_pid = Pid::from_raw(i32::from_ne_bytes(pid_bytes));
            let init_process = match ProcessHandle::open(init_pid) {
                Ok(process) => process,
                Err(error) => {
                    let _ = kill(intermediate, Signal::SIGKILL);
                    let _ = waitpid(intermediate, None);
                    return Err(error);
                }
            };
            if process_parent(init_pid.as_raw()).ok() != Some(intermediate.as_raw()) {
                let _ = kill(intermediate, Signal::SIGKILL);
                let _ = waitpid(intermediate, None);
                bail!("reported init PID is no longer a child of the generation worker");
            }

            let network = match Network::setup_host(&self.config, init_pid.as_raw(), &host_netns) {
                Ok(network) => network,
                Err(error) => {
                    let _ = init_process.send_signal(Signal::SIGKILL);
                    let _ = waitpid(intermediate, None);
                    return Err(error);
                }
            };
            if let Err(error) = cgroup.attach(init_pid.as_raw()) {
                let _ = init_process.send_signal(Signal::SIGKILL);
                let _ = waitpid(intermediate, None);
                network.cleanup();
                return Err(error);
            }
            if let Err(error) =
                nix::unistd::write(&mut network_writer, network.peer_name().as_bytes())
            {
                let _ = init_process.send_signal(Signal::SIGKILL);
                let _ = waitpid(intermediate, None);
                network.cleanup();
                return Err(error).context("failed to complete generation network handshake");
            }
            drop(network_writer);
            let mut boot_status = String::new();
            File::from(boot_reader)
                .read_to_string(&mut boot_status)
                .context("failed to read boot status")?;
            if !boot_status.is_empty() {
                let _ = init_process.send_signal(Signal::SIGKILL);
                let _ = waitpid(intermediate, None);
                network.cleanup();
                if first_boot && let Some(startup) = &mut startup {
                    let _ = nix::unistd::write(startup, boot_status.as_bytes());
                }
                bail!("{boot_status}");
            }

            let state = match (|| {
                Ok::<_, anyhow::Error>(ContainerState {
                    name: self.config.container.name.clone(),
                    init_pid: init_pid.as_raw(),
                    monitor_pid,
                    rootfs: rootfs.path().to_path_buf(),
                    uuid,
                    host_boot_id: host_boot_id.clone(),
                    init_start_time: process_start_time(init_pid.as_raw())?,
                    pid_namespace_inode: namespace_inode(init_pid.as_raw(), "pid")?,
                    started_at_unix: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    monitor_start_time,
                    init_system,
                    generation,
                })
            })() {
                Ok(state) => state,
                Err(error) => {
                    let _ = init_process.send_signal(Signal::SIGKILL);
                    let _ = waitpid(intermediate, None);
                    network.cleanup();
                    return Err(error);
                }
            };
            if let Err(error) = self.write_state(&state) {
                let _ = init_process.send_signal(Signal::SIGKILL);
                let _ = waitpid(intermediate, None);
                network.cleanup();
                return Err(error);
            }
            drop(generation_lock.take());
            if first_boot {
                if let Some(startup) = &mut startup {
                    nix::unistd::write(startup, &serde_json::to_vec(&state)?)
                        .context("failed to report container PID")?;
                }
                drop(startup.take());
                first_boot = false;
                if !foreground {
                    redirect_stdio_to_null();
                }
            }

            let status = if foreground {
                terminal::proxy(
                    &console.master,
                    intermediate,
                    Some((&init_process, init_system)),
                )
                .context("foreground console proxy failed")
            } else {
                waitpid(intermediate, None).context("failed waiting for generation worker")
            };
            let status = match status {
                Ok(status) => status,
                Err(error) => {
                    let _ = init_process.send_signal(Signal::SIGKILL);
                    let _ = waitpid(intermediate, None);
                    network.cleanup();
                    self.remove_state_for(&state).ok();
                    cgroup.remove().ok();
                    return Err(error);
                }
            };
            let mut generation_result = [0_u8; 1];
            let result_length = read_retry(&result_reader, &mut generation_result)
                .context("failed to read generation result")?;
            network.cleanup();
            if result_length != 1 || !matches!(generation_result[0], b'R' | b'E') {
                let _ = init_process.send_signal(Signal::SIGKILL);
                self.remove_state_for(&state).ok();
                cgroup.remove().ok();
                bail!("generation worker exited without a verified init result");
            }
            if generation_result[0] == b'R' {
                let Some(reboot_lock) = self.try_lock()? else {
                    self.remove_state_for(&state)?;
                    cgroup.remove()?;
                    return Ok(());
                };
                generation = generation
                    .checked_add(1)
                    .context("reboot generation overflow")?;
                generation_lock = Some(reboot_lock);
                continue;
            }

            self.remove_state_for(&state)?;
            cgroup.remove()?;
            return match status {
                WaitStatus::Exited(_, 0) => Ok(()),
                WaitStatus::Exited(_, code) => bail!("container exited with status {code}"),
                WaitStatus::Signaled(_, signal, _) => bail!("container terminated by {signal}"),
                status => bail!("unexpected generation status: {status:?}"),
            };
        }
    }

    #[allow(clippy::too_many_lines)]
    fn boot(
        &self,
        _boot_status: &std::os::fd::OwnedFd,
        network_status: std::os::fd::OwnedFd,
        configured_rootfs: &Path,
        console: Option<&OwnedFd>,
        uuid: Uuid,
    ) -> Result<()> {
        if let Some(console) = console {
            terminal::configure_child(console)?;
        }
        let mut status = String::new();
        File::from(network_status).read_to_string(&mut status)?;
        ensure!(!status.is_empty(), "host network setup did not complete");
        Network::setup_child(&self.config, &status)?;
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
        if let Some(console) = console {
            File::create("/dev/console").context("failed to create /dev/console")?;
            let source = format!("/proc/self/fd/{}", console.as_raw_fd());
            mount(
                Some(source.as_str()),
                "/dev/console",
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .context("failed to bind foreground PTY to /dev/console")?;
        }
        for device in ["null", "zero", "random", "urandom", "tty"] {
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
        environment::write_profile_environment(
            &self.config.container.environment,
            &self.config.container.android,
        )?;
        security::harden_mounts(&self.config.container.security)?;
        security::drop_dangerous_capabilities()?;
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
        let base = self
            .config
            .runtime
            .workdir
            .join("volatile")
            .join(&self.config.container.name);
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

    /// Gracefully stops the container, then force-kills it after the timeout.
    ///
    /// # Errors
    ///
    /// Returns an error when the container is not running or cannot be
    /// signalled.
    pub fn stop(&self) -> Result<()> {
        Self::ensure_root()?;
        let _lock = self.lock()?;
        let state = self.state_for_stop()?;
        if !validate_process_identity(&state) {
            return self.wait_for_monitor_cleanup(&state);
        }
        let process = require_handle(state.init_pid)?;
        ensure!(
            validate_process_identity(&state),
            "container init identity changed before pidfd validation"
        );
        let init_system = if state.init_system == init::InitSystem::Unknown {
            init::detect(
                &PathBuf::from(format!("/proc/{}/root", state.init_pid)),
                &self.config.container.init,
            )
        } else {
            state.init_system
        };
        init::request_shutdown(&process, init_system)?;
        if process.wait_for_exit(Duration::from_secs(
            self.config.runtime.stop_timeout_seconds,
        ))? {
            return self.wait_for_monitor_cleanup(&state);
        }
        process.send_signal(Signal::SIGKILL)?;
        let _ = process.wait_for_exit(Duration::from_secs(5))?;
        self.wait_for_monitor_cleanup(&state)
    }

    /// Stops and starts the configured container.
    ///
    /// # Errors
    ///
    /// Returns any error produced by [`Self::stop`] or [`Self::start`].
    pub fn restart(&self, foreground: bool) -> Result<ContainerState> {
        self.stop()?;
        self.start(foreground)
    }
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
