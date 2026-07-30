use std::{
    fs::File,
    io::Read,
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use kurumi_containerd_config::NetworkMode;
use kurumi_containerd_helper::{
    ForkResult, MountFlags, NamespaceFlags, Signal, WaitStatus, current_pid, fork, kill, mount,
    pipe, setsid, unshare, waitpid, write,
};
use uuid::Uuid;

#[cfg(target_os = "android")]
use crate::host::android;
use crate::{
    ContainerState, Runtime,
    container::init,
    host::{
        cgroup::Cgroup,
        network::Network,
        process::{ProcessHandle, parent_pid as process_parent, require_handle},
        terminal,
    },
    runtime::state::{
        host_boot_id, namespace_inode, process_start_time, validate_process_identity,
    },
};

use super::supervisor::{
    configure_monitor_signals, ignore_foreground_parent_signals, is_reboot_status, read_retry,
    redirect_stdio_to_null, reset_init_signals, wait_status_code, waitpid_retry,
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

        let (reader, writer) = pipe().context("failed to create startup pipe")?;
        // SAFETY: the CLI is single-threaded at this point and the child immediately enters the monitor path.
        match unsafe { fork() }.context("failed to fork monitor")? {
            ForkResult::Parent { child } => {
                drop(writer);
                let mut file = File::from(reader);
                let mut payload = String::new();
                file.read_to_string(&mut payload)
                    .context("failed to read monitor startup result")?;
                let state: ContainerState = match serde_json::from_str(&payload) {
                    Ok(state) => state,
                    Err(parse_error) if payload.trim_start().starts_with('{') => {
                        return Err(parse_error)
                            .with_context(|| format!("container failed to start: {payload}"));
                    }
                    Err(_) => bail!("container failed to start: {payload}"),
                };
                drop(lock);
                if foreground_override || self.config.container.foreground {
                    ignore_foreground_parent_signals()?;
                    let status = waitpid(child, false).context("failed waiting for monitor")?;
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
                    eprintln!("KurumiContainerd monitor: {error:#}");
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
        let _selinux = android::SelinuxGuard::apply(&self.config.container.android, &self.workdir)?;
        let host_netns = File::open("/proc/self/ns/net")?;
        unshare(NamespaceFlags::UTS | NamespaceFlags::IPC | NamespaceFlags::MOUNT)
            .context("failed to create UTS/IPC/mount namespaces")?;
        mount(
            None,
            Path::new("/"),
            None,
            MountFlags::REC | MountFlags::PRIVATE,
            None,
        )
        .context("failed to make monitor mount tree private")?;
        let rootfs = self.rootfs.prepare()?;
        self.init.prepare(rootfs.as_ref())?;
        let init_system = self.init.detect(rootfs.as_ref());
        let mut cgroup = Cgroup::create(
            &self.workdir,
            &self.config.container.name,
            &self.config.container.resources,
            init_system == init::InitSystem::Systemd,
            true,
        )?;
        let uuid = self.config.container.uuid.unwrap_or_else(Uuid::new_v4);
        let host_boot_id = host_boot_id()?;
        let monitor_pid = current_pid();
        let monitor_start_time = process_start_time(monitor_pid)?;
        let mut generation = 0_u64;
        let mut first_boot = true;
        let mut generation_lock = None;

        loop {
            let (boot_reader, boot_writer) = pipe().context("failed to create boot pipe")?;
            let (network_reader, mut network_writer) =
                pipe().context("failed to create network pipe")?;
            let (pid_reader, mut pid_writer) = pipe().context("failed to create PID pipe")?;
            let (result_reader, mut result_writer) =
                pipe().context("failed to create result pipe")?;

            // SAFETY: the single-threaded monitor forks a generation worker which only unshares and forks init.
            let intermediate = match unsafe { fork() }
                .context("failed to fork generation worker")?
            {
                ForkResult::Parent { child } => child,
                ForkResult::Child => {
                    drop(startup.take());
                    drop(generation_lock.take());
                    drop(pid_reader);
                    drop(result_reader);
                    let mut flags = NamespaceFlags::PID;
                    if self.config.container.network != NetworkMode::Host {
                        flags |= NamespaceFlags::NETWORK;
                    }
                    unshare(flags).unwrap_or_else(|error| {
                            eprintln!(
                                "KurumiContainerd generation: failed to create PID/network namespace: {error}"
                            );
                            std::process::exit(125);
                        });
                    // SAFETY: the generation worker is single-threaded and the child immediately boots.
                    match unsafe { fork() }.unwrap_or_else(|error| {
                        eprintln!("KurumiContainerd generation: failed to fork init: {error}");
                        std::process::exit(125);
                    }) {
                        ForkResult::Parent { child } => {
                            drop(network_reader);
                            drop(network_writer);
                            drop(boot_reader);
                            drop(boot_writer);
                            write(&mut pid_writer, &child.to_ne_bytes())
                                .unwrap_or_else(|_| std::process::exit(125));
                            drop(pid_writer);
                            if !foreground {
                                redirect_stdio_to_null();
                            }
                            let status =
                                waitpid_retry(child).unwrap_or_else(|_| std::process::exit(125));
                            let result = if is_reboot_status(status) { b'R' } else { b'E' };
                            write(&mut result_writer, &[result])
                                .unwrap_or_else(|_| std::process::exit(125));
                            std::process::exit(wait_status_code(status));
                        }
                        ForkResult::Child => {
                            drop(pid_writer);
                            drop(result_writer);
                            drop(network_writer);
                            drop(boot_reader);
                            reset_init_signals();
                            self.boot(
                                &boot_writer,
                                network_reader,
                                rootfs.as_ref(),
                                Some(&console),
                                init_system,
                                cgroup.unified(),
                                uuid,
                            )
                            .unwrap_or_else(|error| {
                                let message = format!("{error:#}");
                                let _ = write(&boot_writer, message.as_bytes());
                                eprintln!("KurumiContainerd boot: {error:#}");
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
            let init_pid = i32::from_ne_bytes(pid_bytes);
            let init_process = match ProcessHandle::open(init_pid) {
                Ok(process) => process,
                Err(error) => {
                    let _ = kill(intermediate, Signal::Kill);
                    let _ = waitpid(intermediate, false);
                    return Err(error);
                }
            };
            if process_parent(init_pid).ok() != Some(intermediate) {
                let _ = kill(intermediate, Signal::Kill);
                let _ = waitpid(intermediate, false);
                bail!("reported init PID is no longer a child of the generation worker");
            }

            let network = match Network::setup_host(&self.config, init_pid, &host_netns) {
                Ok(network) => network,
                Err(error) => {
                    let _ = init_process.send_signal(Signal::Kill);
                    let _ = waitpid(intermediate, false);
                    return Err(error);
                }
            };
            if let Err(error) = cgroup.attach(init_pid) {
                let _ = init_process.send_signal(Signal::Kill);
                let _ = waitpid(intermediate, false);
                network.cleanup();
                return Err(error);
            }
            if let Err(error) = write(&mut network_writer, network.peer_name().as_bytes()) {
                let _ = init_process.send_signal(Signal::Kill);
                let _ = waitpid(intermediate, false);
                network.cleanup();
                return Err(error).context("failed to complete generation network handshake");
            }
            drop(network_writer);
            let mut boot_status = String::new();
            File::from(boot_reader)
                .read_to_string(&mut boot_status)
                .context("failed to read boot status")?;
            if !boot_status.is_empty() {
                let _ = init_process.send_signal(Signal::Kill);
                let _ = waitpid(intermediate, false);
                network.cleanup();
                if first_boot && let Some(startup) = &mut startup {
                    let _ = write(startup, boot_status.as_bytes());
                }
                bail!("{boot_status}");
            }

            let state = match (|| {
                Ok::<_, anyhow::Error>(ContainerState {
                    name: self.config.container.name.clone(),
                    init_pid,
                    monitor_pid,
                    rootfs: rootfs.as_ref().to_path_buf(),
                    uuid,
                    host_boot_id: host_boot_id.clone(),
                    init_start_time: process_start_time(init_pid)?,
                    pid_namespace_inode: namespace_inode(init_pid, "pid")?,
                    started_at_unix: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    monitor_start_time,
                    init_system,
                    generation,
                })
            })() {
                Ok(state) => state,
                Err(error) => {
                    let _ = init_process.send_signal(Signal::Kill);
                    let _ = waitpid(intermediate, false);
                    network.cleanup();
                    return Err(error);
                }
            };
            if let Err(error) = self.write_state(&state) {
                let _ = init_process.send_signal(Signal::Kill);
                let _ = waitpid(intermediate, false);
                network.cleanup();
                return Err(error);
            }
            drop(generation_lock.take());
            if first_boot {
                if let Some(startup) = &mut startup {
                    write(startup, &serde_json::to_vec(&state)?)
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
                waitpid(intermediate, false).context("failed waiting for generation worker")
            };
            let status = match status {
                Ok(status) => status,
                Err(error) => {
                    let _ = init_process.send_signal(Signal::Kill);
                    let _ = waitpid(intermediate, false);
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
                let _ = init_process.send_signal(Signal::Kill);
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
            self.init
                .detect(&PathBuf::from(format!("/proc/{}/root", state.init_pid)))
        } else {
            state.init_system
        };
        init::request_shutdown(&process, init_system)?;
        if process.wait_for_exit(Duration::from_secs(
            self.config.runtime.stop_timeout_seconds,
        ))? {
            return self.wait_for_monitor_cleanup(&state);
        }
        process.send_signal(Signal::Kill)?;
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
