use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
#[cfg(test)]
use gnosis_helper::parent_pid as current_parent_pid;
use gnosis_helper::{OPEN_CLOEXEC, OPEN_NOFOLLOW, effective_uid};
use procfs::process::{Process, all_processes};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Runtime,
    container::init::InitSystem,
    host::process::{parent_pid, require_handle},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerState {
    pub name: String,
    pub init_pid: i32,
    pub monitor_pid: i32,
    pub rootfs: PathBuf,
    pub uuid: Uuid,
    pub host_boot_id: String,
    pub init_start_time: u64,
    pub pid_namespace_inode: u64,
    pub started_at_unix: u64,
    pub monitor_start_time: u64,
    #[serde(default)]
    pub init_system: InitSystem,
    #[serde(default)]
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerInfo {
    pub name: String,
    pub init_pid: i32,
    pub monitor_pid: i32,
    pub rootfs: PathBuf,
    pub uuid: Uuid,
    pub init_system: InitSystem,
    pub generation: u64,
    pub uptime_seconds: u64,
    pub memory_kb: u64,
    pub processes: usize,
}

impl std::fmt::Display for ContainerInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(formatter, "{}", self.name)?;
        writeln!(
            formatter,
            "{:>12}: active (running) for {}",
            "Active",
            format_duration(self.uptime_seconds)
        )?;
        writeln!(
            formatter,
            "{:>12}: {} ({})",
            "Main PID", self.init_pid, self.init_system
        )?;
        writeln!(formatter, "{:>12}: {}", "Monitor PID", self.monitor_pid)?;
        writeln!(formatter, "{:>12}: {}", "Tasks", self.processes)?;
        writeln!(
            formatter,
            "{:>12}: {}",
            "Memory",
            format_memory(self.memory_kb)
        )?;
        writeln!(formatter, "{:>12}: {}", "Generation", self.generation)?;
        writeln!(formatter, "{:>12}: {}", "Rootfs", self.rootfs.display())?;
        write!(formatter, "{:>12}: {}", "UUID", self.uuid)
    }
}

impl Runtime {
    /// Returns the current container state and resource usage.
    ///
    /// # Errors
    ///
    /// Returns an error when state or procfs cannot be read, or the container is stopped.
    pub fn info(&self) -> Result<ContainerInfo> {
        let state = self.require_state()?;
        let (memory_kb, processes) = collect_usage(&state)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(ContainerInfo {
            name: state.name,
            init_pid: state.init_pid,
            monitor_pid: state.monitor_pid,
            rootfs: state.rootfs,
            uuid: state.uuid,
            init_system: state.init_system,
            generation: state.generation,
            uptime_seconds: now.saturating_sub(state.started_at_unix),
            memory_kb,
            processes,
        })
    }

    /// Returns the validated container init PID.
    ///
    /// # Errors
    ///
    /// Returns an error when the container is not running.
    pub fn pid(&self) -> Result<i32> {
        Ok(self.require_state()?.init_pid)
    }

    /// Lists live containers tracked by the configured work directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the state directory cannot be read.
    pub fn list(&self) -> Result<Vec<ContainerState>> {
        self.ensure_layout()?;
        let mut states = Vec::new();
        for entry in fs::read_dir(self.state_dir())? {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            if let Ok(state) = read_state(&entry.path())
                && (validate_process_identity(&state) || validate_monitor_identity(&state))
            {
                states.push(state);
            }
        }
        states.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(states)
    }

    /// Scans procfs for live containers backed by trusted recovery metadata and
    /// reconstructs missing state files.
    ///
    /// # Errors
    ///
    /// Returns an error when the recovery directory or state cannot be read or
    /// written safely.
    pub fn scan(&self) -> Result<Vec<ContainerState>> {
        Self::ensure_root()?;
        self.ensure_layout()?;
        let mut candidates = BTreeMap::new();
        for entry in fs::read_dir(self.recovery_dir())? {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Ok(mut state) = read_state(&entry.path()) else {
                continue;
            };
            if !valid_state_name(&state.name) {
                continue;
            }
            if host_boot_id().ok().as_deref() != Some(&state.host_boot_id)
                || !validate_monitor_identity(&state)
            {
                remove_if_exists(&entry.path())?;
                continue;
            }
            let Some(init_pid) = find_generation_init(&state)? else {
                continue;
            };
            let handle = require_handle(init_pid)?;
            state.init_pid = init_pid;
            state.init_start_time = process_start_time(init_pid)?;
            state.pid_namespace_inode = namespace_inode(init_pid, "pid")?;
            if handle.pid().as_raw() != init_pid || !validate_process_identity(&state) {
                continue;
            }
            if let Some(existing) = candidates.insert(state.name.clone(), state.clone())
                && existing.uuid != state.uuid
            {
                bail!(
                    "multiple live recovery records claim container '{}'",
                    state.name
                );
            }
        }
        for state in candidates.values() {
            self.write_state_paths(state)?;
        }
        Ok(candidates.into_values().collect())
    }

    pub(crate) fn ensure_root() -> Result<()> {
        ensure!(
            effective_uid() == 0,
            "this operation requires root privileges"
        );
        Ok(())
    }

    pub(crate) fn ensure_layout(&self) -> Result<()> {
        ensure_trusted_directory(&self.workdir)?;
        let state_dir = self.state_dir();
        fs::create_dir_all(&state_dir)
            .with_context(|| format!("failed to create workdir {}", self.workdir.display()))?;
        ensure_trusted_directory(&state_dir)?;
        let recovery_dir = self.recovery_dir();
        fs::create_dir_all(&recovery_dir)?;
        ensure_trusted_directory(&recovery_dir)
    }

    fn state_dir(&self) -> PathBuf {
        self.state_dir.clone()
    }
    fn state_path(&self) -> PathBuf {
        self.state_path_for(&self.config.container.name)
    }

    fn state_path_for(&self, name: &str) -> PathBuf {
        self.state_dir().join(format!("{name}.json"))
    }

    fn recovery_dir(&self) -> PathBuf {
        self.recovery_dir.clone()
    }

    fn recovery_path(&self, uuid: Uuid) -> PathBuf {
        self.recovery_dir().join(format!("{uuid}.json"))
    }

    pub(crate) fn state(&self) -> Result<Option<ContainerState>> {
        let path = self.state_path();
        if !path.exists() {
            return Ok(None);
        }
        let state = read_state(&path)?;
        if validate_process_identity(&state) || validate_monitor_identity(&state) {
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn require_state(&self) -> Result<ContainerState> {
        self.state()?
            .with_context(|| format!("container '{}' is not running", self.config.container.name))
    }

    pub(crate) fn state_for_stop(&self) -> Result<ContainerState> {
        let path = self.state_path();
        let state = read_state(&path).with_context(|| {
            format!("container '{}' is not running", self.config.container.name)
        })?;
        ensure!(
            validate_process_identity(&state) || validate_monitor_identity(&state),
            "container '{}' is not running",
            self.config.container.name
        );
        Ok(state)
    }

    pub(crate) fn write_state(&self, state: &ContainerState) -> Result<()> {
        self.write_state_paths(state)
    }

    fn write_state_paths(&self, state: &ContainerState) -> Result<()> {
        write_state_atomic(&self.recovery_path(state.uuid), state)?;
        write_state_atomic(&self.state_path_for(&state.name), state)
    }

    fn remove_recovery_state(&self, uuid: Uuid) -> Result<()> {
        remove_if_exists(&self.recovery_path(uuid))
    }

    pub(crate) fn remove_state_for(&self, state: &ContainerState) -> Result<()> {
        remove_if_exists(&self.state_path())?;
        self.remove_recovery_state(state.uuid)
    }

    pub(crate) fn remove_state(&self) -> Result<()> {
        remove_if_exists(&self.state_path())
    }

    pub(crate) fn lock(&self) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(OPEN_NOFOLLOW | OPEN_CLOEXEC)
            .open(&self.lock_path)?;
        file.lock_exclusive()
            .context("failed to lock container lifecycle")?;
        Ok(file)
    }

    pub(crate) fn try_lock(&self) -> Result<Option<File>> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(OPEN_NOFOLLOW | OPEN_CLOEXEC)
            .open(&self.lock_path)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Some(file)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error).context("failed to try-lock container lifecycle"),
        }
    }

    pub(crate) fn wait_for_monitor_cleanup(&self, state: &ContainerState) -> Result<()> {
        let monitor = match require_handle(state.monitor_pid) {
            Ok(monitor) => monitor,
            Err(_) if !validate_monitor_identity(state) => {
                self.remove_state_for(state)?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        ensure!(
            validate_monitor_identity(state),
            "container monitor identity changed before pidfd validation"
        );
        if monitor.wait_for_exit(Duration::from_secs(5))? {
            self.remove_state_for(state)?;
            return Ok(());
        }
        bail!("container init exited but monitor did not finish cleanup")
    }
}

fn collect_usage(state: &ContainerState) -> Result<(u64, usize)> {
    let mut memory_kb = 0;
    let mut processes = 0;
    for process in all_processes()? {
        let Ok(process) = process else {
            continue;
        };
        if process_namespace_inode(&process, "pid").ok() != Some(state.pid_namespace_inode) {
            continue;
        }
        processes += 1;
        if let Ok(status) = process.status() {
            memory_kb += status.vmrss.unwrap_or(0);
        }
    }
    Ok((memory_kb, processes))
}

fn format_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = seconds % 86_400 / 3_600;
    let minutes = seconds % 3_600 / 60;
    let seconds = seconds % 60;
    if days > 0 {
        format!("{days}d {hours:02}h {minutes:02}m {seconds:02}s")
    } else if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

fn format_memory(kibibytes: u64) -> String {
    if kibibytes >= 1024 * 1024 {
        format_unit(kibibytes, 1024 * 1024, "GiB")
    } else if kibibytes >= 1024 {
        format_unit(kibibytes, 1024, "MiB")
    } else {
        format!("{kibibytes} KiB")
    }
}

fn format_unit(value: u64, unit: u64, suffix: &str) -> String {
    let whole = value / unit;
    let decimal = value % unit * 10 / unit;
    format!("{whole}.{decimal} {suffix}")
}

pub(crate) fn validate_process_identity(state: &ContainerState) -> bool {
    host_boot_id().is_ok_and(|value| value == state.host_boot_id)
        && process_start_time(state.init_pid).is_ok_and(|value| value == state.init_start_time)
        && namespace_inode(state.init_pid, "pid")
            .is_ok_and(|value| value == state.pid_namespace_inode)
        && fs::read_to_string(format!("/proc/{}/root/run/gnosis/name", state.init_pid))
            .is_ok_and(|value| value == state.name)
}

fn validate_monitor_identity(state: &ContainerState) -> bool {
    host_boot_id().is_ok_and(|value| value == state.host_boot_id)
        && process_start_time(state.monitor_pid)
            .is_ok_and(|value| value == state.monitor_start_time)
}

pub(crate) fn host_boot_id() -> Result<String> {
    Ok(procfs::sys::kernel::random::boot_id()?)
}

pub(crate) fn process_start_time(pid: i32) -> Result<u64> {
    Ok(Process::new(pid)?.stat()?.starttime)
}

pub(crate) fn namespace_inode(pid: i32, namespace: &str) -> Result<u64> {
    process_namespace_inode(&Process::new(pid)?, namespace)
}

fn process_namespace_inode(process: &Process, namespace: &str) -> Result<u64> {
    process
        .namespaces()?
        .0
        .get(std::ffi::OsStr::new(namespace))
        .map(|value| value.identifier)
        .with_context(|| format!("process {} has no {namespace} namespace", process.pid))
}

fn read_state(path: &Path) -> Result<ContainerState> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_state_atomic(path: &Path, state: &ContainerState) -> Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(OPEN_NOFOLLOW | OPEN_CLOEXEC)
        .open(&temporary)?;
    let result = (|| {
        serde_json::to_writer_pretty(&file, state)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(path.parent().context("state path has no parent")?)?.sync_all()?;
        Ok::<(), anyhow::Error>(())
    })();
    if result.is_err() {
        fs::remove_file(temporary).ok();
    }
    result
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn find_generation_init(expected: &ContainerState) -> Result<Option<i32>> {
    for process in all_processes()? {
        let Ok(process) = process else {
            continue;
        };
        let pid = process.pid;
        if namespace_pid(&process).ok().flatten() != Some(1) {
            continue;
        }
        let root = PathBuf::from(format!("/proc/{pid}/root/run/gnosis"));
        if fs::read_to_string(root.join("name")).ok().as_deref() != Some(&expected.name)
            || fs::read_to_string(root.join("uuid"))
                .ok()
                .is_none_or(|value| value.trim() != expected.uuid.to_string())
        {
            continue;
        }
        let Ok(intermediate) = parent_pid(pid) else {
            continue;
        };
        if intermediate <= 0 || parent_pid(intermediate).ok() != Some(expected.monitor_pid) {
            continue;
        }
        return Ok(Some(pid));
    }
    Ok(None)
}

fn valid_state_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn namespace_pid(process: &Process) -> Result<Option<i32>> {
    Ok(process
        .status()?
        .nspid
        .and_then(|values| values.last().copied()))
}

fn ensure_trusted_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !path.exists() {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir(),
        "runtime directory is not a directory: {}",
        path.display()
    );
    ensure!(
        !metadata.file_type().is_symlink(),
        "runtime directory must not be a symlink: {}",
        path.display()
    );
    ensure!(
        metadata.uid() == 0,
        "runtime directory must be owned by root: {}",
        path.display()
    );
    ensure!(
        metadata.mode() & 0o022 == 0,
        "runtime directory must not be group/world writable: {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_state_defaults_to_unknown_init() {
        let state: ContainerState = serde_json::from_value(serde_json::json!({
            "name": "test",
            "init_pid": 1,
            "monitor_pid": 2,
            "rootfs": "/rootfs",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "host_boot_id": "boot",
            "init_start_time": 1,
            "pid_namespace_inode": 2,
            "started_at_unix": 3,
            "monitor_start_time": 4
        }))
        .unwrap();
        assert_eq!(state.init_system, crate::InitSystem::Unknown);
        assert_eq!(state.generation, 0);
    }

    #[test]
    fn parses_namespace_and_parent_pids() {
        let pid = i32::try_from(std::process::id()).unwrap();
        assert!(
            namespace_pid(&Process::new(pid).unwrap())
                .unwrap()
                .is_some()
        );
        assert_eq!(parent_pid(pid).unwrap(), current_parent_pid());
    }

    #[test]
    fn writes_state_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let state = ContainerState {
            name: "test".to_owned(),
            init_pid: 1,
            monitor_pid: 2,
            rootfs: PathBuf::from("/rootfs"),
            uuid: Uuid::nil(),
            host_boot_id: "boot".to_owned(),
            init_start_time: 1,
            pid_namespace_inode: 2,
            started_at_unix: 3,
            monitor_start_time: 4,
            init_system: crate::InitSystem::Unknown,
            generation: 0,
        };
        write_state_atomic(&path, &state).unwrap();
        assert_eq!(read_state(&path).unwrap().uuid, Uuid::nil());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn formats_uptime() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(62), "1m 02s");
        assert_eq!(format_duration(3_723), "1h 02m 03s");
        assert_eq!(format_duration(93_784), "1d 02h 03m 04s");
    }

    #[test]
    fn formats_memory() {
        assert_eq!(format_memory(512), "512 KiB");
        assert_eq!(format_memory(1_536), "1.5 MiB");
        assert_eq!(format_memory(1_572_864), "1.5 GiB");
    }

    #[test]
    fn displays_container_info() {
        let info = ContainerInfo {
            name: "test".to_owned(),
            init_pid: 123,
            monitor_pid: 122,
            rootfs: PathBuf::from("/rootfs"),
            uuid: Uuid::nil(),
            init_system: crate::InitSystem::Systemd,
            generation: 1,
            uptime_seconds: 3_723,
            memory_kb: 1_536,
            processes: 4,
        };
        assert_eq!(
            info.to_string(),
            "test\n      Active: active (running) for 1h 02m 03s\n    Main PID: 123 (systemd)\n Monitor PID: 122\n       Tasks: 4\n      Memory: 1.5 MiB\n  Generation: 1\n      Rootfs: /rootfs\n        UUID: 00000000-0000-0000-0000-000000000000"
        );
    }
}
