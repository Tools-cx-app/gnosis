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
pub struct ContainerUsage {
    pub uptime_seconds: u64,
    pub memory_kb: u64,
    pub processes: usize,
}

impl Runtime {
    /// Returns the current container state.
    ///
    /// # Errors
    ///
    /// Returns an error when state cannot be read or the container is stopped.
    pub fn info(&self) -> Result<ContainerState> {
        self.require_state()
    }

    /// Returns the validated container init PID.
    ///
    /// # Errors
    ///
    /// Returns an error when the container is not running.
    pub fn pid(&self) -> Result<i32> {
        Ok(self.require_state()?.init_pid)
    }

    /// Collects current process count, RSS, and uptime from procfs.
    ///
    /// # Errors
    ///
    /// Returns an error when the container state or procfs cannot be read.
    pub fn usage(&self) -> Result<ContainerUsage> {
        let state = self.require_state()?;
        let mut memory_kb = 0;
        let mut processes = 0;
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<i32>().ok())
            else {
                continue;
            };
            if namespace_inode(pid, "pid").ok() != Some(state.pid_namespace_inode) {
                continue;
            }
            processes += 1;
            if let Ok(status) = fs::read_to_string(entry.path().join("status")) {
                memory_kb += status
                    .lines()
                    .find_map(|line| line.strip_prefix("VmRSS:"))
                    .and_then(|value| value.split_whitespace().next())
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0);
            }
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(ContainerUsage {
            uptime_seconds: now.saturating_sub(state.started_at_unix),
            memory_kb,
            processes,
        })
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
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}

pub(crate) fn process_start_time(pid: i32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(") ")
        .context("invalid proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("proc stat is missing starttime")?
        .parse()
        .context("invalid process starttime")
}

pub(crate) fn namespace_inode(pid: i32, namespace: &str) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(fs::metadata(format!("/proc/{pid}/ns/{namespace}"))?.ino())
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
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        if namespace_pid(pid).ok().flatten() != Some(1) {
            continue;
        }
        let root = entry.path().join("root/run/gnosis");
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

fn namespace_pid(pid: i32) -> Result<Option<i32>> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    Ok(status.lines().find_map(|line| {
        line.strip_prefix("NSpid:")?
            .split_whitespace()
            .next_back()?
            .parse()
            .ok()
    }))
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
        assert!(namespace_pid(pid).unwrap().is_some());
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
}
