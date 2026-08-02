use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use procfs::process::all_processes;
use serde::Serialize;
use uuid::Uuid;

use super::{ContainerState, process_namespace_inode};
use crate::{Runtime, container::init::InitSystem};

#[derive(Debug, Clone, Serialize)]
pub struct ContainerInfo {
    pub name: String,
    pub active: bool,
    pub init_pid: Option<i32>,
    pub monitor_pid: Option<i32>,
    pub rootfs: PathBuf,
    pub uuid: Option<Uuid>,
    pub init_system: Option<InitSystem>,
    pub generation: Option<u64>,
    pub uptime_seconds: Option<u64>,
    pub memory_kb: Option<u64>,
    pub processes: Option<usize>,
}

impl std::fmt::Display for ContainerInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(formatter, "{}", self.name)?;
        if self.active {
            writeln!(
                formatter,
                "{:>12}: active (running) for {}",
                "Active",
                format_duration(self.uptime_seconds.unwrap_or_default())
            )?;
            writeln!(
                formatter,
                "{:>12}: {} ({})",
                "Main PID",
                self.init_pid.unwrap_or_default(),
                self.init_system.unwrap_or_default()
            )?;
            writeln!(
                formatter,
                "{:>12}: {}",
                "Monitor PID",
                self.monitor_pid.unwrap_or_default()
            )?;
            writeln!(
                formatter,
                "{:>12}: {}",
                "Tasks",
                self.processes.unwrap_or_default()
            )?;
            writeln!(
                formatter,
                "{:>12}: {}",
                "Memory",
                format_memory(self.memory_kb.unwrap_or_default())
            )?;
            writeln!(
                formatter,
                "{:>12}: {}",
                "Generation",
                self.generation.unwrap_or_default()
            )?;
        } else {
            writeln!(formatter, "{:>12}: inactive (dead)", "Active")?;
        }
        writeln!(formatter, "{:>12}: {}", "Rootfs", self.rootfs.display())?;
        write!(
            formatter,
            "{:>12}: {}",
            "UUID",
            self.uuid
                .map_or_else(|| "unassigned".to_owned(), |uuid| uuid.to_string())
        )
    }
}

impl Runtime {
    /// Returns the current container state and resource usage.
    ///
    /// # Errors
    ///
    /// Returns an error when state or procfs cannot be read.
    pub fn info(&self) -> Result<ContainerInfo> {
        let Some(state) = self.state()? else {
            let rootfs = self
                .config
                .container
                .rootfs
                .as_ref()
                .or(self.config.container.rootfs_image.as_ref())
                .context("container has no configured rootfs")?
                .clone();
            return Ok(ContainerInfo {
                name: self.config.container.name.clone(),
                active: false,
                init_pid: None,
                monitor_pid: None,
                rootfs,
                uuid: self.config.container.uuid,
                init_system: None,
                generation: None,
                uptime_seconds: None,
                memory_kb: None,
                processes: None,
            });
        };
        let (memory_kb, processes) = collect_usage(&state)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(ContainerInfo {
            name: state.name,
            active: true,
            init_pid: Some(state.init_pid),
            monitor_pid: Some(state.monitor_pid),
            rootfs: state.rootfs,
            uuid: Some(state.uuid),
            init_system: Some(state.init_system),
            generation: Some(state.generation),
            uptime_seconds: Some(now.saturating_sub(state.started_at_unix)),
            memory_kb: Some(memory_kb),
            processes: Some(processes),
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

#[cfg(test)]
mod tests {
    use super::*;

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
            active: true,
            init_pid: Some(123),
            monitor_pid: Some(122),
            rootfs: PathBuf::from("/rootfs"),
            uuid: Some(Uuid::nil()),
            init_system: Some(crate::InitSystem::Systemd),
            generation: Some(1),
            uptime_seconds: Some(3_723),
            memory_kb: Some(1_536),
            processes: Some(4),
        };
        assert_eq!(
            info.to_string(),
            "test\n      Active: active (running) for 1h 02m 03s\n    Main PID: 123 (systemd)\n Monitor PID: 122\n       Tasks: 4\n      Memory: 1.5 MiB\n  Generation: 1\n      Rootfs: /rootfs\n        UUID: 00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn displays_inactive_container_info() {
        let info = ContainerInfo {
            name: "test".to_owned(),
            active: false,
            init_pid: None,
            monitor_pid: None,
            rootfs: PathBuf::from("/rootfs"),
            uuid: Some(Uuid::nil()),
            init_system: None,
            generation: None,
            uptime_seconds: None,
            memory_kb: None,
            processes: None,
        };
        assert_eq!(
            info.to_string(),
            "test\n      Active: inactive (dead)\n      Rootfs: /rootfs\n        UUID: 00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn reports_inactive_container_without_state() {
        let source = "[runtime]\n\n[container]\nname = \"test\"\nrootfs = \"/rootfs\"\n";
        let config: kurumi_containerd_config::Config = toml::from_str(source).unwrap();
        let info = Runtime::new(config).unwrap().info().unwrap();
        assert!(!info.active);
        assert_eq!(info.name, "test");
        assert_eq!(info.rootfs, PathBuf::from("/rootfs"));
        assert_eq!(info.init_pid, None);
    }
}
