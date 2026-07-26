use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::Result;
use gnosis_config::Config;
use nix::sys::signal::Signal;
use serde::{Deserialize, Serialize};

use crate::host::process::ProcessHandle;

#[derive(Debug, Clone)]
pub(crate) struct Init {
    path: PathBuf,
}

impl Init {
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            path: config.container.init.clone(),
        }
    }

    pub(crate) fn detect(&self, rootfs: &Path) -> InitSystem {
        detect(rootfs, &self.path)
    }
}

pub(crate) fn prepare_runtime(system: InitSystem) -> Result<()> {
    if system != InitSystem::Systemd {
        return Ok(());
    }

    fs::create_dir_all("/run/systemd/journal")?;
    fs::create_dir_all("/run/systemd/system")?;
    fs::write("/run/systemd/container", "gnosis")?;
    std::os::unix::fs::symlink(
        "/dev/null",
        "/run/systemd/system/systemd-journald-audit.socket",
    )?;
    std::os::unix::fs::symlink(
        "/dev/null",
        "/run/systemd/system/systemd-networkd-wait-online.service",
    )?;
    fs::create_dir_all("/run/systemd/journald.conf.d")?;
    fs::write(
        "/run/systemd/journald.conf.d/gnosis.conf",
        "[Journal]\nReadKMsg=no\nAudit=no\nStorage=volatile\n",
    )?;
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InitSystem {
    #[default]
    Unknown,
    Systemd,
    Procd,
    Openrc,
    Runit,
    S6,
    Busybox,
    Sysvinit,
    Custom,
}

impl std::fmt::Display for InitSystem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Unknown => "unknown",
            Self::Systemd => "systemd",
            Self::Procd => "procd",
            Self::Openrc => "openrc",
            Self::Runit => "runit",
            Self::S6 => "s6",
            Self::Busybox => "busybox",
            Self::Sysvinit => "sysvinit",
            Self::Custom => "custom",
        };
        formatter.write_str(name)
    }
}

pub(crate) fn detect(rootfs: &Path, configured_init: &Path) -> InitSystem {
    if configured_init != Path::new("/sbin/init") {
        return InitSystem::Custom;
    }
    if systemd_present(rootfs) {
        return InitSystem::Systemd;
    }
    for (system, paths) in [
        (InitSystem::Procd, &["sbin/procd", "usr/sbin/procd"][..]),
        (
            InitSystem::Openrc,
            &["sbin/openrc-init", "usr/bin/openrc-init", "sbin/openrc"][..],
        ),
        (InitSystem::Runit, &["sbin/runit", "usr/bin/runit"][..]),
        (InitSystem::S6, &["bin/s6-svscan", "usr/bin/s6-svscan"][..]),
    ] {
        if paths.iter().any(|path| rootfs.join(path).is_file()) {
            return system;
        }
    }

    let init = rootfs.join("sbin/init");
    if let Ok(target) = fs::read_link(&init) {
        let target = target.to_string_lossy();
        if target.contains("busybox") {
            return InitSystem::Busybox;
        }
        if target.contains("sysvinit") || target.contains("init.sysv") {
            return InitSystem::Sysvinit;
        }
        return InitSystem::Unknown;
    }
    if init.is_file() {
        let content = read_prefix(&init, 4096).unwrap_or_default();
        if content.windows(7).any(|value| value == b"systemd") {
            return InitSystem::Systemd;
        }
        if content.windows(7).any(|value| value == b"busybox") {
            return InitSystem::Busybox;
        }
        if content.windows(10).any(|value| value == b"/nix/store") {
            return InitSystem::Unknown;
        }
        return InitSystem::Sysvinit;
    }
    InitSystem::Unknown
}

pub(crate) fn request_shutdown(process: &ProcessHandle, system: InitSystem) -> Result<()> {
    match system {
        InitSystem::Systemd => process.send_signal_raw(libc::SIGRTMIN() + 3),
        InitSystem::Procd | InitSystem::S6 | InitSystem::Busybox => {
            process.send_signal(Signal::SIGUSR2)
        }
        InitSystem::Runit => process.send_signal(Signal::SIGCONT),
        InitSystem::Openrc => process.send_signal(Signal::SIGPWR),
        InitSystem::Sysvinit => request_sysv_shutdown(process),
        InitSystem::Custom => process.send_signal(Signal::SIGKILL),
        InitSystem::Unknown => process.send_signal(Signal::SIGTERM),
    }
}

fn systemd_present(rootfs: &Path) -> bool {
    [
        "lib/systemd/systemd",
        "usr/lib/systemd/systemd",
        "bin/systemd",
        "usr/bin/systemd",
    ]
    .into_iter()
    .any(|path| rootfs.join(path).is_file())
        || fs::read_link(rootfs.join("sbin/init"))
            .is_ok_and(|target| target.to_string_lossy().contains("systemd"))
}

fn request_sysv_shutdown(process: &ProcessHandle) -> Result<()> {
    let request = init_request();
    for path in ["run/initctl", "dev/initctl"] {
        let target = PathBuf::from(format!("/proc/{}/root/{path}", process.pid().as_raw()));
        if let Ok(mut file) = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&target)
            && file.write_all(&request).is_ok()
        {
            return Ok(());
        }
    }
    process.send_signal(Signal::SIGPWR)
}

fn init_request() -> [u8; 384] {
    let mut request = [0_u8; 384];
    for (offset, value) in [(0, 0x0309_1969_i32), (4, 1), (8, i32::from(b'0')), (12, 3)] {
        request[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }
    request
}

fn read_prefix(path: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut content = Vec::new();
    fs::File::open(path)?
        .take(limit as u64)
        .read_to_end(&mut content)?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create(root: &Path, path: &str, content: &[u8]) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    #[test]
    fn detects_supported_init_families() {
        for (path, expected) in [
            ("usr/lib/systemd/systemd", InitSystem::Systemd),
            ("sbin/procd", InitSystem::Procd),
            ("sbin/openrc-init", InitSystem::Openrc),
            ("sbin/runit", InitSystem::Runit),
            ("bin/s6-svscan", InitSystem::S6),
        ] {
            let root = tempfile::tempdir().unwrap();
            create(root.path(), path, b"init");
            assert_eq!(detect(root.path(), Path::new("/sbin/init")), expected);
        }
    }

    #[test]
    fn distinguishes_busybox_sysv_and_nix_wrappers() {
        let busybox = tempfile::tempdir().unwrap();
        create(busybox.path(), "sbin/init", b"#!/bin/sh\nexec busybox init");
        assert_eq!(
            detect(busybox.path(), Path::new("/sbin/init")),
            InitSystem::Busybox
        );

        let sysv = tempfile::tempdir().unwrap();
        create(sysv.path(), "sbin/init", b"binary init");
        assert_eq!(
            detect(sysv.path(), Path::new("/sbin/init")),
            InitSystem::Sysvinit
        );

        let nix = tempfile::tempdir().unwrap();
        create(
            nix.path(),
            "sbin/init",
            b"#!/bin/sh\nexec /nix/store/abc-finit",
        );
        assert_eq!(
            detect(nix.path(), Path::new("/sbin/init")),
            InitSystem::Unknown
        );
    }

    #[test]
    fn builds_sysvinit_poweroff_request() {
        let request = init_request();
        assert_eq!(
            i32::from_ne_bytes(request[0..4].try_into().unwrap()),
            0x0309_1969
        );
        assert_eq!(i32::from_ne_bytes(request[4..8].try_into().unwrap()), 1);
        assert_eq!(
            i32::from_ne_bytes(request[8..12].try_into().unwrap()),
            i32::from(b'0')
        );
        assert_eq!(request.len(), 384);
    }
}
