//! Core container lifecycle and host-integration primitives for `KurumiContainerd`.

mod container;
mod host;
mod runtime;

use std::path::PathBuf;

#[cfg(target_os = "android")]
use anyhow::Context;
use anyhow::Result;
use kurumi_containerd_config::Config;

use crate::{container::init::Init, host::rootfs::Rootfs};
pub use crate::{
    container::init::InitSystem,
    runtime::state::{ContainerInfo, ContainerState},
};

/// A configured container runtime.
pub struct Runtime {
    pub(crate) config: Config,
    pub(crate) init: Init,
    pub(crate) rootfs: Rootfs,
    pub(crate) workdir: PathBuf,
    pub(crate) state_dir: PathBuf,
    pub(crate) recovery_dir: PathBuf,
    pub(crate) volatile_dir: PathBuf,
    pub(crate) lock_path: PathBuf,
}

impl Runtime {
    /// Creates a runtime for one validated container configuration.
    ///
    /// # Errors
    ///
    /// Returns an error on Android when `TMP` is not set.
    pub fn new(config: Config) -> Result<Self> {
        let workdir = runtime_workdir()?;
        let state_dir = workdir.join("state");
        let recovery_dir = workdir.join("recovery");
        let mount_dir = workdir.join("mounts");
        let volatile_dir = workdir.join("volatile");
        let lock_path = workdir.join(format!("{}.lock", config.container.name));
        let init = Init::new(&config);
        let rootfs = Rootfs::new(&config, &mount_dir);
        Ok(Self {
            config,
            init,
            rootfs,
            workdir,
            state_dir,
            recovery_dir,
            volatile_dir,
            lock_path,
        })
    }
}

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn runtime_workdir() -> Result<PathBuf> {
    #[cfg(target_os = "android")]
    {
        let tmp = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .context("TMPDIR is not set")?;
        anyhow::ensure!(tmp.is_absolute(), "TMPDIR must be an absolute path");
        Ok(tmp.join("kurumi-containerd"))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(PathBuf::from("/run/kurumi-containerd"))
    }
}

/// Reports whether the current kernel exposes pidfd process handles.
#[must_use]
pub fn pidfd_available() -> bool {
    host::process::ProcessHandle::open(kurumi_containerd_helper::process::current_pid()).is_ok()
}
