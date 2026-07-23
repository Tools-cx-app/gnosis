//! Core container lifecycle and host-integration primitives for gnosis.

mod container;
mod host;
mod runtime;

use gnosis_config::Config;

pub use crate::{
    container::init::InitSystem,
    runtime::state::{ContainerState, ContainerUsage},
};

/// A configured container runtime.
pub struct Runtime {
    pub(crate) config: Config,
}

impl Runtime {
    /// Creates a runtime for one validated container configuration.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

/// Reports whether the current kernel exposes pidfd process handles.
#[must_use]
pub fn pidfd_available() -> bool {
    host::process::ProcessHandle::open(nix::unistd::getpid()).is_ok()
}
