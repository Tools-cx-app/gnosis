use std::path::Path;

use anyhow::{Result, ensure};

use crate::Runtime;

impl Runtime {
    /// Installs a local rootfs archive into the configured directory or image.
    ///
    /// Image targets require `size`; directory targets reject it. Existing
    /// targets are replaced only when `force` is true.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid archives, target conflicts, live
    /// containers, missing privileges, or failed filesystem operations.
    pub fn install(&self, archive: &Path, size: Option<u64>, force: bool) -> Result<()> {
        Self::ensure_root()?;
        self.ensure_layout()?;
        let _lock = self.lock()?;
        self.scan()?;
        ensure!(
            self.state()?.is_none(),
            "container '{}' is running",
            self.config.container.name
        );
        self.rootfs
            .install(archive, size, force, |rootfs| self.init.prepare(rootfs))
    }
}
