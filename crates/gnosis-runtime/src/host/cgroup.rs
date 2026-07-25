use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use gnosis_config::ResourceConfig;
use uuid::Uuid;

pub struct Cgroup {
    path: Option<PathBuf>,
}

impl Cgroup {
    pub fn create(
        workdir: &Path,
        name: &str,
        uuid: Uuid,
        resources: &ResourceConfig,
    ) -> Result<Self> {
        if resources.memory_bytes.is_none()
            && resources.cpu_quota.is_none()
            && resources.pids.is_none()
        {
            return Ok(Self { path: None });
        }
        let root = Path::new("/sys/fs/cgroup");
        ensure!(
            root.join("cgroup.controllers").exists(),
            "resource limits require cgroup v2"
        );
        let path = root.join("gnosis").join(cgroup_name(name, uuid));
        fs::create_dir_all(&path)
            .with_context(|| format!("failed to create cgroup {}", path.display()))?;
        if let Some(memory) = resources.memory_bytes {
            fs::write(path.join("memory.max"), memory.to_string())?;
        }
        if let Some(pids) = resources.pids {
            fs::write(path.join("pids.max"), pids.to_string())?;
        }
        if let Some(quota) = resources.cpu_quota {
            let period = resources.cpu_period.unwrap_or(100_000);
            fs::write(path.join("cpu.max"), format!("{quota} {period}"))?;
        }
        fs::create_dir_all(workdir)?;
        Ok(Self { path: Some(path) })
    }

    pub fn attach(&self, pid: i32) -> Result<()> {
        if let Some(path) = &self.path {
            fs::write(path.join("cgroup.procs"), pid.to_string())
                .with_context(|| format!("failed to attach PID {pid} to cgroup"))?;
        }
        Ok(())
    }

    pub fn remove(&mut self) -> Result<()> {
        if let Some(path) = self.path.take() {
            match fs::remove_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

fn cgroup_name(name: &str, uuid: Uuid) -> String {
    format!("{name}-{uuid}")
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn same_named_configs_have_distinct_cgroups() {
        let first = cgroup_name("same", Uuid::nil());
        let second = cgroup_name("same", Uuid::max());

        assert_ne!(first, second);
        assert!(first.starts_with("same-"));
        assert!(second.starts_with("same-"));
    }
}
