use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use gnosis_config::ResourceConfig;
use gnosis_helper::{MountFlags, TMPFS_MAGIC, filesystem_type, mount, unmount};

pub struct Cgroup {
    paths: Vec<PathBuf>,
    unified: bool,
}

impl Cgroup {
    pub fn create(
        workdir: &Path,
        name: &str,
        resources: &ResourceConfig,
        required: bool,
        bootstrap: bool,
    ) -> Result<Self> {
        if !required
            && resources.memory_bytes.is_none()
            && resources.cpu_quota.is_none()
            && resources.pids.is_none()
        {
            return Ok(Self {
                paths: Vec::new(),
                unified: false,
            });
        }
        if resources.memory_bytes.is_none()
            && resources.cpu_quota.is_none()
            && resources.pids.is_none()
        {
            fs::create_dir_all(workdir)?;
            return Ok(Self {
                paths: Vec::new(),
                unified: false,
            });
        }
        if let Some(root) = ensure_cgroup2_root(bootstrap)? {
            let path = root.join("gnosis").join(name);
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
            return Ok(Self {
                paths: vec![path],
                unified: true,
            });
        }

        let roots = ensure_cgroup1_roots(resources, required, bootstrap)?;
        let mut paths = Vec::new();
        for (controller, root) in roots {
            let path = root.join("gnosis").join(name);
            fs::create_dir_all(&path)
                .with_context(|| format!("failed to create cgroup {}", path.display()))?;
            match controller {
                Controller::Memory => {
                    if let Some(value) = resources.memory_bytes {
                        fs::write(path.join("memory.limit_in_bytes"), value.to_string())?;
                    }
                }
                Controller::Cpu => {
                    if let Some(quota) = resources.cpu_quota {
                        let period = resources.cpu_period.unwrap_or(100_000);
                        fs::write(path.join("cpu.cfs_quota_us"), quota.to_string())?;
                        fs::write(path.join("cpu.cfs_period_us"), period.to_string())?;
                    }
                }
                Controller::Pids => {
                    if let Some(value) = resources.pids {
                        fs::write(path.join("pids.max"), value.to_string())?;
                    }
                }
            }
            paths.push(path);
        }
        fs::create_dir_all(workdir)?;
        Ok(Self {
            paths,
            unified: false,
        })
    }

    pub fn attach(&self, pid: i32) -> Result<()> {
        for path in &self.paths {
            fs::write(path.join("cgroup.procs"), pid.to_string())
                .with_context(|| format!("failed to attach PID {pid} to cgroup"))?;
        }
        Ok(())
    }

    pub fn remove(&mut self) -> Result<()> {
        for path in self.paths.drain(..) {
            match fs::remove_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn unified(&self) -> bool {
        self.unified
    }
}

fn ensure_cgroup2_root(bootstrap: bool) -> Result<Option<PathBuf>> {
    if let Some(root) = cgroup2_root() {
        return Ok(Some(root));
    }
    if !bootstrap {
        return Ok(None);
    }

    let root = PathBuf::from("/sys/fs/cgroup");
    fs::create_dir_all(&root)?;
    let filesystem = filesystem_type(&root)?;
    let mut mounted_tmpfs = false;
    if filesystem != TMPFS_MAGIC {
        mount(
            Some(Path::new("none")),
            &root,
            Some("tmpfs"),
            MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            Some("mode=755,size=16M"),
        )
        .context("failed to mount cgroup tmpfs base")?;
        mounted_tmpfs = true;
    }
    if mount(
        Some(Path::new("none")),
        &root,
        Some("cgroup2"),
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        None,
    )
    .is_err()
    {
        if mounted_tmpfs {
            let _ = unmount(&root, false);
        }
        return Ok(None);
    }
    Ok(cgroup2_root().filter(|path| path.join("cgroup.controllers").exists()))
}

fn cgroup2_root() -> Option<PathBuf> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").ok()?;
    mountinfo.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let separator = fields.iter().position(|field| *field == "-")?;
        if fields.get(separator + 1) != Some(&"cgroup2") {
            return None;
        }
        fields.get(4).map(PathBuf::from)
    })
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum Controller {
    Memory,
    Cpu,
    Pids,
}

fn ensure_cgroup1_roots(
    resources: &ResourceConfig,
    required: bool,
    bootstrap: bool,
) -> Result<Vec<(Controller, PathBuf)>> {
    let controllers = requested_controllers(resources, required);
    if controllers.is_empty() {
        return Ok(Vec::new());
    }
    let mut roots = cgroup1_roots()?;
    if controllers
        .iter()
        .all(|controller| roots.contains_key(controller))
    {
        return Ok(controllers
            .into_iter()
            .filter_map(|controller| roots.remove(&controller).map(|root| (controller, root)))
            .collect());
    }
    ensure!(bootstrap, "required cgroup controllers are not mounted");

    let root = PathBuf::from("/sys/fs/cgroup");
    fs::create_dir_all(&root)?;
    if filesystem_type(&root)? != TMPFS_MAGIC {
        mount(
            Some(Path::new("none")),
            &root,
            Some("tmpfs"),
            MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            Some("mode=755,size=16M"),
        )
        .context("failed to mount cgroup tmpfs base")?;
    }
    let hierarchy = root.join("gnosis");
    fs::create_dir_all(&hierarchy)?;
    let options = if controllers.is_empty() {
        "none,name=gnosis".to_owned()
    } else {
        controllers
            .iter()
            .map(|controller| match controller {
                Controller::Memory => "memory",
                Controller::Cpu => "cpu",
                Controller::Pids => "pids",
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    mount(
        Some(Path::new("none")),
        &hierarchy,
        Some("cgroup"),
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        Some(options.as_str()),
    )
    .context("failed to mount cgroup v1 hierarchy")?;
    roots = cgroup1_roots()?;
    ensure!(
        controllers
            .iter()
            .all(|controller| roots.contains_key(controller)),
        "failed to mount required cgroup v1 controllers"
    );
    Ok(controllers
        .into_iter()
        .filter_map(|controller| roots.remove(&controller).map(|root| (controller, root)))
        .collect())
}

fn requested_controllers(resources: &ResourceConfig, required: bool) -> Vec<Controller> {
    let mut controllers = Vec::new();
    if resources.memory_bytes.is_some() {
        controllers.push(Controller::Memory);
    }
    if resources.cpu_quota.is_some() {
        controllers.push(Controller::Cpu);
    }
    if resources.pids.is_some() {
        controllers.push(Controller::Pids);
    }
    if required && controllers.is_empty() {
        // Systemd still needs a writable hierarchy even without limits.
        controllers.push(Controller::Pids);
    }
    controllers
}

fn cgroup1_roots() -> Result<std::collections::HashMap<Controller, PathBuf>> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    Ok(parse_cgroup1_roots(&mountinfo))
}

fn parse_cgroup1_roots(mountinfo: &str) -> std::collections::HashMap<Controller, PathBuf> {
    let mut roots = std::collections::HashMap::new();
    for line in mountinfo.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(separator) = fields.iter().position(|field| *field == "-") else {
            continue;
        };
        if fields.get(separator + 1) != Some(&"cgroup") {
            continue;
        }
        let Some(path) = fields.get(4).map(PathBuf::from) else {
            continue;
        };
        let options = fields.get(separator + 3).copied().unwrap_or_default();
        for (name, controller) in [
            ("memory", Controller::Memory),
            ("cpu", Controller::Cpu),
            ("pids", Controller::Pids),
        ] {
            if options.split(',').any(|option| option == name) {
                roots.entry(controller).or_insert_with(|| path.clone());
            }
        }
    }
    roots
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::{Controller, parse_cgroup1_roots};
    use std::path::PathBuf;

    #[test]
    fn parses_controller_mounts_from_mountinfo() {
        let mountinfo = "29 23 0:26 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n30 23 0:27 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu,cpuacct\n31 23 0:28 / /sys/fs/cgroup/pids rw - cgroup cgroup rw,pids\n";
        let roots = parse_cgroup1_roots(mountinfo);
        assert_eq!(
            roots.get(&Controller::Memory),
            Some(&PathBuf::from("/sys/fs/cgroup/memory"))
        );
        assert_eq!(
            roots.get(&Controller::Cpu),
            Some(&PathBuf::from("/sys/fs/cgroup/cpu"))
        );
        assert_eq!(
            roots.get(&Controller::Pids),
            Some(&PathBuf::from("/sys/fs/cgroup/pids"))
        );
    }
}
