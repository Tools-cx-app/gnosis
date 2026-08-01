use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use kurumi_containerd_config::ResourceConfig;
use kurumi_containerd_helper::{MountFlags, TMPFS_MAGIC, filesystem_type, mount, unmount};

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
        if !cgroup_required(resources, required) {
            return Ok(Self {
                paths: Vec::new(),
                unified: false,
            });
        }
        if let Some(root) = ensure_cgroup2_root(bootstrap)? {
            let path = root.join("kurumi-containerd").join(name);
            fs::create_dir_all(&path)
                .with_context(|| format!("failed to create cgroup {}", path.display()))?;
            let cgroup = Self {
                paths: vec![path.clone()],
                unified: true,
            };
            write_limit(
                &path.join("memory.max"),
                resources.memory_bytes.map(|value| value.to_string()),
                "max",
            )?;
            write_limit(
                &path.join("pids.max"),
                resources.pids.map(|value| value.to_string()),
                "max",
            )?;
            write_limit(
                &path.join("cpu.max"),
                resources
                    .cpu_quota
                    .map(|quota| format!("{quota} {}", resources.cpu_period.unwrap_or(100_000))),
                "max 100000",
            )?;
            fs::create_dir_all(workdir)?;
            return Ok(cgroup);
        }

        let roots = ensure_cgroup1_roots(resources, required, bootstrap)?;
        let mut cgroup = Self {
            paths: Vec::new(),
            unified: false,
        };
        for (controller, root) in roots {
            let path = root.join("kurumi-containerd").join(name);
            fs::create_dir_all(&path)
                .with_context(|| format!("failed to create cgroup {}", path.display()))?;
            cgroup.paths.push(path.clone());
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
                    fs::write(
                        path.join("pids.max"),
                        resources
                            .pids
                            .map_or_else(|| "max".to_owned(), |value| value.to_string()),
                    )?;
                }
            }
        }
        fs::create_dir_all(workdir)?;
        Ok(cgroup)
    }

    pub fn attach(&self, pid: i32) -> Result<()> {
        for path in &self.paths {
            fs::write(path.join("cgroup.procs"), pid.to_string())
                .with_context(|| format!("failed to attach PID {pid} to cgroup"))?;
        }
        Ok(())
    }

    pub fn remove(&mut self) -> Result<()> {
        let mut first_error = None;
        for path in self.paths.drain(..) {
            match fs::remove_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), |error| Err(error.into()))
    }

    #[must_use]
    pub fn unified(&self) -> bool {
        self.unified
    }
}

fn write_limit(path: &Path, value: Option<String>, unlimited: &str) -> Result<()> {
    if let Some(value) = value {
        fs::write(path, value)?;
    } else if path.exists() {
        fs::write(path, unlimited)?;
    }
    Ok(())
}

fn cgroup_required(resources: &ResourceConfig, required: bool) -> bool {
    required
        || resources.memory_bytes.is_some()
        || resources.cpu_quota.is_some()
        || resources.pids.is_some()
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
    procfs::process::Process::myself()
        .ok()?
        .mountinfo()
        .ok()?
        .0
        .into_iter()
        .find(|mount| mount.fs_type == "cgroup2")
        .map(|mount| mount.mount_point)
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
    let hierarchy = root.join("kurumi-containerd");
    fs::create_dir_all(&hierarchy)?;
    let options = if controllers.is_empty() {
        "none,name=kurumi-containerd".to_owned()
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
    let mountinfo = procfs::process::Process::myself()?.mountinfo()?;
    Ok(parse_cgroup1_roots(&mountinfo.0))
}

fn parse_cgroup1_roots(
    mountinfo: &[procfs::process::MountInfo],
) -> std::collections::HashMap<Controller, PathBuf> {
    let mut roots = std::collections::HashMap::new();
    for mount in mountinfo {
        if mount.fs_type != "cgroup" {
            continue;
        }
        for (name, controller) in [
            ("memory", Controller::Memory),
            ("cpu", Controller::Cpu),
            ("pids", Controller::Pids),
        ] {
            if mount.super_options.contains_key(name) {
                roots
                    .entry(controller)
                    .or_insert_with(|| mount.mount_point.clone());
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
    use std::path::PathBuf;

    use kurumi_containerd_config::ResourceConfig;
    use procfs::process::MountInfo;

    use super::{
        Cgroup, Controller, cgroup_required, parse_cgroup1_roots, requested_controllers,
        write_limit,
    };

    #[test]
    fn systemd_requires_cgroup_without_resource_limits() {
        let resources = ResourceConfig::default();

        assert!(cgroup_required(&resources, true));
        assert_eq!(
            requested_controllers(&resources, true),
            vec![Controller::Pids]
        );
    }

    #[test]
    fn custom_init_skips_cgroup_without_resource_limits() {
        assert!(!cgroup_required(&ResourceConfig::default(), false));
    }

    #[test]
    fn parses_controller_mounts_from_mountinfo() {
        let mountinfo = "29 23 0:26 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n30 23 0:27 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu,cpuacct\n31 23 0:28 / /sys/fs/cgroup/pids rw - cgroup cgroup rw,pids\n";
        let mountinfo = mountinfo
            .lines()
            .map(|line| MountInfo::from_line(line).unwrap())
            .collect::<Vec<_>>();
        let roots = parse_cgroup1_roots(&mountinfo);
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

    #[test]
    fn resets_removed_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("memory.max");
        std::fs::write(&path, "1048576").unwrap();

        write_limit(&path, None, "max").unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "max");
    }

    #[test]
    fn cleanup_continues_after_error() {
        let directory = tempfile::tempdir().unwrap();
        let blocked = directory.path().join("blocked");
        std::fs::create_dir(&blocked).unwrap();
        std::fs::write(blocked.join("file"), "content").unwrap();
        let removable = directory.path().join("removable");
        std::fs::create_dir(&removable).unwrap();
        let mut cgroup = Cgroup {
            paths: vec![blocked, removable.clone()],
            unified: false,
        };

        assert!(cgroup.remove().is_err());
        assert!(!removable.exists());
    }
}
