use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use gnosis_config::ResourceConfig;

pub struct Cgroup {
    path: Option<PathBuf>,
    unified: bool,
}

impl Cgroup {
    pub fn create(
        workdir: &Path,
        name: &str,
        resources: &ResourceConfig,
        required: bool,
    ) -> Result<Self> {
        if !required
            && resources.memory_bytes.is_none()
            && resources.cpu_quota.is_none()
            && resources.pids.is_none()
        {
            return Ok(Self {
                path: None,
                unified: false,
            });
        }
        let Some(root) = ensure_cgroup2_root()? else {
            ensure!(
                resources.memory_bytes.is_none()
                    && resources.cpu_quota.is_none()
                    && resources.pids.is_none(),
                "resource limits require cgroup v2"
            );
            return Ok(Self {
                path: None,
                unified: false,
            });
        };
        ensure!(
            root.join("cgroup.controllers").exists(),
            "resource limits require cgroup v2"
        );
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
        Ok(Self {
            path: Some(path),
            unified: true,
        })
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

    #[must_use]
    pub fn unified(&self) -> bool {
        self.unified
    }
}

fn ensure_cgroup2_root() -> Result<Option<PathBuf>> {
    if let Some(root) = cgroup2_root() {
        return Ok(Some(root));
    }

    let root = PathBuf::from("/sys/fs/cgroup");
    fs::create_dir_all(&root)?;
    let current = filesystem_magic(&root)?;
    if current != Some(libc::TMPFS_MAGIC) {
        let _ = nix::mount::mount(
            Some("none"),
            &root,
            Some("tmpfs"),
            nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_NODEV
                | nix::mount::MsFlags::MS_NOEXEC,
            Some("mode=755,size=16M"),
        );
    }
    let _ = nix::mount::mount(
        Some("none"),
        &root,
        Some("cgroup2"),
        nix::mount::MsFlags::MS_NOSUID
            | nix::mount::MsFlags::MS_NODEV
            | nix::mount::MsFlags::MS_NOEXEC,
        None::<&str>,
    );
    Ok(cgroup2_root().or(Some(root)).filter(|path| path.join("cgroup.controllers").exists()))
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

#[allow(unsafe_code)]
fn filesystem_magic(path: &Path) -> Result<Option<libc::c_long>> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: c_path is NUL-terminated and stat points to valid writable memory.
    let result = unsafe { libc::statfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).with_context(|| format!("failed to statfs {}", path.display()));
    }
    // SAFETY: statfs succeeded and initialized stat.
    let stat = unsafe { stat.assume_init() };
    #[cfg(target_os = "android")]
    {
        Ok(Some(stat.f_type.cast_signed()))
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(Some(stat.f_type))
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}
