use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use gnosis_config::AndroidConfig;
use gnosis_helper::{MountFlags, OPEN_CLOEXEC, OPEN_NOFOLLOW, mount};
use serde::{Deserialize, Serialize};

const GPU_DIRECTORIES: &[(&str, &str)] = &[
    ("/dev/dri", "renderD"),
    ("/dev", "kgsl"),
    ("/dev", "mali"),
    ("/dev", "video"),
];
const BINDER_DEVICES: &[&str] = &["/dev/binder", "/dev/hwbinder", "/dev/vndbinder"];

pub struct SelinuxGuard {
    workdir: Option<PathBuf>,
}

impl SelinuxGuard {
    pub fn apply(config: &AndroidConfig, workdir: &Path) -> Result<Self> {
        if !config.selinux_permissive {
            return Ok(Self { workdir: None });
        }

        let enforce = Path::new("/sys/fs/selinux/enforce");
        ensure!(enforce.exists(), "SELinux enforce control is unavailable");
        let _lock = selinux_lock(workdir)?;
        let state_path = workdir.join("selinux-state.json");
        let mut state = read_selinux_state(&state_path);
        if state.users == 0 {
            state.restore_enforcing = fs::read_to_string(enforce)?.trim() == "1";
        }
        if state.users == 0 && state.restore_enforcing {
            write_control(enforce, b"0")?;
        }
        state.users += 1;
        write_selinux_state(&state_path, &state)?;
        Ok(Self {
            workdir: Some(workdir.to_path_buf()),
        })
    }
}

impl Drop for SelinuxGuard {
    fn drop(&mut self) {
        let Some(workdir) = self.workdir.take() else {
            return;
        };
        let Ok(_lock) = selinux_lock(&workdir) else {
            return;
        };
        let state_path = workdir.join("selinux-state.json");
        let mut state = read_selinux_state(&state_path);
        state.users = state.users.saturating_sub(1);
        if state.users == 0 {
            if state.restore_enforcing {
                let _ = write_control(Path::new("/sys/fs/selinux/enforce"), b"1");
            }
            let _ = fs::remove_file(state_path);
        } else {
            let _ = write_selinux_state(&state_path, &state);
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct SelinuxState {
    users: u64,
    restore_enforcing: bool,
}

pub fn setup_before_pivot(rootfs: &Path, config: &AndroidConfig) -> Result<()> {
    if !requested(config) {
        return Ok(());
    }

    if config.storage {
        bind_path(
            Path::new("/storage/emulated/0"),
            &rootfs.join("storage/emulated/0"),
            true,
        )?;
    }
    Ok(())
}

pub fn setup_after_pivot(config: &AndroidConfig) -> Result<()> {
    if !requested(config) {
        return Ok(());
    }
    if config.gpu {
        for (directory, prefix) in GPU_DIRECTORIES {
            mirror_matching(directory, prefix)?;
        }
    }
    if config.binder {
        for source in BINDER_DEVICES {
            mirror_device(source)?;
        }
    }
    if config.termux_x11 {
        bind_socket(
            "/.old_root/data/data/com.termux/files/usr/tmp/.X11-unix/X5",
            "/tmp/.X11-unix/X5",
        )?;
    }
    if config.virgl {
        bind_socket(
            "/.old_root/data/data/com.termux/files/usr/tmp/.virgl_test",
            "/tmp/.virgl_test",
        )?;
    }
    if config.pulse_audio {
        bind_socket(
            "/.old_root/data/data/com.termux/files/usr/tmp/.pulse-socket",
            "/tmp/.pulse-socket",
        )?;
    }
    Ok(())
}

fn requested(config: &AndroidConfig) -> bool {
    config.storage
        || config.gpu
        || config.binder
        || config.termux_x11
        || config.virgl
        || config.pulse_audio
        || config.selinux_permissive
}

fn mirror_matching(directory: &str, prefix: &str) -> Result<()> {
    let host_directory = PathBuf::from("/.old_root").join(directory.trim_start_matches('/'));
    let Ok(entries) = fs::read_dir(&host_directory) else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(prefix) {
            let target = PathBuf::from(directory).join(entry.file_name());
            bind_path(&entry.path(), &target, false)?;
        }
    }
    Ok(())
}

fn mirror_device(source: &str) -> Result<()> {
    let source = PathBuf::from("/.old_root").join(source.trim_start_matches('/'));
    if !source.exists() {
        return Ok(());
    }
    let target = PathBuf::from("/").join(source.strip_prefix("/.old_root")?);
    bind_path(&source, &target, false)
}

fn bind_socket(source: &str, target: &str) -> Result<()> {
    let source = Path::new(source);
    ensure!(
        source.exists(),
        "Android integration socket is unavailable: {}",
        source.display()
    );
    bind_path(source, Path::new(target), false)
}

fn bind_path(source: &Path, target: &Path, recursive: bool) -> Result<()> {
    if source.is_dir() {
        fs::create_dir_all(target)?;
    } else {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        File::create(target)?;
    }
    let flags = if recursive {
        MountFlags::BIND | MountFlags::REC
    } else {
        MountFlags::BIND
    };
    mount(Some(source), target, None, flags, None).with_context(|| {
        format!(
            "failed to bind {} to {}",
            source.display(),
            target.display()
        )
    })
}

fn write_control(path: &Path, value: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.write_all(value)?;
    Ok(())
}

fn selinux_lock(workdir: &Path) -> Result<File> {
    fs::create_dir_all(workdir)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(OPEN_NOFOLLOW | OPEN_CLOEXEC)
        .open(workdir.join("selinux.lock"))?;
    file.lock_exclusive()?;
    Ok(file)
}

fn read_selinux_state(path: &Path) -> SelinuxState {
    fs::read(path)
        .ok()
        .and_then(|source| serde_json::from_slice(&source).ok())
        .unwrap_or_default()
}

fn write_selinux_state(path: &Path, state: &SelinuxState) -> Result<()> {
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec(state)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}
