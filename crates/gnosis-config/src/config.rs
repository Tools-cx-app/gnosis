use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use uuid::Uuid;

use crate::{Config, NetworkMode, Protocol};

impl Config {
    /// Loads, resolves, and validates a TOML configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or parsed, a host path
    /// cannot be resolved, or a configuration invariant is violated.
    pub fn load(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let mut config: Self = toml::from_str(&source)
            .with_context(|| format!("failed to parse TOML config {}", path.display()))?;
        config.resolve_paths(path)?;
        config.validate()?;
        Ok(config)
    }

    /// Loads a configuration and persists an external identity when it does
    /// not already have one. The write is atomic so a killed CLI cannot leave
    /// a partially written TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error when the source configuration is invalid or the
    /// persistent TOML rewrite cannot be committed.
    pub fn load_persistent(path: &Path) -> Result<Self> {
        let config = Self::load(path)?;
        if config.container.uuid.is_none() {
            let source = fs::read_to_string(path)
                .with_context(|| format!("failed to read config {}", path.display()))?;
            let mut document: toml::Value = toml::from_str(&source)
                .with_context(|| format!("failed to parse TOML config {}", path.display()))?;
            let container = document
                .get_mut("container")
                .and_then(toml::Value::as_table_mut)
                .context("TOML config has no container table")?;
            container.insert(
                "uuid".to_owned(),
                toml::Value::String(Uuid::new_v4().to_string()),
            );
            let encoded = toml::to_string_pretty(&document)
                .context("failed to serialize persistent TOML config")?;
            let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
            fs::write(&temporary, encoded).with_context(|| {
                format!("failed to write temporary config {}", temporary.display())
            })?;
            fs::rename(&temporary, path).with_context(|| {
                format!("failed to commit persistent config {}", path.display())
            })?;
            return Self::load(path);
        }
        Ok(config)
    }

    fn resolve_paths(&mut self, config_path: &Path) -> Result<()> {
        let base = config_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        self.runtime.workdir = absolute_workdir(base, &self.runtime.workdir)?;
        if let Some(rootfs) = &mut self.container.rootfs {
            *rootfs = absolute_from(base, rootfs)?;
        }
        if let Some(image) = &mut self.container.rootfs_image {
            *image = absolute_from(base, image)?;
        }
        for mount in &mut self.container.mounts {
            mount.source = absolute_from(base, &mount.source)?;
        }
        if let Some(environment_file) = &mut self.container.environment_file {
            *environment_file = absolute_from(base, environment_file)?;
        }
        Ok(())
    }
}

impl Config {
    /// Validates and normalizes values that affect namespace and mount safety.
    ///
    /// This also resolves the default hostname and merges an environment file
    /// into the inline environment, so callers must expect mutation and I/O.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid names or paths, missing rootfs content,
    /// invalid networking values, or malformed environment keys.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&mut self) -> Result<()> {
        ensure!(
            valid_name(&self.container.name),
            "container name may contain only ASCII letters, digits, '.', '_' and '-'"
        );
        ensure!(
            self.runtime.workdir.is_absolute(),
            "runtime.workdir must resolve to an absolute path"
        );
        ensure!(
            self.container.rootfs.is_some() ^ self.container.rootfs_image.is_some(),
            "configure exactly one of container.rootfs or container.rootfs_image"
        );
        if let Some(rootfs) = &self.container.rootfs {
            ensure!(
                rootfs.is_absolute(),
                "container.rootfs must resolve to an absolute path"
            );
            ensure!(
                rootfs.is_dir(),
                "rootfs is not a directory: {}",
                rootfs.display()
            );
        }
        if let Some(image) = &self.container.rootfs_image {
            ensure!(
                image.is_absolute(),
                "container.rootfs_image must resolve to an absolute path"
            );
            ensure!(
                image.is_file() || image.exists(),
                "rootfs image does not exist: {}",
                image.display()
            );
        }
        ensure!(
            self.container.init.is_absolute(),
            "container.init must be an absolute path inside rootfs"
        );
        ensure!(
            self.runtime.stop_timeout_seconds > 0,
            "runtime.stop_timeout_seconds must be greater than zero"
        );
        if self.container.hostname.is_empty() {
            self.container.hostname.clone_from(&self.container.name);
        }
        ensure!(
            self.container.network_options.prefix <= 32,
            "network prefix must be <= 32"
        );
        ensure!(
            valid_interface_name(&self.container.network_options.bridge),
            "invalid NAT bridge name"
        );
        if matches!(
            self.container.network,
            NetworkMode::Gateway | NetworkMode::Dhcp
        ) {
            ensure!(
                valid_interface_name(&self.container.network_options.gateway_bridge),
                "gateway and dhcp modes require a valid network_options.gateway_bridge"
            );
        }
        for dns in &self.container.network_options.dns {
            ensure!(
                dns.parse::<std::net::IpAddr>().is_ok(),
                "invalid DNS address: {dns}"
            );
        }
        for port in &self.container.network_options.ports {
            ensure!(
                port.host > 0 && port.container > 0,
                "forwarded ports must be non-zero"
            );
        }
        for (index, port) in self.container.network_options.ports.iter().enumerate() {
            for other in &self.container.network_options.ports[index + 1..] {
                if port.protocol != other.protocol {
                    continue;
                }
                ensure!(
                    port.host != other.host,
                    "duplicate host port {}/{}",
                    port.host,
                    protocol_name(port.protocol)
                );
                ensure!(
                    port.container != other.container,
                    "duplicate container port {}/{}",
                    port.container,
                    protocol_name(port.protocol)
                );
            }
        }
        if let Some(memory) = self.container.resources.memory_bytes {
            ensure!(
                memory >= 4 * 1024 * 1024,
                "memory_bytes must be at least 4194304"
            );
        }
        match (
            self.container.resources.cpu_quota,
            self.container.resources.cpu_period,
        ) {
            (Some(quota), Some(period)) => {
                ensure!(quota >= 1_000, "cpu_quota must be at least 1000");
                ensure!(period > 0, "cpu_period must be greater than zero");
            }
            (Some(_), None) | (None, Some(_)) => {
                bail!("cpu_quota and cpu_period must be configured together");
            }
            (None, None) => {}
        }
        if let Some(pids) = self.container.resources.pids {
            ensure!(
                (1..=4_194_304).contains(&pids),
                "pids must be between 1 and 4194304"
            );
        }
        if let Some(rootfs) = &self.container.rootfs {
            let init = rootfs.join(strip_root(&self.container.init));
            ensure!(
                init.exists(),
                "init does not exist in rootfs: {}",
                init.display()
            );
        }
        for mount in &self.container.mounts {
            ensure!(
                mount.source.exists(),
                "bind source does not exist: {}",
                mount.source.display()
            );
            ensure!(
                safe_container_path(&mount.target),
                "unsafe bind target: {}",
                mount.target.display()
            );
        }
        for key in self.container.environment.keys() {
            ensure!(
                valid_env_key(key),
                "invalid environment variable name: {key}"
            );
        }
        for value in self.container.environment.values() {
            ensure!(
                !value.contains('\0'),
                "environment values cannot contain NUL bytes"
            );
        }
        if let Some(path) = &self.container.environment_file {
            ensure!(
                path.is_file(),
                "environment file does not exist: {}",
                path.display()
            );
            let source = fs::read_to_string(path)
                .with_context(|| format!("failed to read environment file {}", path.display()))?;
            let from_file = parse_environment(&source)
                .with_context(|| format!("failed to parse environment file {}", path.display()))?;
            let configured = std::mem::take(&mut self.container.environment);
            self.container.environment = from_file;
            self.container.environment.extend(configured);
        }
        Ok(())
    }
}

/// Parses newline-separated `KEY=VALUE` environment entries.
///
/// # Errors
///
/// Returns an error for malformed lines, invalid variable names, or NUL bytes.
pub fn parse_environment(source: &str) -> Result<BTreeMap<String, String>> {
    let mut environment = BTreeMap::new();
    for (index, raw) in source.lines().enumerate() {
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(value) = line.strip_prefix("export ") {
            line = value.trim_start();
        }
        let (key, raw_value) = line
            .split_once('=')
            .with_context(|| format!("line {} has no '='", index + 1))?;
        ensure!(valid_env_key(key), "invalid key on line {}", index + 1);
        let value = if raw_value.len() >= 2
            && ((raw_value.starts_with('"') && raw_value.ends_with('"'))
                || (raw_value.starts_with('\'') && raw_value.ends_with('\'')))
        {
            &raw_value[1..raw_value.len() - 1]
        } else {
            raw_value
        };
        ensure!(!value.contains('\0'), "NUL byte on line {}", index + 1);
        environment.insert(key.to_owned(), value.to_owned());
    }
    Ok(environment)
}

fn absolute_from(base: &Path, path: &Path) -> Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    joined
        .canonicalize()
        .with_context(|| format!("failed to resolve path {}", joined.display()))
}

fn absolute_workdir(base: &Path, path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let base = base
        .canonicalize()
        .with_context(|| format!("failed to resolve config directory {}", base.display()))?;
    Ok(base.join(path))
}

pub(crate) fn strip_root(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

pub(crate) fn safe_container_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir))
        && path != Path::new("/")
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn valid_env_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}
