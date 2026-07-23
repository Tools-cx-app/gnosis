use std::{
    collections::BTreeMap,
    fs,
    net::Ipv4Addr,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub runtime: RuntimeConfig,
    pub container: ContainerConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Host directory for state, PID files, logs, and transient data.
    pub workdir: PathBuf,
    #[serde(default = "default_stop_timeout")]
    pub stop_timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerConfig {
    pub name: String,
    #[serde(default)]
    pub uuid: Option<Uuid>,
    #[serde(default)]
    pub rootfs: Option<PathBuf>,
    #[serde(default)]
    pub rootfs_image: Option<PathBuf>,
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default = "default_init")]
    pub init: PathBuf,
    #[serde(default)]
    pub foreground: bool,
    #[serde(default)]
    pub volatile: bool,
    #[serde(default)]
    pub network: NetworkMode,
    #[serde(default)]
    pub network_options: NetworkConfig,
    #[serde(default)]
    pub android: AndroidConfig,
    #[serde(default)]
    pub resources: ResourceConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub mounts: Vec<BindMount>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub environment_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    pub address: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub prefix: u8,
    pub bridge: String,
    pub gateway_bridge: String,
    pub dns: Vec<String>,
    pub ports: Vec<PortForward>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            address: Ipv4Addr::new(172, 28, 0, 2),
            gateway: Ipv4Addr::new(172, 28, 0, 1),
            prefix: 16,
            bridge: "gnosis-br0".to_owned(),
            gateway_bridge: String::new(),
            dns: vec!["1.1.1.1".to_owned(), "8.8.8.8".to_owned()],
            ports: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortForward {
    pub host: u16,
    pub container: u16,
    #[serde(default)]
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AndroidConfig {
    pub storage: bool,
    pub gpu: bool,
    pub binder: bool,
    pub termux_x11: bool,
    pub virgl: bool,
    pub pulse_audio: bool,
    pub selinux_permissive: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceConfig {
    pub memory_bytes: Option<u64>,
    pub cpu_quota: Option<u64>,
    pub cpu_period: Option<u64>,
    pub pids: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    pub read_only_sys: bool,
    pub allow_user_namespaces: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            read_only_sys: true,
            allow_user_namespaces: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    #[default]
    Host,
    None,
    Nat,
    Gateway,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindMount {
    pub source: PathBuf,
    pub target: PathBuf,
    #[serde(default)]
    pub read_only: bool,
}

fn default_stop_timeout() -> u64 {
    15
}

fn default_hostname() -> String {
    String::new()
}

fn default_init() -> PathBuf {
    PathBuf::from("/sbin/init")
}

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

    /// Validates values that affect namespace and mount safety.
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
        if self.container.network == NetworkMode::Gateway {
            ensure!(
                valid_interface_name(&self.container.network_options.gateway_bridge),
                "gateway mode requires a valid network_options.gateway_bridge"
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
            let from_file = parse_environment_file(path)?;
            let configured = std::mem::take(&mut self.container.environment);
            self.container.environment = from_file;
            self.container.environment.extend(configured);
        }
        Ok(())
    }
}

fn parse_environment_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read environment file {}", path.display()))?;
    parse_environment(&source)
        .with_context(|| format!("failed to parse environment file {}", path.display()))
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

#[must_use]
pub fn strip_root(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

fn safe_container_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir))
        && path != Path::new("/")
}

fn valid_name(name: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn loads_toml_and_resolves_relative_host_paths() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("rootfs/sbin")).unwrap();
        fs::write(dir.path().join("rootfs/sbin/init"), "").unwrap();
        fs::write(
            dir.path().join("container.toml"),
            "[runtime]\nworkdir = 'state'\n\n[container]\nname = 'test-1'\nrootfs = 'rootfs'\n",
        )
        .unwrap();

        let config = Config::load(&dir.path().join("container.toml")).unwrap();
        assert_eq!(config.runtime.workdir, dir.path().join("state"));
        assert!(!config.runtime.workdir.exists());
        assert_eq!(config.container.hostname, "test-1");
        assert_eq!(config.container.rootfs, Some(dir.path().join("rootfs")));
    }

    #[test]
    fn rejects_parent_bind_target() {
        assert!(!safe_container_path(Path::new("/opt/../etc")));
    }

    #[test]
    fn persists_stable_uuid_when_missing() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("rootfs/sbin")).unwrap();
        fs::write(dir.path().join("rootfs/sbin/init"), "").unwrap();
        let path = dir.path().join("container.toml");
        fs::write(
            &path,
            "[runtime]\nworkdir = 'state'\n\n[container]\nname = 'test'\nrootfs = 'rootfs'\n",
        )
        .unwrap();

        let first = Config::load_persistent(&path).unwrap();
        let second = Config::load_persistent(&path).unwrap();
        assert_eq!(first.container.uuid, second.container.uuid);
        assert!(first.container.uuid.is_some());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn parses_environment_file_syntax() {
        let environment =
            parse_environment("# comment\nexport LANG='C.UTF-8'\nEMPTY=\nVALUE=a=b\n").unwrap();
        assert_eq!(environment.get("LANG").map(String::as_str), Some("C.UTF-8"));
        assert_eq!(environment.get("EMPTY").map(String::as_str), Some(""));
        assert_eq!(environment.get("VALUE").map(String::as_str), Some("a=b"));
        assert!(parse_environment("INVALID\n").is_err());
    }

    #[test]
    fn loads_environment_file_before_inline_overrides() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("rootfs/sbin")).unwrap();
        fs::write(dir.path().join("rootfs/sbin/init"), "").unwrap();
        fs::write(
            dir.path().join("container.env"),
            "LANG=en_US.UTF-8\nFILE_ONLY=yes\n",
        )
        .unwrap();
        let path = dir.path().join("container.toml");
        fs::write(
            &path,
            "[runtime]\nworkdir = 'state'\n\n[container]\nname = 'test'\nrootfs = 'rootfs'\nenvironment_file = 'container.env'\n\n[container.environment]\nLANG = 'C.UTF-8'\n",
        )
        .unwrap();

        let config = Config::load_persistent(&path).unwrap();
        assert_eq!(config.container.environment["LANG"], "C.UTF-8");
        assert_eq!(config.container.environment["FILE_ONLY"], "yes");
        let persisted = fs::read_to_string(path).unwrap();
        assert!(persisted.contains("environment_file = \"container.env\""));
        assert!(!persisted.contains("FILE_ONLY"));
    }

    #[test]
    fn rejects_dot_container_names() {
        assert!(!valid_name("."));
        assert!(!valid_name(".."));
        assert!(valid_name("debian.12"));
        assert!(valid_name("a..b"));
    }

    #[test]
    fn rejects_conflicting_ports_within_protocol() {
        let (_directory, mut config) = test_config();
        config.container.network_options.ports = vec![
            PortForward {
                host: 8080,
                container: 80,
                protocol: Protocol::Tcp,
            },
            PortForward {
                host: 8080,
                container: 81,
                protocol: Protocol::Tcp,
            },
        ];
        assert!(config.validate().is_err());

        config.container.network_options.ports[1].protocol = Protocol::Udp;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validates_resource_limit_ranges() {
        let (_directory, mut config) = test_config();
        config.container.resources.memory_bytes = Some(4 * 1024 * 1024 - 1);
        assert!(config.validate().is_err());

        let (_directory, mut config) = test_config();
        config.container.resources.cpu_quota = Some(1_000);
        assert!(config.validate().is_err());

        let (_directory, mut config) = test_config();
        config.container.resources.cpu_quota = Some(999);
        config.container.resources.cpu_period = Some(100_000);
        assert!(config.validate().is_err());

        let (_directory, mut config) = test_config();
        config.container.resources.pids = Some(0);
        assert!(config.validate().is_err());

        let (_directory, mut config) = test_config();
        config.container.resources.memory_bytes = Some(4 * 1024 * 1024);
        config.container.resources.cpu_quota = Some(1_000);
        config.container.resources.cpu_period = Some(100_000);
        config.container.resources.pids = Some(4_194_304);
        assert!(config.validate().is_ok());
    }

    fn test_config() -> (tempfile::TempDir, Config) {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("rootfs/sbin")).unwrap();
        fs::write(dir.path().join("rootfs/sbin/init"), "").unwrap();
        let path = dir.path().join("container.toml");
        fs::write(
            &path,
            "[runtime]\nworkdir = 'state'\n\n[container]\nname = 'test'\nrootfs = 'rootfs'\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        (dir, config)
    }
}
