use std::{collections::BTreeMap, net::Ipv4Addr, path::PathBuf};

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
    Dhcp,
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
