//! Configuration schema, loading, path resolution, and validation for gnosis.

mod config;
mod model;

pub use config::parse_environment;
pub use model::{
    AndroidConfig, BindMount, Config, ContainerConfig, NetworkConfig, NetworkMode, PortForward,
    Protocol, ResourceConfig, RuntimeConfig, SecurityConfig,
};

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use tempfile::tempdir;

    use super::*;
    use crate::config::{safe_container_path, valid_name};

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
    fn rejects_old_root_bind_targets() {
        assert!(!safe_container_path(Path::new("/.old_root")));
        assert!(!safe_container_path(Path::new("/.old_root/etc")));
        assert!(safe_container_path(Path::new("/.old_rootfs")));
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
    fn dhcp_requires_an_existing_bridge_name() {
        let (_directory, mut config) = test_config();
        config.container.network = NetworkMode::Dhcp;
        config.container.network_options.gateway_bridge.clear();
        assert!(config.validate().is_err());

        config.container.network_options.gateway_bridge = "br0".to_owned();
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
