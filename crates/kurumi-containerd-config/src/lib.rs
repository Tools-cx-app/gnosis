//! Configuration schema, loading, path resolution, and validation for `KurumiContainerd`.

mod config;
mod model;

pub use config::parse_environment;
pub use model::{
    AndroidConfig, BindMount, Config, ContainerConfig, NetworkConfig, NetworkMode, PortForward,
    Protocol, ResourceConfig, RuntimeConfig, SecurityConfig,
};

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

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
            "[runtime]\n\n[container]\nname = 'test-1'\nrootfs = 'rootfs'\n",
        )
        .unwrap();

        let config = Config::load(&dir.path().join("container.toml")).unwrap();
        assert_eq!(config.container.hostname, "test-1");
        assert_eq!(config.container.rootfs, Some(dir.path().join("rootfs")));
    }

    #[test]
    fn rejects_removed_workdir_setting() {
        let source = "[runtime]\nworkdir = '/tmp'\n[container]\nname = 'test'\nrootfs = '/tmp'\n";
        assert!(toml::from_str::<Config>(source).is_err());
    }

    #[test]
    fn loads_missing_directory_for_install() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("container.toml");
        fs::write(
            &path,
            "[runtime]\n\n[container]\nname = 'test'\nrootfs = 'rootfs'\n",
        )
        .unwrap();

        let config = Config::load_for_install(&path).unwrap();
        assert_eq!(config.container.rootfs, Some(dir.path().join("rootfs")));
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn loads_missing_image_for_install() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("container.toml");
        fs::write(
            &path,
            "[runtime]\n\n[container]\nname = 'test'\nrootfs_image = 'rootfs.img'\n",
        )
        .unwrap();

        let config = Config::load_for_install(&path).unwrap();
        assert_eq!(
            config.container.rootfs_image,
            Some(dir.path().join("rootfs.img"))
        );
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn install_target_rejects_parent_traversal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("container.toml");
        fs::write(
            &path,
            "[runtime]\n\n[container]\nname = 'test'\nrootfs = '../rootfs'\n",
        )
        .unwrap();

        assert!(Config::load_for_install(&path).is_err());
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
            "[runtime]\n\n[container]\nname = 'test'\nrootfs = 'rootfs'\n",
        )
        .unwrap();

        let first = Config::load_persistent(&path).unwrap();
        let second = Config::load_persistent(&path).unwrap();
        assert_eq!(first.container.uuid, second.container.uuid);
        assert!(first.container.uuid.is_some());
        assert!(!fs::read_to_string(path).unwrap().contains(".tmp"));
    }

    #[test]
    fn persistent_load_preserves_permissions() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("rootfs/sbin")).unwrap();
        fs::write(dir.path().join("rootfs/sbin/init"), "").unwrap();
        let path = dir.path().join("container.toml");
        fs::write(
            &path,
            "[runtime]\n\n[container]\nname = 'test'\nrootfs = 'rootfs'\n",
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        Config::load_persistent(&path).unwrap();

        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn persistent_load_preserves_config_symlink() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("rootfs/sbin")).unwrap();
        fs::write(dir.path().join("rootfs/sbin/init"), "").unwrap();
        let target = dir.path().join("container.target.toml");
        fs::write(
            &target,
            "[runtime]\n\n[container]\nname = 'test'\nrootfs = 'rootfs'\n",
        )
        .unwrap();
        let path = dir.path().join("container.toml");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        Config::load_persistent(&path).unwrap();

        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
        assert!(fs::read_to_string(target).unwrap().contains("uuid"));
    }

    #[test]
    fn concurrent_persistent_loads_share_uuid() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("rootfs/sbin")).unwrap();
        fs::write(dir.path().join("rootfs/sbin/init"), "").unwrap();
        let path = Arc::new(dir.path().join("container.toml"));
        fs::write(
            path.as_ref(),
            "[runtime]\n\n[container]\nname = 'test'\nrootfs = 'rootfs'\n",
        )
        .unwrap();
        let loads = (0..2)
            .map(|_| {
                let path = Arc::clone(&path);
                std::thread::spawn(move || Config::load_persistent(&path).unwrap().container.uuid)
            })
            .collect::<Vec<_>>();
        let uuids = loads
            .into_iter()
            .map(|load| load.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(uuids[0], uuids[1]);
        assert!(uuids[0].is_some());
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
            "[runtime]\n\n[container]\nname = 'test'\nrootfs = 'rootfs'\nenvironment_file = 'container.env'\n\n[container.environment]\nLANG = 'C.UTF-8'\n",
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
            "[runtime]\n\n[container]\nname = 'test'\nrootfs = 'rootfs'\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        (dir, config)
    }
}
