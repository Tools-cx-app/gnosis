use std::{
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    os::{
        fd::AsFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use kurumi_containerd_config::{Config, NetworkMode, Protocol};
use kurumi_containerd_helper::{NamespaceFlags, OPEN_CLOEXEC, OPEN_NOFOLLOW, current_pid, setns};
use procfs::process::Process;
use serde::{Deserialize, Serialize};

use crate::{
    runtime::state::{host_boot_id, process_start_time},
    runtime_workdir,
};

pub struct Network {
    host_link: Option<String>,
    peer_link: Option<String>,
    rules: Vec<Vec<String>>,
    nat_lease: bool,
}

impl Network {
    #[allow(clippy::too_many_lines)]
    pub fn setup_host(config: &Config, init_pid: i32, host_netns: &File) -> Result<Self> {
        tracing::debug!(
            network_mode = ?config.container.network,
            init_pid,
            "setting up host network"
        );
        let mut network = Self::empty();
        if config.container.network == NetworkMode::Host {
            return Ok(network);
        }
        setns(host_netns.as_fd(), NamespaceFlags::NETWORK)
            .context("failed to return to host network namespace")?;
        if config.container.network == NetworkMode::None {
            return Ok(network);
        }

        let _lock = network_lock()?;
        let host_link = format!("dsv{init_pid}");
        let peer_link = format!("dsp{init_pid}");
        network.host_link = Some(host_link.clone());
        network.peer_link = Some(peer_link.clone());
        let options = &config.container.network_options;
        let bridge = if config.container.network == NetworkMode::Nat {
            &options.bridge
        } else {
            &options.gateway_bridge
        };

        let setup = (|| {
            if !link_exists(bridge) {
                run("ip", &["link", "add", bridge, "type", "bridge"])?;
            }
            if config.container.network == NetworkMode::Nat {
                let address = format!("{}/{}", options.gateway, options.prefix);
                run_allow_exists("ip", &["address", "add", &address, "dev", bridge])?;
            }
            run("ip", &["link", "set", bridge, "up"])?;
            run(
                "ip",
                &[
                    "link", "add", &host_link, "type", "veth", "peer", "name", &peer_link,
                ],
            )?;
            run("ip", &["link", "set", &host_link, "master", bridge])?;
            run("ip", &["link", "set", &host_link, "up"])?;
            run(
                "ip",
                &["link", "set", &peer_link, "netns", &init_pid.to_string()],
            )?;

            if config.container.network == NetworkMode::Nat {
                acquire_nat_lease()?;
                network.nat_lease = true;
                fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
                let subnet = format!(
                    "{}/{}",
                    masked_network(options.address, options.prefix),
                    options.prefix
                );
                network.ensure_rule(&owned_rule(
                    &config.container.name,
                    init_pid,
                    &[
                        "-t",
                        "nat",
                        "-A",
                        "POSTROUTING",
                        "-s",
                        &subnet,
                        "-j",
                        "MASQUERADE",
                    ],
                ))?;
                network.ensure_rule(&owned_rule(
                    &config.container.name,
                    init_pid,
                    &["-A", "FORWARD", "-i", bridge, "-j", "ACCEPT"],
                ))?;
                network.ensure_rule(&owned_rule(
                    &config.container.name,
                    init_pid,
                    &[
                        "-A",
                        "FORWARD",
                        "-o",
                        bridge,
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "ESTABLISHED,RELATED",
                        "-j",
                        "ACCEPT",
                    ],
                ))?;
                for port in &options.ports {
                    let protocol = match port.protocol {
                        Protocol::Tcp => "tcp",
                        Protocol::Udp => "udp",
                    };
                    let destination = format!("{}:{}", options.address, port.container);
                    network.ensure_rule(&owned_rule(
                        &config.container.name,
                        init_pid,
                        &[
                            "-t",
                            "nat",
                            "-A",
                            "PREROUTING",
                            "-p",
                            protocol,
                            "--dport",
                            &port.host.to_string(),
                            "-j",
                            "DNAT",
                            "--to-destination",
                            &destination,
                        ],
                    ))?;
                    network.ensure_rule(&owned_rule(
                        &config.container.name,
                        init_pid,
                        &[
                            "-A",
                            "FORWARD",
                            "-p",
                            protocol,
                            "-d",
                            &options.address.to_string(),
                            "--dport",
                            &port.container.to_string(),
                            "-j",
                            "ACCEPT",
                        ],
                    ))?;
                }
            }
            Ok::<(), anyhow::Error>(())
        })();
        if let Err(error) = setup {
            network.cleanup_resources_locked();
            return Err(error);
        }
        Ok(network)
    }

    pub fn peer_name(&self) -> &str {
        self.peer_link.as_deref().unwrap_or("none")
    }

    pub fn setup_child(config: &Config, peer_name: &str) -> Result<()> {
        tracing::debug!(
            network_mode = ?config.container.network,
            peer_name,
            "setting up container network"
        );
        if config.container.network == NetworkMode::Host {
            return Ok(());
        }
        run("ip", &["link", "set", "lo", "up"])?;
        if matches!(
            config.container.network,
            NetworkMode::Nat | NetworkMode::Gateway | NetworkMode::Dhcp
        ) {
            run("ip", &["link", "set", peer_name, "name", "eth0"])?;
            run("ip", &["link", "set", "eth0", "up"])?;
            if config.container.network == NetworkMode::Nat {
                let options = &config.container.network_options;
                let address = format!("{}/{}", options.address, options.prefix);
                run("ip", &["address", "add", &address, "dev", "eth0"])?;
                run(
                    "ip",
                    &[
                        "route",
                        "add",
                        "default",
                        "via",
                        &options.gateway.to_string(),
                    ],
                )?;
            }
        }
        Ok(())
    }

    pub fn setup_dhcp(config: &Config) -> Result<()> {
        if config.container.network != NetworkMode::Dhcp {
            return Ok(());
        }
        tracing::debug!("setting up DHCP");
        if command_exists("udhcpc") {
            return run("udhcpc", &["-n", "-q", "-i", "eth0"])
                .context("DHCP configuration failed with udhcpc");
        }
        if command_exists("dhclient") {
            return run("dhclient", &["-1", "-v", "eth0"])
                .context("DHCP configuration failed with dhclient");
        }
        if command_exists("dhcpcd") {
            return run("dhcpcd", &["-1", "eth0"]).context("DHCP configuration failed with dhcpcd");
        }
        bail!("DHCP mode requires udhcpc, dhclient, or dhcpcd in the container rootfs")
    }

    pub fn write_dns(config: &Config, rootfs: &Path) -> Result<()> {
        let resolv = rootfs.join("etc/resolv.conf");
        if let Some(parent) = resolv.parent() {
            fs::create_dir_all(parent)?;
        }
        if fs::symlink_metadata(&resolv).is_ok_and(|metadata| metadata.file_type().is_symlink())
            && !resolv.try_exists()?
        {
            fs::remove_file(&resolv)?;
        }
        let content =
            config
                .container
                .network_options
                .dns
                .iter()
                .fold(String::new(), |mut content, dns| {
                    let _ = writeln!(content, "nameserver {dns}");
                    content
                });
        fs::write(&resolv, content)
            .with_context(|| format!("failed to write DNS configuration {}", resolv.display()))?;
        Ok(())
    }

    pub fn cleanup(mut self) {
        self.cleanup_resources();
    }

    fn empty() -> Self {
        Self {
            host_link: None,
            peer_link: None,
            rules: Vec::new(),
            nat_lease: false,
        }
    }

    fn ensure_rule(&mut self, rule: &[String]) -> Result<()> {
        let arguments = rule.iter().map(String::as_str).collect::<Vec<_>>();
        if add_iptables(&arguments)? {
            self.rules.push(rule.to_vec());
        }
        Ok(())
    }

    fn cleanup_resources(&mut self) {
        let _lock = network_lock().ok();
        self.cleanup_resources_locked();
    }

    fn cleanup_resources_locked(&mut self) {
        for rule in self.rules.drain(..).rev() {
            let mut delete = rule;
            if let Some(position) = delete.iter().position(|argument| argument == "-A") {
                "-D".clone_into(&mut delete[position]);
            }
            let arguments = delete.iter().map(String::as_str).collect::<Vec<_>>();
            let _ = run("iptables", &arguments);
        }
        if let Some(link) = self.host_link.take() {
            let _ = run("ip", &["link", "delete", &link]);
        }
        self.peer_link = None;
        if self.nat_lease {
            let _ = release_nat_lease();
            self.nat_lease = false;
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        self.cleanup_resources();
    }
}

fn network_lock() -> Result<File> {
    let state_dir = network_state_dir()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(OPEN_NOFOLLOW | OPEN_CLOEXEC)
        .open(state_dir.join("network.lock"))?;
    file.lock_exclusive()?;
    Ok(file)
}

fn network_state_dir() -> Result<PathBuf> {
    let path = runtime_workdir()?;
    if !path.exists() {
        fs::create_dir_all(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(metadata.is_dir(), "network state path is not a directory");
    ensure!(
        !metadata.file_type().is_symlink(),
        "network state directory must not be a symlink"
    );
    ensure!(
        metadata.uid() == 0,
        "network state directory must be owned by root"
    );
    ensure!(
        metadata.mode() & 0o022 == 0,
        "network state directory must not be group or world writable"
    );
    Ok(path)
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct NatLease {
    #[serde(default)]
    owners: Vec<NatLeaseOwner>,
    restore_disabled: bool,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct NatLeaseOwner {
    host_boot_id: String,
    pid: i32,
    start_time: u64,
}

impl NatLeaseOwner {
    fn current() -> Result<Self> {
        let pid = current_pid();
        Ok(Self {
            host_boot_id: host_boot_id()?,
            pid,
            start_time: process_start_time(pid)?,
        })
    }

    fn is_live(&self, current_boot_id: &str) -> bool {
        self.host_boot_id == current_boot_id
            && Process::new(self.pid).is_ok_and(|process| {
                process
                    .stat()
                    .is_ok_and(|stat| stat.starttime == self.start_time && stat.state != 'Z')
            })
    }
}

fn acquire_nat_lease() -> Result<()> {
    let path = network_state_dir()?.join("network-state.json");
    let mut lease = read_nat_lease(&path);
    let owner = NatLeaseOwner::current()?;
    lease
        .owners
        .retain(|candidate| candidate.is_live(&owner.host_boot_id));
    if lease.owners.is_empty() && !path.exists() {
        lease.restore_disabled = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?.trim() == "0";
    }
    if !lease.owners.contains(&owner) {
        lease.owners.push(owner);
    }
    write_nat_lease(&path, &lease)
}

fn release_nat_lease() -> Result<()> {
    let path = network_state_dir()?.join("network-state.json");
    let mut lease = read_nat_lease(&path);
    let owner = NatLeaseOwner::current()?;
    lease
        .owners
        .retain(|candidate| candidate != &owner && candidate.is_live(&owner.host_boot_id));
    if lease.owners.is_empty() {
        if lease.restore_disabled {
            fs::write("/proc/sys/net/ipv4/ip_forward", "0")?;
        }
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        return Ok(());
    }
    write_nat_lease(&path, &lease)
}

fn read_nat_lease(path: &Path) -> NatLease {
    fs::read(path)
        .ok()
        .and_then(|source| serde_json::from_slice(&source).ok())
        .unwrap_or_default()
}

fn write_nat_lease(path: &Path, lease: &NatLease) -> Result<()> {
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec(lease)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn owned_rule(name: &str, pid: i32, rule: &[&str]) -> Vec<String> {
    let mut owned = rule
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let position = owned
        .iter()
        .position(|argument| argument == "-j")
        .unwrap_or(owned.len());
    owned.splice(
        position..position,
        [
            "-m".to_owned(),
            "comment".to_owned(),
            "--comment".to_owned(),
            format!("kurumi-containerd:{name}:{pid}"),
        ],
    );
    owned
}

fn link_exists(name: &str) -> bool {
    command("ip")
        .args(["link", "show", name])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn add_iptables(rule: &[&str]) -> Result<bool> {
    let mut check = rule.to_vec();
    if let Some(position) = check.iter().position(|argument| *argument == "-A") {
        check[position] = "-C";
    }
    if command("iptables")
        .args(&check)
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return Ok(false);
    }
    run("iptables", rule)?;
    Ok(true)
}

fn run_allow_exists(program: &str, arguments: &[&str]) -> Result<()> {
    let output = command(program)
        .args(arguments)
        .output()
        .with_context(|| format!("failed to execute {program}"))?;
    if output.status.success() || String::from_utf8_lossy(&output.stderr).contains("File exists") {
        return Ok(());
    }
    bail!(
        "{program} {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn run(program: &str, arguments: &[&str]) -> Result<()> {
    let output = command(program)
        .args(arguments)
        .output()
        .with_context(|| format!("failed to execute {program}"))?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "{program} {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn command(program: &str) -> Command {
    let candidates: &[&str] = match program {
        "ip" => &["/system/bin/ip", "/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"],
        "iptables" => &[
            "/system/bin/iptables",
            "/usr/sbin/iptables",
            "/sbin/iptables",
            "/usr/bin/iptables",
        ],
        _ => &[],
    };
    let executable = candidates
        .iter()
        .find(|candidate| Path::new(candidate).is_file())
        .copied()
        .unwrap_or(program);
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("PATH", "/system/bin:/usr/sbin:/sbin:/usr/bin:/bin");
    command
}

fn command_exists(program: &str) -> bool {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin", "/system/bin"]
        .iter()
        .map(|directory| Path::new(directory).join(program))
        .any(|path| path.is_file())
}

fn masked_network(address: std::net::Ipv4Addr, prefix: u8) -> std::net::Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    std::net::Ipv4Addr::from(u32::from(address) & mask)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn replaces_dangling_resolv_conf_symlink() {
        let rootfs = tempfile::tempdir().unwrap();
        fs::create_dir(rootfs.path().join("etc")).unwrap();
        symlink(
            "../run/systemd/resolve/stub-resolv.conf",
            rootfs.path().join("etc/resolv.conf"),
        )
        .unwrap();
        let config = test_config();

        Network::write_dns(&config, rootfs.path()).unwrap();

        assert_eq!(
            fs::read_to_string(rootfs.path().join("etc/resolv.conf")).unwrap(),
            "nameserver 1.1.1.1\n"
        );
    }

    fn test_config() -> Config {
        toml::from_str(
            "[runtime]\n\n[container]\nname = 'test'\nrootfs = '/tmp'\n\n[container.network_options]\ndns = ['1.1.1.1']\n",
        )
        .unwrap()
    }

    #[test]
    fn rejects_stale_nat_lease_owner_identity() {
        let owner = NatLeaseOwner::current().unwrap();
        assert!(owner.is_live(&owner.host_boot_id));

        let stale_owner = NatLeaseOwner {
            start_time: owner.start_time.wrapping_add(1),
            ..owner
        };
        assert!(!stale_owner.is_live(&stale_owner.host_boot_id));
    }

    #[test]
    fn preserves_restore_state_from_legacy_nat_lease() {
        let lease: NatLease =
            serde_json::from_str(r#"{"users":2,"restore_disabled":true}"#).unwrap();
        assert!(lease.owners.is_empty());
        assert!(lease.restore_disabled);
    }
}
