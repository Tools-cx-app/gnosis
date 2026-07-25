use std::{
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    os::{fd::AsFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use gnosis_config::{Config, NetworkMode, Protocol};
use nix::sched::{CloneFlags, setns};
use serde::{Deserialize, Serialize};

use crate::runtime::state::ensure_trusted_directory;

const NETWORK_RUNTIME_DIRECTORY: &str = "/run/gnosis";

pub struct Network {
    host_link: Option<String>,
    peer_link: Option<String>,
    rules: Vec<Vec<String>>,
    managed: bool,
    nat_lease: bool,
}

impl Network {
    #[allow(clippy::too_many_lines)]
    pub fn setup_host(config: &Config, init_pid: i32, host_netns: &File) -> Result<Self> {
        let mut network = Self::empty();
        if config.container.network == NetworkMode::Host {
            return Ok(network);
        }
        setns(host_netns.as_fd(), CloneFlags::CLONE_NEWNET)
            .context("failed to return to host network namespace")?;
        if config.container.network == NetworkMode::None {
            return Ok(network);
        }

        let _lock = network_lock()?;
        network.managed = true;
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
        if config.container.network == NetworkMode::Host {
            return Ok(());
        }
        run("ip", &["link", "set", "lo", "up"])?;
        if matches!(
            config.container.network,
            NetworkMode::Nat | NetworkMode::Gateway
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

    pub fn write_dns(config: &Config, rootfs: &Path) -> Result<()> {
        let resolv = rootfs.join("etc/resolv.conf");
        if let Some(parent) = resolv.parent() {
            fs::create_dir_all(parent)?;
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
        fs::write(resolv, content)?;
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
            managed: false,
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
        let _lock = self.managed.then(|| network_lock().ok()).flatten();
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
        self.managed = false;
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        self.cleanup_resources();
    }
}

fn network_lock() -> Result<File> {
    let directory = Path::new(NETWORK_RUNTIME_DIRECTORY);
    ensure_trusted_directory(directory)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("network.lock"))?;
    file.lock_exclusive()?;
    Ok(file)
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct NatLease {
    users: u64,
    restore_disabled: bool,
}

fn acquire_nat_lease() -> Result<()> {
    let path = nat_lease_path();
    let mut lease = read_nat_lease(&path);
    if lease.users == 0 {
        lease.restore_disabled = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?.trim() == "0";
    }
    lease.users += 1;
    write_nat_lease(&path, &lease)
}

fn release_nat_lease() -> Result<()> {
    let path = nat_lease_path();
    let mut lease = read_nat_lease(&path);
    lease.users = lease.users.saturating_sub(1);
    if lease.users == 0 {
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

fn nat_lease_path() -> PathBuf {
    Path::new(NETWORK_RUNTIME_DIRECTORY).join("network-state.json")
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
            format!("gnosis:{name}:{pid}"),
        ],
    );
    owned
}

fn link_exists(name: &str) -> bool {
    command("ip")
        .args(["link", "show", name])
        .status()
        .is_ok_and(|status| status.success())
}

fn add_iptables(rule: &[&str]) -> Result<bool> {
    let mut check = rule.to_vec();
    if let Some(position) = check.iter().position(|argument| *argument == "-A") {
        check[position] = "-C";
    }
    if command("iptables")
        .args(&check)
        .status()
        .is_ok_and(|status| status.success())
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
    use super::*;

    #[test]
    fn nat_lease_uses_global_runtime_directory() {
        assert_eq!(
            nat_lease_path(),
            Path::new("/run/gnosis/network-state.json")
        );
    }
}
