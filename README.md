# gnosis

gnosis is a privileged Linux container runtime and command-line tool written
in Rust. It manages lightweight system containers with Linux namespaces,
mounts, cgroups, networking, and a persistent TOML configuration.

This repository contains the CLI and runtime only. It does not contain an
Android application. The runtime can still expose optional Android host
resources when compiled for and executed on Android.

> gnosis is a container runtime, not a security sandbox. Run only root
> filesystems and commands you trust.

## Features

- Directory, ext4 image, btrfs image, and block-device root filesystems
- Mount, PID, UTS, IPC, and optional network namespaces
- Host, isolated, NAT, and existing-bridge networking
- cgroup v2 memory, CPU, and process limits
- Bind mounts and volatile OverlayFS
- Background monitoring and foreground PTY consoles
- Container entry and command execution without an external `nsenter`
- Persistent, PID-reuse-resistant runtime state
- Capability reduction, seccomp filtering, and read-only kernel views
- Optional Android host integration without an Android app

## Requirements

- A Linux or Android kernel with the required namespace and mount features
- Root privileges
- Rust 1.85 or newer for the 2024 edition
- `ip` and `iptables` for NAT or bridge networking
- cgroup v2 when resource limits are configured
- A prepared Linux root filesystem containing an init executable

Run the host capability checks before starting a container:

```bash
sudo cargo run --release -p gnosis -- check
```

## Build

```bash
cargo build --release
```

The binary is written to `target/release/gnosis`.

## Quick Start

Create a configuration from the example and update the rootfs path:

```bash
cp gnosis.example.toml gnosis.toml
$EDITOR gnosis.toml
sudo ./target/release/gnosis --config gnosis.toml start
sudo ./target/release/gnosis --config gnosis.toml info
sudo ./target/release/gnosis --config gnosis.toml enter
sudo ./target/release/gnosis --config gnosis.toml stop
```

`--config` defaults to `gnosis.toml` and can also be set with
`GNOSIS_CONFIG`. Relative host paths are resolved from the configuration
file, not from the current working directory.

## Commands

```text
start [--foreground]   Start the configured container
stop                   Gracefully stop it
restart [--foreground] Stop and start it
enter [USER]           Open an interactive login, defaulting to root
run COMMAND...          Run a non-interactive command
info                    Show detailed live state
pid                     Print the container init PID
usage                   Print uptime, memory, and process counts
show                    List containers in the configured work directory
scan                    Recover missing state for validated live containers
check                   Probe required host capabilities
```

## Documentation

- [CLI usage](docs/usage.md)
- [Configuration reference](docs/configuration.md)
- [Runtime architecture](docs/architecture.md)
- [Implementation status](docs/status.md)

## License

gnosis is licensed under the GNU General Public License v3.0 or later. See
[LICENSE](LICENSE).
