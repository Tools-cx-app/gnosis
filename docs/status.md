# Implementation status

gnosis is an early Rust implementation. The core lifecycle is functional,
but operators should evaluate it on disposable systems before relying on it.

## Implemented

- Start, stop, restart, foreground console, and background monitoring
- Interactive `enter` and non-interactive `run`
- PID, info, usage, list, host check, and validated recovery scan
- Directory, ext4, btrfs, block-device, and volatile OverlayFS rootfs modes
- Mount, UTS, IPC, PID, and optional network namespaces
- Host, isolated, NAT, and existing-bridge networking
- TCP/UDP single-port forwarding with rollback and owned rule cleanup
- cgroup v2 memory, CPU, and PID limits
- Persistent UUIDs and PID-reuse-resistant process identity
- Init-aware graceful shutdown and internal reboot generations
- PTY consoles and interactive sessions using descriptor passing
- Capability reduction, seccomp, read-only sys/proc controls, and bind masks
- Optional Android storage/device/socket integration in the runtime

## Current limitations

- Networking depends on host `ip` and `iptables`
- cgroup v1 is not supported
- DHCP, port ranges, and automatic upstream monitoring are not implemented
- Interactive sessions cannot be detached and reattached
- Recovery requires the protected host recovery record
- Crash reconciliation is incomplete for some host-global resources
- Android service supervision and full hardware/device policy are incomplete
- There is no Android app, daemon/client API, package installer, or stable
  machine-readable output contract

Configuration fields are documented only when they have an active runtime
path. Treat failures as errors rather than assuming a degraded fallback.
