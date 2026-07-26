# Runtime architecture

gnosis is a Cargo workspace with three crates:

```text
crates/
  gnosis-cli/      command parsing and output
  gnosis-config/   strict TOML schema, path resolution, and validation
  gnosis-runtime/  lifecycle, isolation, state, and host integration
```

The `gnosis` package produces the command-line binary. The two library
crates are internal implementation boundaries.

Dependencies flow in one direction: the CLI uses the runtime and
configuration crates, while the runtime depends on configuration. Host and
container implementation details remain private to `gnosis-runtime`.

## Configuration modules

The configuration crate keeps its public API in `lib.rs` and uses two
implementation modules. Related loading and validation helpers stay together
to keep navigation local:

```text
src/
  model.rs   serializable configuration schema and defaults
  config.rs  loading, path resolution, validation, and environment parsing
```

Callers import schema types from `gnosis_config`; the internal module layout
does not leak into the CLI or runtime.

## Lifecycle

A start operation validates configuration, locks the container identity,
prepares the root filesystem, allocates long-lived resources, and creates a
monitor. Each boot generation uses an intermediate process to create fresh PID
and optional network namespaces before forking init.

The monitor owns resources that must survive an internal container reboot:
rootfs mounts, console PTY, cgroup, and Android SELinux state where applicable.
It records init and monitor identities using the host boot ID, process start
time, and PID namespace inode so stale PIDs are not trusted.

Stop and restart use the same per-container lifecycle lock. Init signaling and
waiting use pidfds when available.

## Runtime modules

The runtime source is grouped by ownership:

```text
src/
  container/  behavior and policy applied inside the container
  runtime/    lifecycle orchestration, execution, state, and supervision
  host/       host processes, filesystems, networking, cgroups, and terminals
```

The main modules are:

- `runtime/lifecycle.rs`: start, monitor, boot generations, shutdown, and cleanup
- `runtime/boot.rs`: namespace-internal mounts, pivot, environment, and init execution
- `runtime/supervisor.rs`: wait/retry, signal policy, and child supervision helpers
- `runtime/state.rs`: public state types, secure persistence, usage, and recovery
- `runtime/execute.rs`: namespace entry, command execution, and interactive login
- `container/environment.rs`: deterministic init and session environments
- `container/init.rs`: init-family detection and shutdown protocols
- `container/security.rs`: capabilities, seccomp, and protected kernel views
- `host/process.rs`: pidfd handles and procfs process identity helpers
- `host/terminal.rs`: PTY allocation, descriptor passing, and console proxying
- `host/rootfs.rs`: directory/image rootfs preparation and loop devices
- `host/network.rs`: veth, bridges, NAT, forwarding, and rollback
- `host/cgroup.rs`: cgroup v2 resource limits
- `host/android.rs`: Android host integration on Android targets

## State and trust

Runtime directories and files are created with restrictive ownership and
permissions. State updates use no-follow opens, random temporary files, fsync,
and atomic rename. Recovery requires both a protected host record and matching
markers under `/run/gnosis` inside the container.

The runtime reduces capabilities and installs a classic-BPF seccomp filter,
but privileged container mechanisms still share the host kernel. The design
does not claim a hostile-workload security boundary.
