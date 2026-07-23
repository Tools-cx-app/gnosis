# Configuration

gnosis uses strict TOML. Unknown fields and invalid values are rejected.
Start from [gnosis.example.toml](../gnosis.example.toml).

Host paths may be absolute or relative to the TOML file. Container paths such
as `init`, mount targets, and device paths are always paths inside the
container.

## Runtime

```toml
[runtime]
workdir = "./var/gnosis"
stop_timeout_seconds = 15
```

`workdir` is required and stores locks, live state, recovery data, and other
runtime-owned files. It must be root-owned, must not be group/world writable,
and must not be a symlink. There is deliberately no system-wide default.

## Container

```toml
[container]
name = "debian-dev"
rootfs = "./rootfs"
hostname = "debian-dev"
init = "/sbin/init"
foreground = false
volatile = false
network = "host"
```

Configure exactly one of `rootfs` or `rootfs_image`. A missing `uuid` is
generated on first use and atomically written back to the TOML file.
`volatile = true` places writable OverlayFS layers on tmpfs.

Names may contain ASCII letters, digits, `.`, `_`, and `-`. The values
`.` and `..` are rejected.

## Networking

Network modes are `host`, `none`, `nat`, and `gateway`.

```toml
[container.network_options]
address = "172.28.0.2"
gateway = "172.28.0.1"
prefix = 16
bridge = "gnosis-br0"
gateway_bridge = ""
dns = ["1.1.1.1", "8.8.8.8"]

[[container.network_options.ports]]
host = 8080
container = 80
protocol = "tcp"
```

NAT and bridge setup currently use fixed host `ip` and `iptables`
executables. `gateway` attaches the container veth to the existing interface
named by `gateway_bridge`. It does not create or manage that bridge.

## Resources and security

```toml
[container.resources]
memory_bytes = 536870912
cpu_quota = 100000
cpu_period = 100000
pids = 512

[container.security]
read_only_sys = true
allow_user_namespaces = false
```

Resource limits require cgroup v2. Memory must be at least 4 MiB. CPU quota and
period must be configured together; quota must be at least 1000. The PID limit
must be between 1 and 4194304.

## Environment and mounts

```toml
[container]
environment_file = "./container.env"

[container.environment]
LANG = "C.UTF-8"

[[container.mounts]]
source = "./shared"
target = "/mnt/shared"
read_only = false
```

Environment files accept `KEY=VALUE`, optional `export`, comments, quoted
values, empty values, and values containing `=`. Inline values win over file
values. Mount sources must exist, and targets must be absolute, non-root paths
without parent traversal.

## Android host integration

The optional `[container.android]` table controls selected storage, GPU,
Binder, Termux:X11, VirGL, PulseAudio, and SELinux integration when gnosis is
built for Android. These options fail closed on unsupported hosts. They are
runtime features and do not require or provide an Android application.
