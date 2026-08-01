# CLI usage

KurumiContainerd manages one configured container per invocation. Use separate TOML
files for multiple containers and point them at the same protected runtime
work directory when shared listing and recovery are required.

## Invocation

```text
kurumi-containerd [--config PATH] COMMAND
```

The config path defaults to `kurumi-containerd.toml`. `KURUMI_CONTAINERD_CONFIG` provides the
same value through the environment. `check` is the only command that does not
load a configuration.

Most operations require root because they create namespaces, mounts, devices,
cgroups, and network interfaces.

## Install a local rootfs

`install` accepts only a local archive. It never downloads a rootfs or accepts
a registry or URL source. Supported content formats are tar, gzip-compressed
tar, XZ-compressed tar, Zstandard-compressed tar, and ZIP. The format is
detected from the file header rather than its name or extension.

For a configured directory target:

```bash
sudo kurumi-containerd --config debian.toml install ./debian-rootfs.tar.zst
```

For `container.rootfs_image`, provide the logical size of the new sparse ext4
image. Binary suffixes such as `M`, `G`, `MiB`, and `GiB` are accepted:

```bash
sudo kurumi-containerd --config debian-image.toml install ./debian-rootfs.tar.zst --size 8G
```

An existing target is rejected unless `--force` is supplied. Replacement is
staged and renamed only after extraction and init validation complete. The
container must be stopped. Image installation additionally requires
`mke2fs` or `mkfs.ext4`, loop devices, and mount privileges.

Archive paths are installed directly at the rootfs top level, so `sbin/init`
must not be wrapped in an extra distribution directory. ZIP cannot preserve
UID/GID and device nodes reliably; tar is recommended for system rootfs
archives. `--size` is required for image targets and rejected for directory
targets.

## Lifecycle

```bash
sudo kurumi-containerd --config debian.toml start
sudo kurumi-containerd --config debian.toml start --foreground
sudo kurumi-containerd --config debian.toml restart
sudo kurumi-containerd --config debian.toml stop
```

Background start detaches a monitor process. Foreground start connects the
container console to the current terminal. In a foreground console,
`Escape` followed by `Ctrl-Q` requests shutdown.

Stop selects a shutdown protocol from the detected init family and escalates
after `runtime.stop_timeout_seconds`.

## Enter and run

```bash
sudo kurumi-containerd --config debian.toml enter
sudo kurumi-containerd --config debian.toml enter developer
sudo kurumi-containerd --config debian.toml run uname -a
sudo kurumi-containerd --config debian.toml run sh -c 'id && mount'
```

`enter` opens an interactive login and defaults to `root`. `run` executes
the remaining arguments directly; use a shell explicitly for pipes,
redirection, or compound commands.

## Inspect and recover

```bash
sudo kurumi-containerd --config debian.toml info
sudo kurumi-containerd --config debian.toml pid
sudo kurumi-containerd --config debian.toml show
sudo kurumi-containerd --config debian.toml scan
```

`show` reads live states from the configured work directory. `scan` searches
procfs for namespace PID 1 processes and reconstructs missing state only when
the in-container identity and root-owned recovery record agree.

`info` prints container identity, init and monitor PIDs, init system, uptime,
memory use, process count, generation, rootfs, and UUID.

## Host checks

```bash
sudo kurumi-containerd check
```

The check command probes mount, PID, UTS, IPC, and network namespaces, then
reports OverlayFS, cgroup v2, pidfd, `ip`, and `iptables` availability. A
failed mandatory namespace probe returns an error.
