# CLI usage

gnosis manages one configured container per invocation. Use separate TOML
files for multiple containers and point them at the same protected runtime
work directory when shared listing and recovery are required.

## Invocation

```text
gnosis [--config PATH] COMMAND
```

The config path defaults to `gnosis.toml`. `GNOSIS_CONFIG` provides the
same value through the environment. `check` is the only command that does not
load a configuration.

Most operations require root because they create namespaces, mounts, devices,
cgroups, and network interfaces.

## Lifecycle

```bash
sudo gnosis --config debian.toml start
sudo gnosis --config debian.toml start --foreground
sudo gnosis --config debian.toml restart
sudo gnosis --config debian.toml stop
```

Background start detaches a monitor process. Foreground start connects the
container console to the current terminal. In a foreground console,
`Escape` followed by `Ctrl-Q` requests shutdown.

Stop selects a shutdown protocol from the detected init family and escalates
after `runtime.stop_timeout_seconds`.

## Enter and run

```bash
sudo gnosis --config debian.toml enter
sudo gnosis --config debian.toml enter developer
sudo gnosis --config debian.toml run uname -a
sudo gnosis --config debian.toml run sh -c 'id && mount'
```

`enter` opens an interactive login and defaults to `root`. `run` executes
the remaining arguments directly; use a shell explicitly for pipes,
redirection, or compound commands.

## Inspect and recover

```bash
sudo gnosis --config debian.toml info
sudo gnosis --config debian.toml pid
sudo gnosis --config debian.toml usage
sudo gnosis --config debian.toml show
sudo gnosis --config debian.toml scan
```

`show` reads live states from the configured work directory. `scan` searches
procfs for namespace PID 1 processes and reconstructs missing state only when
the in-container identity and root-owned recovery record agree.

`usage` prints human-readable key/value lines for uptime, memory, and process
counts.

## Host checks

```bash
sudo gnosis check
```

The check command probes mount, PID, UTS, IPC, and network namespaces, then
reports OverlayFS, cgroup v2, pidfd, `ip`, and `iptables` availability. A
failed mandatory namespace probe returns an error.
