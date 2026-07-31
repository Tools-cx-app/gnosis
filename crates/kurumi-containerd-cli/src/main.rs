use std::{
    io::{self, IsTerminal},
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use kurumi_containerd_config::Config;
use kurumi_containerd_helper::{ForkResult, NamespaceFlags, WaitStatus, fork, unshare, waitpid};
use kurumi_containerd_runtime::{ContainerInfo, ContainerState, Runtime};
use tracing::level_filters::LevelFilter;

#[derive(Debug, Parser)]
#[command(version, about = "Privileged Linux container runtime")]
struct Cli {
    /// TOML configuration file. Relative host paths are resolved from this file.
    #[arg(
        short,
        long,
        env = "KURUMI_CONTAINERD_CONFIG",
        default_value = "kurumi-containerd.toml"
    )]
    config: PathBuf,
    /// Logger verbose
    #[arg(short, long, default_value = "true")]
    verbose: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the configured container.
    Start {
        /// Attach the container console to this terminal.
        #[arg(short, long)]
        foreground: bool,
    },
    /// Stop the configured container.
    Stop,
    /// Restart the configured container.
    Restart {
        /// Attach the container console to this terminal.
        #[arg(short, long)]
        foreground: bool,
    },
    /// Open an interactive login in the container.
    Enter {
        /// Login user.
        #[arg(default_value = "root")]
        user: String,
    },
    /// Run a command in the container.
    #[command(visible_alias = "exec")]
    Run {
        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Show container status and resource usage.
    Info,
    /// Print the container init PID.
    Pid,
    /// List running containers.
    Show,
    /// Recover validated running containers.
    Scan,
    /// Check host capabilities.
    Check,
}

fn main() -> Result<()> {
    let cli: Cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_max_level(if cli.verbose {
            LevelFilter::DEBUG
        } else {
            LevelFilter::INFO
        })
        .with_target(false)
        .with_ansi(io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none())
        .init();
    if matches!(cli.command, Commands::Check) {
        return check();
    }
    let config = Config::load_persistent(&cli.config)?;
    let container_name = config.container.name.clone();
    let runtime = Runtime::new(config);
    match cli.command {
        Commands::Start { foreground } => {
            let state = runtime.start(foreground)?;
            log_started(&state);
        }
        Commands::Stop => {
            runtime.stop()?;
            tracing::info!(container = container_name, "container stopped");
        }
        Commands::Restart { foreground } => {
            let state = runtime.restart(foreground)?;
            log_started(&state);
        }
        Commands::Enter { user } => runtime.enter(&user)?,
        Commands::Run { command } => runtime.run(&command)?,
        Commands::Info => log_info(&runtime.info()?),
        Commands::Pid => tracing::info!(pid = runtime.pid()?, "container PID"),
        Commands::Show => log_containers(&runtime.list()?),
        Commands::Scan => {
            let states = runtime.scan()?;
            log_recovered(&states);
        }
        Commands::Check => unreachable!("check is handled before loading configuration"),
    }
    Ok(())
}

fn check() -> Result<()> {
    tracing::info!(host = std::env::consts::OS, "checking host capabilities");
    let namespaces = [
        probe_namespace(NamespaceFlags::MOUNT),
        probe_namespace(NamespaceFlags::PID),
        probe_namespace(NamespaceFlags::UTS),
        probe_namespace(NamespaceFlags::IPC),
        probe_namespace(NamespaceFlags::NETWORK),
    ];
    let namespaces_available = namespaces.into_iter().all(|available| available);
    log_check(
        "Namespaces",
        namespaces_available,
        "mount, pid, uts, ipc, network",
    );
    log_check(
        "OverlayFS",
        std::fs::read_to_string("/proc/filesystems")?.contains("overlay"),
        "kernel filesystem",
    );
    let mountinfo = procfs::process::Process::myself()?.mountinfo()?;
    log_check(
        "Cgroup v2",
        Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        "unified hierarchy",
    );
    log_check(
        "Cgroup v1",
        mountinfo.0.iter().any(|mount| mount.fs_type == "cgroup"),
        "legacy hierarchy",
    );
    log_check(
        "Pidfd",
        kurumi_containerd_runtime::pidfd_available(),
        "process handles",
    );
    log_command("ip");
    log_command("iptables");
    if !namespaces_available {
        bail!("one or more required namespaces are unavailable");
    }
    Ok(())
}

#[allow(unsafe_code)]
fn probe_namespace(flag: NamespaceFlags) -> bool {
    match unsafe { fork() } {
        Err(_) => false,
        Ok(ForkResult::Child) => {
            let code = i32::from(unshare(flag).is_err());
            std::process::exit(code);
        }
        Ok(ForkResult::Parent { child }) => {
            matches!(waitpid(child, false), Ok(WaitStatus::Exited(_, 0)))
        }
    }
}

fn log_started(state: &ContainerState) {
    tracing::info!(
        container = state.name,
        pid = state.init_pid,
        "container started"
    );
}

fn log_info(info: &ContainerInfo) {
    tracing::info!(
        container = info.name,
        active = info.active,
        init_pid = ?info.init_pid,
        monitor_pid = ?info.monitor_pid,
        rootfs = %info.rootfs.display(),
        uuid = ?info.uuid,
        init_system = ?info.init_system,
        generation = ?info.generation,
        uptime_seconds = ?info.uptime_seconds,
        memory_kb = ?info.memory_kb,
        processes = ?info.processes,
        "container info"
    );
}

fn log_containers(states: &[ContainerState]) {
    for state in states {
        tracing::info!(
            container = state.name,
            pid = state.init_pid,
            rootfs = %state.rootfs.display(),
            "running container"
        );
    }
    tracing::info!(count = states.len(), "containers listed");
}

fn log_recovered(states: &[ContainerState]) {
    if states.is_empty() {
        tracing::info!("no containers required recovery");
        return;
    }
    for state in states {
        tracing::info!(
            container = state.name,
            pid = state.init_pid,
            "container recovered"
        );
    }
    tracing::info!(count = states.len(), "container recovery completed");
}

fn log_check(capability: &str, available: bool, detail: &str) {
    tracing::info!(capability, available, detail, "host capability");
}

fn log_command(command: &str) {
    match which::which(command) {
        Ok(path) => log_check(command, true, &path.display().to_string()),
        Err(_) => log_check(command, false, "not found in PATH"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_command_has_help_text() {
        for command in Cli::command().get_subcommands() {
            assert!(
                command.get_about().is_some(),
                "{} has no help text",
                command.get_name()
            );
        }
    }

    #[test]
    fn exec_alias_parses_as_run() {
        let cli = Cli::try_parse_from(["kurumi-containerd", "exec", "sh", "-c", "true"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Run { command } if command == ["sh", "-c", "true"]
        ));
    }
}
