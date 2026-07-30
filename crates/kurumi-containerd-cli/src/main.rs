use std::{
    io::{self, IsTerminal},
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use kurumi_containerd_config::Config;
use kurumi_containerd_helper::{ForkResult, NamespaceFlags, WaitStatus, fork, unshare, waitpid};
use kurumi_containerd_runtime::{ContainerInfo, ContainerState, Runtime};

const GREEN: &str = "\x1b[1;32m";
const YELLOW: &str = "\x1b[1;33m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

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
    let cli = Cli::parse();
    if matches!(cli.command, Commands::Check) {
        return check();
    }
    let config = Config::load_persistent(&cli.config)?;
    let container_name = config.container.name.clone();
    let runtime = Runtime::new(config);
    match cli.command {
        Commands::Start { foreground } => {
            let state = runtime.start(foreground)?;
            print_started(&state);
        }
        Commands::Stop => {
            runtime.stop()?;
            println!("Stopped {container_name}.");
        }
        Commands::Restart { foreground } => {
            let state = runtime.restart(foreground)?;
            print_started(&state);
        }
        Commands::Enter { user } => runtime.enter(&user)?,
        Commands::Run { command } => runtime.run(&command)?,
        Commands::Info => print_info(&runtime.info()?),
        Commands::Pid => println!("{}", runtime.pid()?),
        Commands::Show => print_containers(&runtime.list()?),
        Commands::Scan => {
            let states = runtime.scan()?;
            print_recovered(&states);
        }
        Commands::Check => unreachable!("check is handled before loading configuration"),
    }
    Ok(())
}

fn check() -> Result<()> {
    println!(
        "{}KurumiContainerd host capabilities{}",
        style(BOLD),
        style(RESET)
    );
    println!("{:>12}: {}", "Host", std::env::consts::OS);
    let namespaces = [
        probe_namespace(NamespaceFlags::MOUNT),
        probe_namespace(NamespaceFlags::PID),
        probe_namespace(NamespaceFlags::UTS),
        probe_namespace(NamespaceFlags::IPC),
        probe_namespace(NamespaceFlags::NETWORK),
    ];
    let namespaces_available = namespaces.into_iter().all(|available| available);
    print_check(
        "Namespaces",
        namespaces_available,
        "mount, pid, uts, ipc, network",
    );
    print_check(
        "OverlayFS",
        std::fs::read_to_string("/proc/filesystems")?.contains("overlay"),
        "kernel filesystem",
    );
    let mountinfo = procfs::process::Process::myself()?.mountinfo()?;
    print_check(
        "Cgroup v2",
        Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        "unified hierarchy",
    );
    print_check(
        "Cgroup v1",
        mountinfo.0.iter().any(|mount| mount.fs_type == "cgroup"),
        "legacy hierarchy",
    );
    print_check(
        "Pidfd",
        kurumi_containerd_runtime::pidfd_available(),
        "process handles",
    );
    print_command("ip");
    print_command("iptables");
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

fn print_started(state: &ContainerState) {
    println!(
        "{}{}{} Started {}.",
        style(GREEN),
        marker(),
        style(RESET),
        state.name
    );
    println!("{:>12}: active (running)", "Active");
    println!("{:>12}: {}", "Main PID", state.init_pid);
}

fn print_info(info: &ContainerInfo) {
    let color = if info.active { GREEN } else { YELLOW };
    println!(
        "{}{}{} {}",
        style(color),
        status_marker(info.active),
        style(RESET),
        info.name
    );
    let rendered = info.to_string();
    if let Some((_, details)) = rendered.split_once('\n') {
        println!("{details}");
    }
}

fn print_containers(states: &[ContainerState]) {
    let name_width = states
        .iter()
        .map(|state| state.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    println!(
        "  {:<name_width$} {:>8} {:<10} ROOTFS",
        "NAME", "PID", "STATE"
    );
    for state in states {
        println!(
            "{}{}{} {:<name_width$} {:>8} {:<10} {}",
            style(GREEN),
            marker(),
            style(RESET),
            state.name,
            state.init_pid,
            "running",
            state.rootfs.display()
        );
    }
    println!();
    println!(
        "{} container{} listed.",
        states.len(),
        if states.len() == 1 { "" } else { "s" }
    );
}

fn print_recovered(states: &[ContainerState]) {
    if states.is_empty() {
        println!("No containers required recovery.");
        return;
    }
    for state in states {
        println!(
            "{}{}{} Recovered {} (PID {}).",
            style(GREEN),
            marker(),
            style(RESET),
            state.name,
            state.init_pid
        );
    }
    println!();
    println!(
        "Recovered {} container{}.",
        states.len(),
        if states.len() == 1 { "" } else { "s" }
    );
}

fn print_check(label: &str, available: bool, detail: &str) {
    let (color, status) = if available {
        (GREEN, "available")
    } else {
        (YELLOW, "unavailable")
    };
    println!(
        "{:>12}: {}{}{} ({detail})",
        label,
        style(color),
        status,
        style(RESET)
    );
}

fn print_command(command: &str) {
    match which::which(command) {
        Ok(path) => print_check(command, true, &path.display().to_string()),
        Err(_) => print_check(command, false, "not found in PATH"),
    }
}

fn marker() -> &'static str {
    if io::stdout().is_terminal() {
        "●"
    } else {
        "*"
    }
}

fn status_marker(active: bool) -> &'static str {
    if active {
        marker()
    } else if io::stdout().is_terminal() {
        "○"
    } else {
        "o"
    }
}

fn style(code: &'static str) -> &'static str {
    if io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() {
        code
    } else {
        ""
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
