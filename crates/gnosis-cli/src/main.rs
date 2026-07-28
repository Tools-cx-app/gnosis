use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use gnosis_config::Config;
use gnosis_helper::{ForkResult, NamespaceFlags, WaitStatus, fork, unshare, waitpid};
use gnosis_runtime::Runtime;

#[derive(Debug, Parser)]
#[command(version, about = "Privileged Linux container runtime")]
struct Cli {
    /// TOML configuration file. Relative host paths are resolved from this file.
    #[arg(short, long, env = "GNOSIS_CONFIG", default_value = "gnosis.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Start {
        #[arg(short, long)]
        foreground: bool,
    },
    Stop,
    Restart {
        #[arg(short, long)]
        foreground: bool,
    },
    Enter {
        #[arg(default_value = "root")]
        user: String,
    },
    Run {
        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },
    Info,
    Pid,
    Show,
    Scan,
    Check,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if matches!(cli.command, Commands::Check) {
        return check();
    }
    let config = Config::load_persistent(&cli.config)?;
    let runtime = Runtime::new(config);
    match cli.command {
        Commands::Start { foreground } => {
            let state = runtime.start(foreground)?;
            println!("{}\t{}", state.name, state.init_pid);
        }
        Commands::Stop => runtime.stop()?,
        Commands::Restart { foreground } => {
            let state = runtime.restart(foreground)?;
            println!("{}\t{}", state.name, state.init_pid);
        }
        Commands::Enter { user } => runtime.enter(&user)?,
        Commands::Run { command } => runtime.run(&command)?,
        Commands::Info => println!("{}", runtime.info()?),
        Commands::Pid => println!("{}", runtime.pid()?),
        Commands::Show => {
            println!("NAME\tPID\tROOTFS");
            for state in runtime.list()? {
                println!(
                    "{}\t{}\t{}",
                    state.name,
                    state.init_pid,
                    state.rootfs.display()
                );
            }
        }
        Commands::Scan => {
            let states = runtime.scan()?;
            println!("RECOVERED={}", states.len());
            for state in states {
                println!("RUNNING={} PID={}", state.name, state.init_pid);
            }
        }
        Commands::Check => unreachable!("check is handled before loading configuration"),
    }
    Ok(())
}

fn check() -> Result<()> {
    probe_namespace(NamespaceFlags::MOUNT, "mount")?;
    probe_namespace(NamespaceFlags::PID, "PID")?;
    probe_namespace(NamespaceFlags::UTS, "UTS")?;
    probe_namespace(NamespaceFlags::IPC, "IPC")?;
    probe_namespace(NamespaceFlags::NETWORK, "network")?;
    println!(
        "overlayfs: {}",
        std::fs::read_to_string("/proc/filesystems")?.contains("overlay")
    );
    println!(
        "cgroup v2: {}",
        std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
    );
    println!("pidfd: {}", gnosis_runtime::pidfd_available());
    println!("ip command: {}", system_command_exists("ip"));
    println!("iptables command: {}", system_command_exists("iptables"));
    Ok(())
}

#[allow(unsafe_code)]
fn probe_namespace(flag: NamespaceFlags, name: &str) -> Result<()> {
    match unsafe { fork() }? {
        ForkResult::Child => {
            let code = i32::from(unshare(flag).is_err());
            std::process::exit(code);
        }
        ForkResult::Parent { child } => {
            let status = waitpid(child, false)?;
            ensure!(
                matches!(status, WaitStatus::Exited(_, 0)),
                "{name} namespace probe failed"
            );
            println!("{name} namespace: available");
        }
    }
    Ok(())
}

fn system_command_exists(program: &str) -> bool {
    ["/system/bin", "/usr/sbin", "/sbin", "/usr/bin", "/bin"]
        .into_iter()
        .any(|directory| std::path::Path::new(directory).join(program).is_file())
}
