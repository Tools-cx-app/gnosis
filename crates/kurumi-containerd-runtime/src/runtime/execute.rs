use std::{collections::BTreeMap, ffi::CString, fs, os::fd::AsFd, path::Path};

use anyhow::{Context, Result, bail, ensure};
use kurumi_containerd_config::{AndroidConfig, NetworkMode};
use kurumi_containerd_helper::{
    process::{
        ForkResult, NamespaceFlags, WaitStatus, chdir, chroot, close_fds_except, current_pid,
        execve, fchdir, fork, init_groups, set_gid, set_uid, setns, waitpid,
    },
    signal::{Signal, kill, kill_process_group},
    terminal::socket_pair,
};
use procfs::process::Process;

use crate::{
    Runtime,
    container::{environment, security},
    host::{cgroup::Cgroup, terminal},
    runtime::state::validate_process_identity_for,
};

impl Runtime {
    /// Opens an interactive login session inside the container.
    ///
    /// # Errors
    ///
    /// Returns an error when the user is invalid, the container is stopped, or
    /// an interactive login shell cannot be executed.
    pub fn enter(&self, user: &str) -> Result<()> {
        ensure!(valid_login_name(user), "invalid login user name");
        self.execute(&[], Some(user))
    }

    /// Executes a command inside the container namespaces.
    ///
    /// # Errors
    ///
    /// Returns an error when the container is stopped, namespaces cannot be
    /// joined, or the command exits unsuccessfully.
    pub fn run(&self, command: &[String]) -> Result<()> {
        ensure!(!command.is_empty(), "no command specified");
        self.execute(command, None)
    }

    #[allow(unsafe_code)]
    #[allow(clippy::too_many_lines)]
    fn execute(&self, command: &[String], login_user: Option<&str>) -> Result<()> {
        Self::ensure_root()?;
        let lock = self.lock()?;
        let state = self.require_state()?;
        let process = Process::new(state.init_pid).context("failed to open container process")?;
        ensure!(
            validate_process_identity_for(&state, &process),
            "container init identity changed before namespace capture"
        );
        let root = process
            .open_relative("root")
            .context("failed to open container root")?;
        let namespaces = ["mnt", "uts", "ipc", "pid"]
            .into_iter()
            .chain((self.config.container.network != NetworkMode::Host).then_some("net"))
            .map(|name| {
                process
                    .open_relative(Path::new("ns").join(name))
                    .map(|file| (name, file))
            })
            .collect::<procfs::ProcResult<Vec<_>>>()?;
        let terminal_socket = login_user
            .is_some()
            .then(socket_pair)
            .transpose()
            .context("failed to create interactive PTY channel")?;
        drop(lock);

        // SAFETY: the CLI is single-threaded; the child immediately joins namespaces and forks again.
        match unsafe { fork() }.context("failed to fork command worker")? {
            ForkResult::Parent { child } => {
                let status = if let Some((receiver, sender)) = terminal_socket {
                    drop(sender);
                    let master = match terminal::receive_fd(&receiver) {
                        Ok(master) => master,
                        Err(error) => {
                            terminate_and_reap(child);
                            return Err(error);
                        }
                    };
                    drop(receiver);
                    terminal::proxy(&master, child, None)
                } else {
                    waitpid(child, false).context("failed waiting for command")
                };
                let status = match status {
                    Ok(status) => status,
                    Err(error) => {
                        terminate_session_and_reap(child);
                        return Err(error);
                    }
                };
                command_status(status)
            }
            ForkResult::Child => {
                let terminal_sender = terminal_socket.map(|(receiver, sender)| {
                    drop(receiver);
                    sender
                });
                for (name, namespace) in &namespaces {
                    setns(namespace.as_fd(), NamespaceFlags::EMPTY).unwrap_or_else(|error| {
                        exec_failure(&format!("failed to join {name} namespace: {error}"))
                    });
                }
                let cgroup = Cgroup::create(
                    &self.workdir,
                    &self.config.container.name,
                    &self.config.container.resources,
                    false,
                    false,
                )
                .unwrap_or_else(|error| exec_failure(&error.to_string()));
                cgroup
                    .attach(current_pid())
                    .unwrap_or_else(|error| exec_failure(&error.to_string()));
                let console = terminal_sender.map(|sender| {
                    let console = terminal::Console::open()
                        .unwrap_or_else(|error| exec_failure(&error.to_string()));
                    let slave = console
                        .open_slave()
                        .unwrap_or_else(|error| exec_failure(&error.to_string()));
                    terminal::configure_child(&slave)
                        .unwrap_or_else(|error| exec_failure(&error.to_string()));
                    terminal::ignore_hangup()
                        .unwrap_or_else(|error| exec_failure(&error.to_string()));
                    terminal::send_fd(&sender, &console.master)
                        .unwrap_or_else(|error| exec_failure(&error.to_string()));
                    drop(sender);
                    drop(console.master);
                    slave
                });
                security::install_seccomp(&self.config.container.security)
                    .unwrap_or_else(|error| exec_failure(&error.to_string()));
                // A child created after setns(CLONE_NEWPID) enters the target PID namespace.
                match unsafe { fork() }.unwrap_or_else(|error| {
                    exec_failure(&format!("failed to enter PID namespace: {error}"))
                }) {
                    ForkResult::Parent { child } => match waitpid(child, false) {
                        Ok(WaitStatus::Exited(_, code)) => std::process::exit(code),
                        Ok(WaitStatus::Signaled(_, signal, _)) => {
                            std::process::exit(128 + signal.raw())
                        }
                        _ => std::process::exit(125),
                    },
                    ForkResult::Child => {
                        drop(console);
                        result_or_exit(fchdir(&root));
                        result_or_exit(chroot("."));
                        result_or_exit(chdir("/"));
                        // SAFETY: this is the single-threaded command child and every
                        // subsequent path exits directly without unwinding descriptor owners.
                        #[allow(unsafe_code)]
                        result_or_exit(unsafe { close_fds_except(&[]) });
                        if let Some(user) = login_user {
                            exec_login(
                                user,
                                &self.config.container.environment,
                                &self.config.container.android,
                            );
                        }
                        let mut resolved = command.to_vec();
                        if !resolved[0].contains('/') {
                            resolved[0] =
                                resolve_container_command(&resolved[0]).unwrap_or_else(|| {
                                    exec_failure("command was not found in container PATH")
                                });
                        }
                        let args = resolved
                            .iter()
                            .map(|arg| CString::new(arg.as_str()))
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap_or_else(|error| exec_failure(&error.to_string()));
                        let env = command_environment(
                            &self.config.container.environment,
                            &self.config.container.android,
                        );
                        let error = execve(&args[0], &args, &env).unwrap_err();
                        exec_failure(&error.to_string());
                    }
                }
            }
        }
    }
}

fn command_status(status: WaitStatus) -> Result<()> {
    match status {
        WaitStatus::Exited(_, 0) => Ok(()),
        WaitStatus::Exited(_, code) => bail!("command exited with status {code}"),
        WaitStatus::Signaled(_, signal, _) => {
            bail!("command terminated by {}", signal.name())
        }
        status => bail!("unexpected command status: {status:?}"),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PasswdEntry {
    uid: u32,
    gid: u32,
    home: String,
    shell: String,
}

fn exec_login(user: &str, configured: &BTreeMap<String, String>, android: &AndroidConfig) -> ! {
    let base_env = command_environment(configured, android);
    for su in ["/bin/su", "/usr/bin/su", "/run/wrappers/bin/su"] {
        if Path::new(su).is_file() {
            let executable = result_or_exit(CString::new(su));
            let arguments = [
                result_or_exit(CString::new("su")),
                result_or_exit(CString::new("-l")),
                result_or_exit(CString::new(user)),
            ];
            let _ = execve(&executable, &arguments, &base_env);
        }
    }
    let source = fs::read_to_string("/etc/passwd")
        .unwrap_or_else(|error| exec_failure(&format!("failed to read /etc/passwd: {error}")));
    let account = parse_passwd(&source, user)
        .unwrap_or_else(|| exec_failure(&format!("login user '{user}' was not found")));
    if !account.shell.starts_with('/') || !Path::new(&account.shell).is_file() {
        exec_failure("login user has no usable absolute shell");
    }
    let user_name = result_or_exit(CString::new(user));
    result_or_exit(init_groups(&user_name, account.gid));
    result_or_exit(set_gid(account.gid));
    result_or_exit(set_uid(account.uid));
    result_or_exit(chdir(Path::new(&account.home)));
    let shell = result_or_exit(CString::new(account.shell.as_str()));
    let shell_name = Path::new(&account.shell)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sh");
    let arguments = [
        result_or_exit(CString::new(shell_name)),
        result_or_exit(CString::new("-l")),
    ];
    let mut environment = base_env;
    replace_environment(&mut environment, "HOME", &account.home);
    replace_environment(&mut environment, "USER", user);
    replace_environment(&mut environment, "LOGNAME", user);
    replace_environment(&mut environment, "SHELL", &account.shell);
    let error = execve(&shell, &arguments, &environment).unwrap_err();
    exec_failure(&format!("failed to execute login shell: {error}"));
}

fn replace_environment(environment: &mut Vec<CString>, key: &str, value: &str) {
    let prefix = format!("{key}=");
    environment.retain(|entry| !entry.to_bytes().starts_with(prefix.as_bytes()));
    environment.push(result_or_exit(CString::new(format!("{key}={value}"))));
}

fn command_environment(
    configured: &BTreeMap<String, String>,
    android: &AndroidConfig,
) -> Vec<CString> {
    result_or_exit(environment::session_environment(configured, android))
}

fn parse_passwd(source: &str, user: &str) -> Option<PasswdEntry> {
    source.lines().find_map(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 7 || fields[0] != user {
            return None;
        }
        Some(PasswdEntry {
            uid: fields[2].parse().ok()?,
            gid: fields[3].parse().ok()?,
            home: fields[5].to_owned(),
            shell: fields[6].to_owned(),
        })
    })
}

fn valid_login_name(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 256
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn terminate_and_reap(child: i32) {
    let _ = kill(child, Signal::Kill);
    let _ = waitpid(child, false);
}

fn terminate_session_and_reap(child: i32) {
    let _ = kill_process_group(child, Signal::Kill);
    terminate_and_reap(child);
}

fn exec_failure(message: &str) -> ! {
    tracing::error!("exec failed: {message}");
    std::process::exit(126)
}

fn result_or_exit<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| exec_failure(&error.to_string()))
}

fn resolve_container_command(command: &str) -> Option<String> {
    [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ]
    .into_iter()
    .map(|directory| format!("{directory}/{command}"))
    .find(|candidate| Path::new(candidate).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_login_account() {
        let source = "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/sh\n";
        assert_eq!(
            parse_passwd(source, "user"),
            Some(PasswdEntry {
                uid: 1000,
                gid: 1000,
                home: "/home/user".to_owned(),
                shell: "/bin/sh".to_owned()
            })
        );
        assert_eq!(parse_passwd(source, "missing"), None);
    }

    #[test]
    fn rejects_unsafe_login_names() {
        assert!(valid_login_name("root"));
        assert!(valid_login_name("service-user_1"));
        assert!(!valid_login_name(""));
        assert!(!valid_login_name("../../root"));
        assert!(!valid_login_name("user:name"));
    }
}
