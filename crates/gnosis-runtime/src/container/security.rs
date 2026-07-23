use std::{collections::HashSet, path::Path};

use anyhow::{Context, Result};
use caps::{CapSet, Capability};
use gnosis_config::SecurityConfig;
use nix::mount::{MsFlags, mount};

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARG0_OFFSET: u32 = 16;

pub fn harden_mounts(config: &SecurityConfig) -> Result<()> {
    if config.read_only_sys {
        mount::<str, str, str, str>(
            None,
            "/sys",
            None,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None,
        )
        .context("failed to make /sys read-only")?;
    }
    mount(
        Some("/proc/sys"),
        "/proc/sys",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("failed to bind /proc/sys for hardening")?;
    mount::<str, str, str, str>(
        None,
        "/proc/sys",
        None,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None,
    )
    .context("failed to make /proc/sys read-only")?;
    for path in [
        "/proc/kcore",
        "/proc/keys",
        "/proc/timer_list",
        "/proc/sysrq-trigger",
        "/sys/kernel/debug",
        "/sys/kernel/tracing",
    ] {
        let target = Path::new(path);
        if !target.exists() {
            continue;
        }
        if target.is_dir() {
            mount(
                Some("tmpfs"),
                path,
                Some("tmpfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                Some("size=4k"),
            )
            .with_context(|| format!("failed to mask {path}"))?;
        } else {
            mount(
                Some("/dev/null"),
                path,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .with_context(|| format!("failed to mask {path}"))?;
            mount::<str, str, str, str>(
                None,
                path,
                None,
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                None,
            )
            .with_context(|| format!("failed to make mask read-only for {path}"))?;
        }
    }
    Ok(())
}

pub fn drop_dangerous_capabilities() -> Result<()> {
    let dangerous = HashSet::from([
        Capability::CAP_SYS_MODULE,
        Capability::CAP_SYS_RAWIO,
        Capability::CAP_SYS_PTRACE,
        // CAP_SYS_BOOT is intentionally retained for reboot(2) in the PID namespace.
        Capability::CAP_MAC_ADMIN,
        Capability::CAP_MAC_OVERRIDE,
        Capability::CAP_AUDIT_CONTROL,
        Capability::CAP_AUDIT_READ,
        Capability::CAP_DAC_READ_SEARCH,
        Capability::CAP_BLOCK_SUSPEND,
        Capability::CAP_WAKE_ALARM,
    ]);
    for capability in &dangerous {
        caps::drop(None, CapSet::Bounding, *capability)
            .with_context(|| format!("failed to drop {capability:?} from bounding set"))?;
    }
    for set in [
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
        CapSet::Ambient,
    ] {
        let mut current = caps::read(None, set)?;
        current.retain(|capability| !dangerous.contains(capability));
        caps::set(None, set, &current)?;
    }
    Ok(())
}

#[allow(unsafe_code)]
#[allow(clippy::too_many_lines)]
pub fn install_seccomp(config: &SecurityConfig) -> Result<()> {
    let mut blocked = vec![
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_settimeofday,
        libc::SYS_adjtimex,
        libc::SYS_clock_settime,
        libc::SYS_clock_adjtime,
    ];
    #[cfg(all(
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        ),
        not(target_os = "android")
    ))]
    blocked.push(libc::SYS_kexec_file_load);

    let mut instructions = vec![
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
        jump(BPF_JMP_JEQ_K, audit_arch(), 1, 0),
        statement(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
    ];
    #[cfg(target_arch = "x86_64")]
    instructions.extend([
        jump(BPF_JMP_JSET_K, 0x4000_0000, 0, 1),
        statement(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS),
    ]);
    for syscall in blocked {
        instructions.push(jump(
            BPF_JMP_JEQ_K,
            u32::try_from(syscall).context("invalid syscall number")?,
            0,
            1,
        ));
        instructions.push(statement(
            BPF_RET_K,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
    }
    if !config.allow_user_namespaces {
        instructions.extend([
            statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
            jump(
                BPF_JMP_JEQ_K,
                u32::try_from(libc::SYS_unshare).context("invalid unshare syscall number")?,
                0,
                3,
            ),
            statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG0_OFFSET),
            jump(
                BPF_JMP_JSET_K,
                u32::try_from(libc::CLONE_NEWUSER).context("invalid CLONE_NEWUSER flag")?,
                0,
                1,
            ),
            statement(BPF_RET_K, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
            statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        ]);
        instructions.push(jump(
            BPF_JMP_JEQ_K,
            u32::try_from(libc::SYS_clone).context("invalid clone syscall number")?,
            0,
            3,
        ));
        instructions.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG0_OFFSET));
        instructions.push(jump(
            BPF_JMP_JSET_K,
            u32::try_from(libc::CLONE_NEWUSER).context("invalid CLONE_NEWUSER flag")?,
            0,
            1,
        ));
        instructions.push(statement(
            BPF_RET_K,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        ))]
        instructions.extend([
            statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
            jump(
                BPF_JMP_JEQ_K,
                u32::try_from(libc::SYS_clone3).context("invalid clone3 syscall number")?,
                0,
                1,
            ),
            statement(BPF_RET_K, libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
        ]);
    }
    instructions.extend([
        statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        jump(
            BPF_JMP_JEQ_K,
            u32::try_from(libc::SYS_socket).context("invalid socket syscall number")?,
            0,
            3,
        ),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG0_OFFSET),
        jump(BPF_JMP_JEQ_K, libc::AF_ALG as u32, 0, 1),
        statement(BPF_RET_K, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ]);
    instructions.push(statement(BPF_RET_K, libc::SECCOMP_RET_ALLOW));
    let program = libc::sock_fprog {
        len: u16::try_from(instructions.len()).context("seccomp program is too large")?,
        filter: instructions.as_mut_ptr(),
    };
    // SAFETY: program points to a live, initialized BPF instruction array for the duration of prctl.
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &raw const program,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("failed to install seccomp filter");
    }
    Ok(())
}

const fn audit_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    return 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    return 0xc000_00b7;
    #[cfg(target_arch = "riscv64")]
    return 0xc000_00f3;
    #[cfg(target_arch = "x86")]
    return 0x4000_0003;
    #[cfg(target_arch = "arm")]
    return 0x4000_0028;
    #[allow(unreachable_code)]
    0
}

const fn statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn jump(code: u16, value: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt,
        jf,
        k: value,
    }
}
