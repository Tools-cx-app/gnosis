use std::path::Path;

use anyhow::{Context, Result};
use gnosis_config::SecurityConfig;
use gnosis_helper::{
    ADDRESS_FAMILY_ALG, FilterInstruction, MountFlags, SECCOMP_ALLOW, SECCOMP_ERRNO_PERMISSION,
    SECCOMP_KILL_PROCESS, blocked_syscalls, install_seccomp as install_seccomp_filter, mount,
    namespace_user_flag, syscall_clone, syscall_socket, syscall_unshare,
};

#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
))]
use gnosis_helper::{SECCOMP_ERRNO_NOT_IMPLEMENTED, syscall_clone3};

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARG0_OFFSET: u32 = 16;

pub fn harden_mounts(config: &SecurityConfig) -> Result<()> {
    if config.read_only_sys {
        mount(
            None,
            Path::new("/sys"),
            None,
            MountFlags::BIND | MountFlags::REMOUNT | MountFlags::RDONLY,
            None,
        )
        .context("failed to make /sys read-only")?;
    }
    mount(
        Some(Path::new("/proc/sys")),
        Path::new("/proc/sys"),
        None,
        MountFlags::BIND,
        None,
    )
    .context("failed to bind /proc/sys for hardening")?;
    mount(
        None,
        Path::new("/proc/sys"),
        None,
        MountFlags::BIND | MountFlags::REMOUNT | MountFlags::RDONLY,
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
                Some(Path::new("tmpfs")),
                target,
                Some("tmpfs"),
                MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                Some("size=4k"),
            )
            .with_context(|| format!("failed to mask {path}"))?;
        } else {
            mount(
                Some(Path::new("/dev/null")),
                target,
                None,
                MountFlags::BIND,
                None,
            )
            .with_context(|| format!("failed to mask {path}"))?;
            mount(
                None,
                target,
                None,
                MountFlags::BIND | MountFlags::REMOUNT | MountFlags::RDONLY,
                None,
            )
            .with_context(|| format!("failed to make mask read-only for {path}"))?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub fn install_seccomp(config: &SecurityConfig) -> Result<()> {
    let blocked = blocked_syscalls();

    let mut instructions = vec![
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
        jump(BPF_JMP_JEQ_K, audit_arch(), 1, 0),
        statement(BPF_RET_K, SECCOMP_KILL_PROCESS),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
    ];
    #[cfg(target_arch = "x86_64")]
    instructions.extend([
        jump(BPF_JMP_JSET_K, 0x4000_0000, 0, 1),
        statement(BPF_RET_K, SECCOMP_KILL_PROCESS),
    ]);
    for syscall in blocked {
        instructions.push(jump(
            BPF_JMP_JEQ_K,
            u32::try_from(syscall).context("invalid syscall number")?,
            0,
            1,
        ));
        instructions.push(statement(BPF_RET_K, SECCOMP_ERRNO_PERMISSION));
    }
    if !config.allow_user_namespaces {
        instructions.extend([
            statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
            jump(
                BPF_JMP_JEQ_K,
                u32::try_from(syscall_unshare()).context("invalid unshare syscall number")?,
                0,
                3,
            ),
            statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG0_OFFSET),
            jump(BPF_JMP_JSET_K, namespace_user_flag(), 0, 1),
            statement(BPF_RET_K, SECCOMP_ERRNO_PERMISSION),
            statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        ]);
        instructions.push(jump(
            BPF_JMP_JEQ_K,
            u32::try_from(syscall_clone()).context("invalid clone syscall number")?,
            0,
            3,
        ));
        instructions.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG0_OFFSET));
        instructions.push(jump(BPF_JMP_JSET_K, namespace_user_flag(), 0, 1));
        instructions.push(statement(BPF_RET_K, SECCOMP_ERRNO_PERMISSION));
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        ))]
        instructions.extend([
            statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
            jump(
                BPF_JMP_JEQ_K,
                u32::try_from(syscall_clone3()).context("invalid clone3 syscall number")?,
                0,
                1,
            ),
            statement(BPF_RET_K, SECCOMP_ERRNO_NOT_IMPLEMENTED),
        ]);
    }
    instructions.extend([
        statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        jump(
            BPF_JMP_JEQ_K,
            u32::try_from(syscall_socket()).context("invalid socket syscall number")?,
            0,
            3,
        ),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG0_OFFSET),
        jump(BPF_JMP_JEQ_K, ADDRESS_FAMILY_ALG, 0, 1),
        statement(BPF_RET_K, SECCOMP_ERRNO_PERMISSION),
    ]);
    instructions.push(statement(BPF_RET_K, SECCOMP_ALLOW));
    install_seccomp_filter(&mut instructions).context("failed to install seccomp filter")
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

const fn statement(code: u16, value: u32) -> FilterInstruction {
    FilterInstruction {
        code,
        jump_true: 0,
        jump_false: 0,
        value,
    }
}

const fn jump(code: u16, value: u32, jt: u8, jf: u8) -> FilterInstruction {
    FilterInstruction {
        code,
        jump_true: jt,
        jump_false: jf,
        value,
    }
}
