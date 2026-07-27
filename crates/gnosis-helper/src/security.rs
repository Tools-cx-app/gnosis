use std::io;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FilterInstruction {
    pub code: u16,
    pub jump_true: u8,
    pub jump_false: u8,
    pub value: u32,
}

pub const SECCOMP_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
pub const SECCOMP_KILL_PROCESS: u32 = libc::SECCOMP_RET_KILL_PROCESS;
pub const SECCOMP_ERRNO_PERMISSION: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
pub const SECCOMP_ERRNO_NOT_IMPLEMENTED: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
pub const ADDRESS_FAMILY_ALG: u32 = libc::AF_ALG as u32;

pub fn namespace_user_flag() -> u32 {
    libc::CLONE_NEWUSER as u32
}

pub fn syscall_unshare() -> libc::c_long {
    libc::SYS_unshare
}
pub fn syscall_clone() -> libc::c_long {
    libc::SYS_clone
}
pub fn syscall_socket() -> libc::c_long {
    libc::SYS_socket
}

#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
))]
pub fn syscall_clone3() -> libc::c_long {
    libc::SYS_clone3
}

pub fn blocked_syscalls() -> Vec<libc::c_long> {
    let blocked = vec![
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
        any(target_arch = "x86_64", target_arch = "aarch64"),
        all(not(target_os = "android"), not(target_env = "musl"))
    ))]
    let blocked = {
        let mut blocked = blocked;
        blocked.push(libc::SYS_kexec_file_load);
        blocked
    };
    blocked
}

pub fn install_seccomp(instructions: &mut [FilterInstruction]) -> io::Result<()> {
    let program = libc::sock_fprog {
        len: u16::try_from(instructions.len()).map_err(io::Error::other)?,
        filter: instructions.as_mut_ptr().cast(),
    };
    // SAFETY: FilterInstruction matches sock_filter's C layout and program is live for the call.
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &raw const program,
        )
    } == -1
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
