//! Host resources used to construct and supervise a container.

#[cfg(target_os = "android")]
pub(crate) mod android;
pub(crate) mod cgroup;
pub(crate) mod network;
pub(crate) mod process;
pub(crate) mod rootfs;
pub(crate) mod terminal;
