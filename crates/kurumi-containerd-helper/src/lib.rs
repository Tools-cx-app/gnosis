//! Target-aware Linux and Android system call wrappers for `KurumiContainerd`.

#![allow(unsafe_code)]
#![allow(
    clippy::borrow_as_ptr,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::unnecessary_cast,
    clippy::useless_conversion
)]

mod fs;
mod process;
mod security;
mod syscall;
mod terminal;

pub use fs::*;
pub use process::*;
pub use security::*;
pub use terminal::*;

pub const OPEN_CLOEXEC: i32 = libc::O_CLOEXEC;
pub const OPEN_NOFOLLOW: i32 = libc::O_NOFOLLOW;
pub const OPEN_NONBLOCK: i32 = libc::O_NONBLOCK;
pub const OPEN_NOCTTY: i32 = libc::O_NOCTTY;
