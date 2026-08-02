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

pub mod fs;
pub mod process;
pub mod security;
pub mod signal;
mod syscall;
pub mod terminal;
