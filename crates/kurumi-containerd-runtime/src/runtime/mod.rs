//! Runtime orchestration, execution, and persistent state.

mod boot;
mod execute;
mod install;
mod lifecycle;
pub(crate) mod state;
mod supervisor;
