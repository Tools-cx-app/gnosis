# Repository Guide

## Workspace boundaries

- `gnosis` is a privileged Linux/Android container runtime, not an Android app or a security sandbox. Runtime operations generally require root and a prepared rootfs; unit tests do not.
- The workspace has four packages: `gnosis` (`crates/gnosis-cli`, binary entrypoint), `gnosis-config` (strict TOML loading/validation), `gnosis-runtime` (lifecycle and isolation), and `gnosis-helper` (target-aware syscall wrappers). `docs/architecture.md` still omits `gnosis-helper`; trust `Cargo.toml`.
- In `gnosis-runtime`, `runtime/` orchestrates lifecycle/state/exec, `host/` owns host resources, and `container/` applies in-container policy. Keep raw Linux/Android syscall wrappers in `gnosis-helper`; its crate-level unsafe/clippy allowances are intentional.

## Code ownership

- Put raw syscalls, libc/FFI details, file-descriptor primitives, and Linux/Android or architecture-specific wrappers in `gnosis-helper`. Keep policy, lifecycle decisions, and user-facing output out of this crate.
- Put TOML schema, parsing, path resolution, defaults, and configuration validation in `gnosis-config`. It must not depend on runtime or host state.
- Put container lifecycle and isolation policy in `gnosis-runtime`: orchestration/state/exec in `runtime/`, host-owned resources in `host/`, and behavior applied inside the container in `container/`. Call `gnosis-helper` rather than duplicating unsafe syscall code.
- Put argument parsing, command dispatch, capability-report formatting, and other terminal-facing presentation in `gnosis-cli`. Keep reusable runtime behavior out of the CLI.

## Verification

- Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo test --workspace --locked` for a full local check.
- Run one package with `cargo test -p gnosis-config` or one test by substring, for example `cargo test -p gnosis-runtime configured_environment_overrides_session_environment`.
- CI does locked release cross-builds only. Match it with `cargo build --workspace --release --locked --target <linux-target>` or `cargo ndk --platform 21 --target <android-abi> build --workspace --release --locked`; Android ABIs are listed in `.github/workflows/ci.yml`.
- Unit tests exercise pure logic and lightweight host primitives. Lifecycle, namespace, mount, cgroup, networking, and Android integration need a suitable privileged host; use `sudo cargo run --release -p gnosis -- check` before manual runtime testing.

## Runtime constraints

- Config is strict TOML. Relative host paths resolve from the config file, while init/mount/device paths are container paths. `Config::load_persistent` may atomically rewrite the source TOML to add a missing UUID; use `Config::load` in tests that must not mutate it.
- Changes to persisted state or recovery must preserve the trust model in `runtime/state.rs`: restrictive ownership/permissions, no-follow access, atomic replacement, and PID identity checks. A numeric PID alone is not trusted.
- Platform behavior is selected with `cfg(target_os = "android")` and architecture gates. A successful host build does not verify Android code; preserve and exercise the CI target matrix when changing gated code.
- Gate platform-specific modules, functions, imports, and exports with the narrowest applicable `#[cfg(...)]` or `cfg_if!`; do not expose unsupported functionality and reject it only at runtime. Keep matching tests under the same gate.
- The repository intentionally warns on unsafe code. Keep any unavoidable unsafe block narrowly allowed at the call site unless it belongs in `gnosis-helper`; do not weaken workspace lints.
