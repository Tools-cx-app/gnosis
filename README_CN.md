# KurumiContainerd

KurumiContainerd 是一个使用 Rust 编写的特权 Linux 容器运行时和命令行工具。它通过
Linux namespace、挂载、cgroup、网络及持久化 TOML 配置管理轻量级系统容器。

项目名中的 **Kurumi** 是日语“胡桃”（くるみ）的罗马字，后缀
**Containerd** 表明它是一个容器运行时项目。

本仓库只包含 CLI 和运行时，不包含 Android App。运行时在 Android 目标上编译
和执行时，仍可按配置暴露部分 Android 主机资源。

> KurumiContainerd 是容器运行时，不是安全沙箱。请只运行可信的 rootfs 和命令。

## 主要能力

- 目录、ext4 镜像、btrfs 镜像和块设备 rootfs
- 从本地 tar/ZIP 归档安装目录 rootfs 或稀疏 ext4 镜像
- Mount、PID、UTS、IPC 以及可选的 Network namespace
- Host、隔离、NAT 和已有网桥网络模式
- cgroup v1/v2 内存、CPU 和进程数限制
- Bind mount 和临时 OverlayFS
- 后台 monitor 与前台 PTY 控制台
- 无需外部 `nsenter` 的容器进入和命令执行
- 防 PID 复用的持久化运行状态
- seccomp 过滤和只读内核视图
- 不依赖 Android App 的可选 Android 主机集成

## 环境要求

- 支持所需 namespace 和挂载功能的 Linux 或 Android 内核
- root 权限
- Rust 1.85 或更高版本
- NAT/网桥网络所需的 `ip` 和 `iptables`
- 配置资源限制时可用的 cgroup v1 或 v2
- 包含 init 可执行文件的 Linux rootfs

启动容器前可检查主机能力：

```bash
sudo cargo run --release -p kurumi-containerd -- check
```

## 构建

```bash
cargo build --release
```

生成的二进制位于 `target/release/kurumi-containerd`。

## 快速开始

```bash
cp kurumi-containerd.example.toml kurumi-containerd.toml
$EDITOR kurumi-containerd.toml
sudo ./target/release/kurumi-containerd --config kurumi-containerd.toml install ./rootfs.tar.zst
sudo ./target/release/kurumi-containerd --config kurumi-containerd.toml start
sudo ./target/release/kurumi-containerd --config kurumi-containerd.toml info
sudo ./target/release/kurumi-containerd --config kurumi-containerd.toml enter
sudo ./target/release/kurumi-containerd --config kurumi-containerd.toml stop
```

`--config` 默认读取 `kurumi-containerd.toml`，也可通过
`KURUMI_CONTAINERD_CONFIG` 指定。
配置中的相对主机路径以 TOML 文件所在目录为基准，而不是当前工作目录。

## 命令

```text
install ARCHIVE [--size SIZE] [--force]
                        从本地归档安装 rootfs
start [--foreground]   启动配置中的容器
stop                   优雅停止容器
restart [--foreground] 重启容器
enter [USER]           进入交互式登录，默认用户为 root
run COMMAND...          执行非交互命令
info                    显示运行状态和资源使用情况
pid                     输出容器 init PID
show                    列出运行时目录中的容器
scan                    验证运行进程并恢复缺失状态
check                   检查主机能力
```

## 文档

- [CLI 使用](docs/usage.md)
- [配置参考](docs/configuration.md)
- [运行时架构](docs/architecture.md)
- [实现状态](docs/status.md)

## 许可证

KurumiContainerd 使用 GNU General Public License v3.0 or later，详见
[LICENSE](LICENSE)。
