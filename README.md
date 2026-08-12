# hdc-remote-kit

[![CI](https://github.com/yabi-zzh/hdc-remote-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/yabi-zzh/hdc-remote-kit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8.svg)](go.mod)
[![GitHub stars](https://img.shields.io/github/stars/yabi-zzh/hdc-remote-kit?style=social)](https://github.com/yabi-zzh/hdc-remote-kit/stargazers)

独立、无第三方依赖的 Go HDC 远程调试服务。

本机插上 USB 设备并启动本服务后，会自动为每台在线设备分配稳定代理端口；其它机器用 `hdc tconn host:port` 即可像本地一样调试。无需额外控制面或手动登记设备。

## 快速开始

要求：Go 1.26+，本机已有正在运行的 HDC server，且至少一台 USB 在线设备。

```bash
go run ./cmd/hdc-remote
```

日志出现可复制的连接命令后，在客户端执行：

```text
2026-07-21 11:05:21 INFO forwarding ready serial=4ABVB24A10014201 connect="hdc tconn 192.168.1.8:50000"
```

```bash
hdc tconn 192.168.1.8:50000
hdc -t 192.168.1.8:50000 shell echo ok
```

- 多设备时用日志里的 `serial` 区分；`connect` 中的端口是该设备的代理入口。
- 客户端连上后会再打 `connection accepted`（同一 `serial`）。
- Ctrl+C 可优雅退出服务。

默认放行本机 loopback 与 RFC1918 私网来源。从公网或其它非私网地址接入时，需显式放宽 `HDC_REMOTE_ALLOWED_SOURCE_CIDRS`。连接命令中的主机默认自动探测本机可展示的 IPv4（优先私网，失败回退 `127.0.0.1`），也可用 `HDC_REMOTE_PUBLIC_HOST` 覆盖为域名或指定 IP。

排查连接问题时可开 debug（`-log-level` / `-v` 优先于环境变量）：

```bash
go run ./cmd/hdc-remote -log-level=debug
go run ./cmd/hdc-remote -v
HDC_REMOTE_LOG_LEVEL=debug go run ./cmd/hdc-remote
```

debug 下会额外输出：设备扫描刷新、租约续期、主 HDC dial/open target、daemon 帧路由（命令名/channel，不含完整命令行）、握手与 shell 打开等。

也可先跑测试：`go test ./...`。预编译二进制见 [Releases](https://github.com/yabi-zzh/hdc-remote-kit/releases)。

## 当前能力

- 通过 HDC host channel 协议读取 USB/TCP 设备列表，不依赖外部 `hdc` CLI。
- 后台跟踪设备 online / offline / stale；在线 USB 自动开启转发，离线自动冻结。
- 为每台在线 USB 维护稳定代理端口；端口映射（Binding）经主/备 JSON 快照恢复；租约（Lease）仅存在于当前进程，重启后按当时在线设备重新开启。
- 握手前校验来源 CIDR 与并发上限；命令决策结构化审计落盘 JSONL。
- 支持 daemon 握手、keepalive、交互式 shell 与一次性 shell。
- Unity：`hilog`、`jpid`、`track-jpid`、`bugreport` 流式转发。
- 文件：`send` / `recv`；端口转发：`fport` / `rport`（`tcp` 与 `localabstract` / `localreserved` / `localfilesystem`）；应用：`install` / `uninstall`。
- 对重启、刷写、root/runmode、修改 HDC daemon 状态等高危命令 fail-closed。

## 配置

| 环境变量 | 默认值 | 作用 |
| --- | --- | --- |
| `HDC_REMOTE_HDC_ADDR` | `127.0.0.1:8710` | 主 HDC server 地址 |
| `HDC_REMOTE_PROXY_BIND_HOST` | `0.0.0.0` | 设备代理监听地址 |
| `HDC_REMOTE_PROXY_PORT_MIN` | `50000` | 代理端口范围下界 |
| `HDC_REMOTE_PROXY_PORT_MAX` | `50500` | 代理端口范围上界 |
| `HDC_REMOTE_PUBLIC_HOST` | 自动探测可展示 IPv4（优先私网，失败回退 `127.0.0.1`） | 连接命令中展示的域名或 IP；显式设置时优先生效 |
| `HDC_REMOTE_SERVER_NODE` | `local` | 设备稳定 ID 的节点作用域 |
| `HDC_REMOTE_STATE_DIR` | `./data` | Binding 快照与审计日志目录 |
| `HDC_REMOTE_ALLOWED_SOURCE_CIDRS` | loopback + `10/8` / `172.16/12` / `192.168/16` | daemon 连接来源白名单 |
| `HDC_REMOTE_LOG_LEVEL` | `info` | 日志级别：`debug` / `info` / `warn` / `error`；可用 `-log-level` 或 `-v`（debug）覆盖 |
| `HDC_REMOTE_DEVICE_POLL_INTERVAL` | `2s` | 设备扫描周期 |
| `HDC_REMOTE_DEVICE_STALE_AFTER` | `10s` | 扫描持续失败后的 stale 阈值 |
| `HDC_REMOTE_LEASE_MAX_TTL` | `8h` | 租约保险 TTL（运行期持续刷新；异常停止后到期自动关闭入口） |
| `HDC_REMOTE_MAX_CONNECTIONS` | `2` | 单设备最大并发连接数 |
| `HDC_REMOTE_MAX_CHANNELS_PER_CONNECTION` | `64` | 单连接最大同时打开 channel 数 |
| `HDC_REMOTE_HANDSHAKE_TIMEOUT` | `10s` | 连接建立后完成握手的时限，超时断开以免空连接占用并发名额 |
| `HDC_REMOTE_SHUTDOWN_TIMEOUT` | `10s` | 退出时等待连接收敛的上限，超时则放弃等待直接退出 |
| `HDC_REMOTE_HOST_CONNECT_TIMEOUT` | `3s` | 连接主 HDC server 的超时 |
| `HDC_REMOTE_HOST_READ_TIMEOUT` | `5s` | 主 HDC 读超时（命令流式期间清除） |
| `HDC_REMOTE_MAX_HOST_PAYLOAD_BYTES` | `1 MiB` | 主 HDC channel 单帧负载上限 |
| `HDC_REMOTE_MAX_DAEMON_FRAME_BYTES` | `64 MiB` | daemon 单帧大小上限 |
| `HDC_REMOTE_MAX_FILE_BYTES` | `2 GiB` | 单文件声明大小上限 |
| `HDC_REMOTE_MAX_TEMP_BYTES` | `4 GiB` | 文件桥临时空间配额；`recv` 按 `MAX_FILE_BYTES` 预占，故并发 `recv` 数上限为两者之商（默认 2） |
| `HDC_REMOTE_FILE_TRANSFER_TIMEOUT` | `10m` | 文件桥主 HDC 传输超时 |
| `HDC_REMOTE_UNITY_STREAM_TIMEOUT` | `30m` | hilog / JDWP / bugreport 流式桥超时 |
| `HDC_REMOTE_POLICY_PROFILE` | `studio-debug` | 命令策略档位：`studio-debug` 或更严的 `restricted` |
| `HDC_REMOTE_EXTRA_DENIED_EXECUTABLES` | 空 | 在内置规则上追加禁止的 shell 可执行名（逗号分隔，仅加严）；按小写 basename 归一，写绝对路径同样生效 |

## 构建与多平台发布

纯 Go、无 cgo，支持交叉编译。提供 Makefile（需本机有 `make`；Windows 可用 Git Bash）：

```bash
make build              # 当前平台，产物 ./hdc-remote(.exe)
make test               # 全量测试
make release            # 交叉编译全部平台到 dist/，产物名含版本号
./hdc-remote -version   # 打印版本号
```

发布目标平台：

| GOOS/GOARCH | 说明 |
| --- | --- |
| `linux/amd64`、`linux/arm64` | Linux |
| `darwin/amd64`、`darwin/arm64` | macOS（Intel / Apple Silicon） |
| `windows/amd64`、`windows/arm64` | Windows |

版本号由 `git describe --tags --always --dirty` 注入（无 tag 时回退 `dev`）。

版本变更见 [CHANGELOG.md](CHANGELOG.md)。打 `v*` tag 前须先写入对应版本条目；推送 tag 后 GitHub Actions 会交叉编译、生成 `checksums.txt`（SHA256），并从 CHANGELOG 提取该版本说明挂到 [GitHub Release](https://github.com/yabi-zzh/hdc-remote-kit/releases)。Release 附件不计入 git 仓库体积。

```bash
# 1. 更新 CHANGELOG.md 中的 [x.y.z] 后提交
# 2. 打 tag 并推送
git tag v0.1.0
git push origin v0.1.0
```

不用 make 时可直接交叉编译：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o hdc-remote ./cmd/hdc-remote
```

## 模块关系

```text
main（装配 + 生命周期）
   -> remote.Manager      Binding、Lease 编排与自动转发对账
      -> device.Registry  后台设备事实与 stale 投影
      -> store            Binding 原子 JSON 快照
      -> gateway.Gateway  准入、daemon 会话与连接事件
         -> protocol      HDC daemon 帧与握手编解码
         -> hdc.HostClient 主 HDC target channel
      -> audit.Sink       命令决策 JSONL 落盘
```

- **Binding**：持久的稳定端口映射，可跨进程恢复。
- **Lease**：当前进程内的转发租约与活跃连接；服务重启后按当时在线设备重新自动开启转发。

## 安全边界

本服务把 USB 设备通过网络暴露为可远程调试的 HDC daemon 入口，请理解信任模型后再部署：

- 主信任边界是网络准入：来源 CIDR 白名单（默认 loopback + RFC1918 私网）+ 单设备并发上限 + 租约保险 TTL。只应对可信来源开放。
- `HDC_REMOTE_PROXY_BIND_HOST` 默认 `0.0.0.0`，实际可达性由来源 CIDR 白名单收敛；放宽白名单前请评估暴露面并配合防火墙。
- 命令策略（`internal/policy`）是尽力而为的高危黑名单，不是完备沙箱：拦截重启、刷写、remount、删除关键路径等，但不保证挡住所有恶意变体。可用 `HDC_REMOTE_POLICY_PROFILE=restricted` 额外禁网络工具，或用 `HDC_REMOTE_EXTRA_DENIED_EXECUTABLES` 追加禁止项；请勿把本服务直接暴露到不可信网络。
- 策略按 shell 语义解析命令：换行、`;`、`|`、`&&` 等一律视为命令分隔符，引号与反斜杠转义按 shell 规则还原，`sh -c`、`busybox`、`timeout`/`nohup` 等包装器会被展开后再判定。命令位无法静态解析的写法一律拒绝（规则 `indirect-command`），包括 `$(...)` / 反引号 / `$var` 直接作为命令，以及 `... | sh` 这类把命令喂给 shell 的管道——它们可以承载任意命令，放行等于让整张黑名单失效。
- 为保证 fail-closed，判定偏保守，存在已知误伤：包装器的普通参数也会按可执行名匹配（`nohup cat /tmp/reboot` 会被拦），结束进程的命令与 `hdcd` 出现在同一条命令里即拦（`ps -ef | grep hdcd; kill 1234` 会被拦）。
- 所有命令决策写入 `STATE_DIR/audit.jsonl`，不含文件内容与完整命令行；单文件超过 64 MiB 自动轮转为 `audit.jsonl.1`，仅保留一代历史，需要长期留存请自行归档。

漏洞报告与更完整说明见 [SECURITY.md](SECURITY.md)。

## 贡献

欢迎贡献。开发环境、验证命令、CHANGELOG 与提交规范见 [CONTRIBUTING.md](CONTRIBUTING.md)。HDC 协议相关改动需真机验证。

## 许可证

本项目以 [Apache License 2.0](LICENSE) 授权。
