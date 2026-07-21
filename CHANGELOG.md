# 更新日志

本项目所有值得注意的变更均记录于此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.1.0]

### 新增

- 独立 Go HDC 远程调试服务：自动发现在线 USB 设备，为每台维护稳定代理端口，支持 `hdc tconn host:port` 远程接入。
- 通过 HDC host channel 协议读取设备列表，不依赖外部 `hdc` CLI；设备 Registry 跟踪 online/offline/stale，离线自动冻结转发。
- Binding 主/备 JSON 快照恢复稳定端口映射；Lease 不跨进程恢复，重启后按当前在线设备重新开启转发。
- Daemon 会话支持握手、keepalive、交互式 shell 与一次性 shell 转发。
- Unity 桥：`hilog`、`jpid`、`track-jpid`、`bugreport` 流式转发。
- 文件桥：`send` / `recv`；端口转发：`fport` / `rport`（`tcp` 与 `localabstract` / `localreserved` / `localfilesystem`）；App 桥：`install` / `uninstall`。
- 来源 CIDR 白名单、单设备并发与 channel 上限、命令策略（`studio-debug` / `restricted`）与 JSONL 审计。
- 多平台发布流水线：打 `v*` tag 后交叉编译六平台二进制并附带 SHA256 校验和。

### 安全

- 对重启、刷写、root/runmode、修改 HDC daemon 状态等高危命令 fail-closed；策略为尽力而为黑名单，非完备沙箱。
