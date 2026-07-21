# 安全策略

hdc-remote-kit 把服务器上的 USB 设备通过网络暴露为可远程调试的 HDC daemon 入口，属于安全敏感工具。请在部署前理解其信任模型。

## 信任模型与边界

- **主信任边界是网络准入**：来源 CIDR 白名单（`HDC_REMOTE_ALLOWED_SOURCE_CIDRS`，默认 loopback + RFC1918 私网）+ 单设备并发上限 + 租约保险 TTL。只应对可信来源开放。
- `HDC_REMOTE_PROXY_BIND_HOST` 默认 `0.0.0.0`（监听所有网卡），实际可达性由来源 CIDR 白名单收敛。放宽白名单到局域网或公网前，请自行评估暴露面并配合防火墙。
- **命令策略是尽力而为的高危黑名单，不是完备沙箱**：`internal/policy` 拦截重启、刷写、remount、删除关键路径、改 HDC daemon 状态等已知破坏性操作，但不保证拦截所有恶意变体。可通过 `HDC_REMOTE_POLICY_PROFILE=restricted`（在默认之上额外禁网络下载/外连工具）与 `HDC_REMOTE_EXTRA_DENIED_EXECUTABLES`（追加禁止的可执行名）加严。配置中的非法档位会在启动时被拒绝；策略引擎对未知非空档位会 fail-safe 到最严 `restricted`。因此不要把本服务直接暴露到不可信网络，也不要把命令策略当作唯一安全防线。
- 所有命令决策落盘结构化审计（`STATE_DIR/audit.jsonl`），审计不含文件内容、安装包内容与完整命令行。

## 支持的版本

项目处于活跃开发阶段，安全修复仅针对 `main` 分支最新提交。已发布版本见 [Releases](https://github.com/yabi-zzh/hdc-remote-kit/releases) 与 [CHANGELOG.md](CHANGELOG.md)。

## 报告漏洞

请勿通过公开 issue、PR 或讨论区披露安全漏洞。

请使用 GitHub 的 **Security Advisories**（仓库 Security → Report a vulnerability）私下报告，包含：

- 受影响的组件与版本（commit 或 tag）。
- 复现步骤或 PoC。
- 影响评估（可达性、前置条件）。

我们会尽快确认并在修复发布后进行协调披露。
