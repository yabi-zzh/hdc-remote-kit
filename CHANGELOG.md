# 更新日志

本项目所有值得注意的变更均记录于此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.3.0]

### 新增

- 远程 `hdc tconn` 改为官方多轮公钥握手。默认 `HDC_REMOTE_HOST_AUTH=off`：来源白名单内完成验签后进入命令转发，不写 `known_hosts`。`confirm`（或 `on`）时未知电脑 `tconn` 仍打印 `Connect OK`（官方客户端写死），`list targets` 为 Unauthorized；本机在 http://127.0.0.1:18080 点「始终允许」或「仅当次」后才进入命令转发。「始终允许」写入 `STATE_DIR/known_hosts.json`，「仅当次」不落盘。日志打印 `auth pending` 指纹供对照，没有终端 allow/deny。
- 远程客户端须 `hdc >= Ver: 3.0.0b`（`hdc -v`）；更低版本在 `AUTH_NONE` 即被拒（`confirm` / `off` 都拒），确认台只提示升级，不出现放行按钮。版本按官方 `Ver: x.y.z[letter]` 比较。
- 新增 `HDC_REMOTE_WEB_ADDR`（默认 `127.0.0.1:18080`，空字符串关闭确认台；非回环地址启动失败）、`HDC_REMOTE_AUTH_CONFIRM_TIMEOUT`（`confirm` 下等待放行，默认 `90s`）与 `HDC_REMOTE_HOST_AUTH`（默认 `off`；`confirm` / `on` 打开人工授权）。确认台可看待确认、版本过低提示、已验签会话（可踢出，不撤白名单）与白名单（可撤销，不拆已建立连接）。
- 握手在已解析出公钥后，审计写入 `fingerprint`（不含 PEM）。待确认连接仍占用该设备的 `MAX_CONNECTIONS`（默认 2）。

### 变更

- 相对 0.2.0：握手改为官方公钥；低于 `Ver: 3.0.0b` 的客户端无法接入。默认 `off` 时来源 CIDR 内验签后直连；`confirm` 时未知公钥须本机确认台放行。

### 安全

- 远程调试身份绑对端 hdc 公钥（`~/.harmony/hdckey`）。默认 `HDC_REMOTE_HOST_AUTH=off` 时关闭人工授权，来源白名单内能完成官方握手的客户端可直接调试。
- 确认台强制只绑回环；API 拒绝非回环 Host/Origin，并要求启动时生成的随机 token（防 DNS rebinding / CSRF）。

## [0.2.0]

### 新增

- 新增两个环境变量：`HDC_REMOTE_HANDSHAKE_TIMEOUT`（连接建立后须在此时间内完成握手，否则断开，默认 `10s`）与 `HDC_REMOTE_SHUTDOWN_TIMEOUT`（退出时等待连接收尾的上限，默认 `10s`）。

### 变更

- `MAX_TEMP_BYTES` 用法变化：`recv` 开始时会按 `MAX_FILE_BYTES` 预占配额，因此默认配置（4 GiB / 2 GiB）下同一时刻最多 2 个 `recv`，并与进行中的 `send` / `install` 共享该配额；此前不预占，并发传输可能一起占满磁盘。
- 转发大数据帧时的内存占用显著降低（单帧约为原先的三分之一）。
- 交互式 shell 长时间会话中，输入处理不再随时间推移变慢。

### 修复

- 设备持续在线满 `LEASE_MAX_TTL`（默认 8 小时）后，该设备拒绝所有新的 `hdc tconn` 连接且不再自动恢复，期间日志和状态却仍显示可连接。
- 只连接、不握手的空闲连接会占用设备的并发连接名额，两条即可让默认配置下的设备无法再被调试；客户端崩溃遗留的半开连接同理，现已通过 TCP keepalive 自动回收。
- `FILE_TRANSFER_TIMEOUT` 对文件传输实际从未生效；`recv` 现在还会在下载过程中检查大小，不再等写满本机磁盘后才拒绝超大文件。
- `hdc file send` 到目录时会在设备上写出名为 `payload` 的文件（丢失了原始文件名）。
- `hdc file recv` 拉取文件期间，同一条连接无法响应任何其它命令，也无法中途取消，文件越大阻塞越久。
- `fport` / `rport` 撤销转发规则时没有超时，主 HDC 无响应会导致连接一直无法关闭。
- 一次性命令在设备侧结束后不归还 channel 名额（除非客户端主动关闭该 channel），同一连接累计到 `MAX_CHANNELS_PER_CONNECTION` 上限后就无法再执行新命令。
- 退出时可能一直卡住无法结束进程；现在受 `SHUTDOWN_TIMEOUT` 约束，再次按 Ctrl+C 立即强制退出。
- 并发写入端口映射快照可能同时损坏主文件和备份，导致重启后丢失已分配的端口。
- 被临时占用的代理端口探测失败后不再放回，长期运行可能把端口池耗尽且不会自动恢复。
- 离线设备一直留在设备表中不清除，长期运行后内存和每轮扫描的开销缓慢增长。
- 回收租约与自动开启转发可能同时发生，导致刚建立的监听端口被误关，使设备在租约到期前一直无法连接。
- `EXTRA_DENIED_EXECUTABLES` 填写绝对路径时不生效（已改为按可执行名匹配）；`POLICY_PROFILE` 取值不再区分大小写；时长类环境变量填错时会报出具体变量名，不再静默当作 0。

### 安全

- **收紧了能绕过命令黑名单的 shell 写法（升级后可能影响现有用法）：** 命令替换（`$(...)`、反引号）、变量（`$VAR`）作为命令本身执行，以及把命令用管道喂给 shell（如 `echo ... | sh`），现在一律拒绝——它们能承载任意命令。作为参数的替换/变量（如 `echo $(date)`、`ls $HOME`）不受影响；若调试脚本依赖上述写法，升级后需改写。
- 修复命令策略解析的多类绕过：换行 / 回车 / NUL 之前未被当作命令分隔符，导致 `ls`(换行)`reboot` 这类命令直接放行，并使交互式 shell 逐帧拼接命令的检查整体失效；其余绕过包括反斜杠转义未还原、复合语句关键字和 `timeout` / `nice` / `xargs` / `eval` 等包装器遮住真正执行的命令、`sh -xc` 与 `sh -c --` 未识别、`rm -r`（不带 `-f`）未拦关键路径、带引号的重定向目标未匹配、`mount --options remount` 未识别。
- 交互式 shell 单个数据帧超过 256 KiB 会被拒绝，防止超大输入把高危命令挤出检查范围。
- 审计日志超过 64 MiB 自动轮转为 `audit.jsonl.1`（仅保留最近一代）；此前不轮转，会一直增长到写满状态分区。
- 日志中的字段值会转义换行等控制字符，修复借输出内容伪造日志行的问题。
- 状态目录权限从 `0755` 收紧为 `0700`；来源白名单配成 `0.0.0.0/0` 或 `::/0`（对所有网络开放）时启动会给出告警。

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
