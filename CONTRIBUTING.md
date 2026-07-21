# 贡献指南

感谢你对 hdc-remote-kit 的关注。本文约定开发环境、代码规范与提交流程。

## 开发环境

- Go 1.26 或更高版本（与 `go.mod` / CI 一致；补丁版本建议使用当前 1.26.x 最新）。
- 一个正在运行的主 `hdc server`（真机联调时需要）。
- 纯 Go、无 cgo、无第三方依赖，`go build` 即可。

## 本地验证

提交前必须全部通过：

```bash
make fmt      # gofmt -w internal cmd
make vet      # go vet ./...
make test     # go test ./...
go test -race ./...
```

CI 会在 PR 上重复执行 gofmt 检查、`go vet`、构建、`go test -race` 与六平台交叉编译，请确保本地已通过。

## 代码规范

- 严格 `gofmt`，导出符号必须有文档注释。
- 注释使用中文；代码标识符、命令、路径、日志保持原语言。
- 注释解释业务意图、边界条件与风险取舍，不复述表面代码行为。
- 遵循既有分层：`cmd → remote/gateway/... → protocol/bridge/hdc`，禁止跨层调用。
- 显式错误处理，资源（连接、文件、goroutine）必须有明确释放路径。
- 安全相关改动遵循 fail-closed 原则：未知命令、越界输入、不支持的能力一律拒绝。

## 协议相关改动

HDC 协议族（file / app / unity / forward）的改动，除离线单测外还需真机抓帧验证。若暂无设备，请在 PR 中明确标注「待真机验收」，不要宣称完整可用。

## 提交与 PR

- 提交信息格式为单行 `type: 描述`（如 `fix: 修复 rport 清理泄漏`），type 取 `feat` / `fix` / `docs` / `refactor` / `test` / `chore` / `ci` 等。
- 不使用 `Co-Authored-By` 等尾注。
- 一个 PR 聚焦一件事，附带动机说明与验证方式（含是否真机验证）。
- 涉及安全边界、协议兼容或配置默认值的改动，请在描述中显式说明影响。
- 用户可见行为变更时，请同步更新 [CHANGELOG.md](CHANGELOG.md)（Keep a Changelog：新增 / 变更 / 修复 / 安全等分类）。

## 发版

1. 在 [CHANGELOG.md](CHANGELOG.md) 写入即将发布的 `[x.y.z]` 条目并提交到 `main`。
2. 确认 CI 通过后打 tag 并推送：`git tag vX.Y.Z && git push origin vX.Y.Z`。
3. Release 流水线会交叉编译产物，并从 CHANGELOG 提取该版本说明；若 CHANGELOG 缺少对应版本，发版会失败。

## 安全问题

请勿通过公开 issue 报告安全漏洞，参见 [SECURITY.md](SECURITY.md)。
