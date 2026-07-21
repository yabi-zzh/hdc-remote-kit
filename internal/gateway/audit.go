package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
	"github.com/yabi-zzh/hdc-remote-kit/internal/policy"
	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

// audit 在命令主链路上记录一条脱敏审计事件；未接入 recorder 时静默跳过。
// 该调用必须保持非阻塞，落盘背压由 audit.Sink 内部丢弃处理。
func (c *daemonConnection) audit(frame protocol.Frame, decision model.AuditDecision, reason string) {
	if c.recorder == nil {
		return
	}
	c.recorder.Record(model.Audit{
		LeaseID:           c.leaseID,
		ConnectionID:      c.connectionID,
		DeviceID:          c.binding.DeviceID,
		OwnerID:           c.ownerID,
		SourceIP:          c.sourceIP,
		CommandFlag:       uint64(frame.CommandFlag),
		CommandName:       frame.CommandName,
		NormalizedCommand: auditNormalized(frame),
		Decision:          decision,
		Reason:            reason,
		CreatedAt:         time.Now().UTC(),
	})
}

// auditableCommand 标记需要在 route 层记录 ALLOWED 的命令发起帧。
// shell 族在 handleShell 内单独记录（携带可执行名），此处不重复；
// 数据流帧（ShellData、FileData、AppData、ForwardData、echo 等）不逐帧审计以避免刷屏。
func auditableCommand(flag protocol.Command) bool {
	switch flag {
	case protocol.CommandUnityHilog, protocol.CommandJDWPList, protocol.CommandJDWPTrack,
		protocol.CommandUnityBugreportInit,
		protocol.CommandFileInit, protocol.CommandFileCheck,
		protocol.CommandAppInit, protocol.CommandAppCheck, protocol.CommandAppUninstall,
		protocol.CommandForwardInit, protocol.CommandForwardCheck,
		protocol.CommandForwardActiveMaster, protocol.CommandForwardActiveSlave,
		protocol.CommandForwardList, protocol.CommandForwardRemove:
		return true
	default:
		return false
	}
}

// auditNormalized 生成脱敏后的规范化命令摘要，绝不包含文件内容、安装包内容或完整命令行。
func auditNormalized(frame protocol.Frame) string {
	switch frame.CommandFlag {
	case protocol.CommandShellInit:
		return "shell"
	case protocol.CommandShellData:
		return "shell data"
	case protocol.CommandUnityExecute, protocol.CommandUnityExecuteEx:
		if executable := policy.FirstExecutable(protocol.ExtractShellCommand(frame)); executable != "" {
			return "shell exec " + executable
		}
		return "shell exec"
	default:
		return frame.CommandName
	}
}

func sourceIP(address net.Addr) string {
	parsed, err := remoteAddress(address)
	if err != nil {
		return ""
	}
	return parsed.String()
}

func newConnectionID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("conn-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}
