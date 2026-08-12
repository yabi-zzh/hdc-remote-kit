// Package policy 提供 daemon 命令的安全阀，包含两道守卫：
// 帧级命令黑名单（InspectFrame）与 shell 高危操作拦截（InspectShell，按 Profile 分级）。
// 规则以声明式规则表组织，判定结果携带命中的规则名供审计追溯；
// 内置规则为固定 fail-closed 基线，可经 Config 追加自定义禁止项（只能加严，不能放松）。
// file/app/forward 的输入合法性校验仍由各自 bridge 负责。
package policy

import (
	"strings"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

// ReasonProhibited 是命令被拒时统一对外的原因；不向调用方泄露具体命中的规则，避免暴露拦截细节。
const ReasonProhibited = "Command execution is prohibited."

// Profile 是命令策略档位，控制启用的 shell 规则集。
type Profile string

const (
	// ProfileStudioDebug 是默认档位：拦截已知高危操作，放行常规调试命令。
	ProfileStudioDebug Profile = "studio-debug"
	// ProfileRestricted 是收紧档位：在默认之上额外禁止网络下载/外连工具等。
	ProfileRestricted Profile = "restricted"
)

// Decision 表示一次策略判定结果。
// Reason 对外统一（避免暴露拦截细节），Rule 记录命中的规则名，仅供内部审计追溯。
type Decision struct {
	Allowed bool
	Reason  string
	Rule    string
}

func allow() Decision { return Decision{Allowed: true} }

func deny(rule string) Decision {
	return Decision{Allowed: false, Reason: ReasonProhibited, Rule: rule}
}

// frameRule 是帧级命令黑名单的一条声明式规则。
type frameRule struct {
	name   string
	denies func(protocol.Command) bool
}

// frameRules 是帧级永久禁止规则，对所有 profile 一律生效。
var frameRules = []frameRule{
	{"deny-remount", func(flag protocol.Command) bool { return flag == protocol.CommandUnityRemount }},
	{"deny-reboot", func(flag protocol.Command) bool { return flag == protocol.CommandUnityReboot }},
	{"deny-runmode", func(flag protocol.Command) bool { return flag == protocol.CommandUnityRunmode }},
	{"deny-rootrun", func(flag protocol.Command) bool { return flag == protocol.CommandUnityRootrun }},
	{"deny-sideload", func(flag protocol.Command) bool { return flag == protocol.CommandAppSideload }},
	{"deny-flash-family", func(flag protocol.Command) bool { return protocol.CommandFamily(flag) == protocol.FamilyFlash }},
}

// Config 是构造 Policy 的配置。
type Config struct {
	// ExtraDeniedExecutables 是在内置规则之上追加禁止的 shell 可执行名（只能加严，不能放松内置规则）。
	ExtraDeniedExecutables []string
}

// Policy 持有命令拦截规则集：内置帧级/shell 规则 + 配置追加的禁止可执行名。
type Policy struct {
	extraExecutables map[string]struct{}
}

// defaultPolicy 是无额外配置的默认策略，供包级兼容函数与未注入 Policy 的场景使用。
var defaultPolicy = &Policy{}

// New 构造带配置追加的 Policy。追加的可执行名会被规范化为小写 basename。
func New(cfg Config) *Policy {
	extras := make(map[string]struct{}, len(cfg.ExtraDeniedExecutables))
	for _, item := range cfg.ExtraDeniedExecutables {
		if normalized := baseExecutable(strings.ToLower(strings.TrimSpace(item))); normalized != "" {
			extras[normalized] = struct{}{}
		}
	}
	return &Policy{extraExecutables: extras}
}

// Default 返回无额外配置的默认策略实例。
func Default() *Policy { return defaultPolicy }

// InspectFrame 对 daemon 协议帧命令做黑名单判定，命中即返回对应规则名。
func (p *Policy) InspectFrame(flag protocol.Command) Decision {
	for _, rule := range frameRules {
		if rule.denies(flag) {
			return deny(rule.name)
		}
	}
	return allow()
}

// InspectFrameCommand 用默认策略做帧级判定（包级兼容入口，行为等价 studio-debug 默认档位）。
func InspectFrameCommand(flag protocol.Command) Decision {
	return defaultPolicy.InspectFrame(flag)
}

// ValidProfile 判定 profile 字符串是否为已知档位，供配置校验使用。
func ValidProfile(profile string) bool {
	switch Profile(profile) {
	case ProfileStudioDebug, ProfileRestricted:
		return true
	default:
		return false
	}
}

// resolveProfile 归一 profile：空视为默认 studio-debug；未知非空档位回退最严 restricted（fail-safe）。
func resolveProfile(profile Profile) Profile {
	switch profile {
	case ProfileStudioDebug, ProfileRestricted:
		return profile
	case "":
		return ProfileStudioDebug
	default:
		return ProfileRestricted
	}
}
