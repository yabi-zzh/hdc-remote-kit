package policy

import (
	"testing"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

func TestInspectFrameCommandDeniesDangerousFamilies(t *testing.T) {
	denied := []protocol.Command{
		protocol.CommandUnityRemount, protocol.CommandUnityReboot, protocol.CommandUnityRunmode,
		protocol.CommandUnityRootrun, protocol.CommandAppSideload,
		protocol.CommandFlashUpdateInit, protocol.CommandFlashErase, protocol.CommandFlashFormat,
		protocol.CommandLegacyUartFinish,
	}
	for _, command := range denied {
		if InspectFrameCommand(command).Allowed {
			t.Fatalf("InspectFrameCommand(%d) allowed, want denied", command)
		}
	}
	allowed := []protocol.Command{
		protocol.CommandShellInit, protocol.CommandShellData, protocol.CommandKernelHandshake,
		protocol.CommandUnityHilog, protocol.CommandFileCheck, protocol.CommandAppInit,
	}
	for _, command := range allowed {
		if !InspectFrameCommand(command).Allowed {
			t.Fatalf("InspectFrameCommand(%d) denied, want allowed", command)
		}
	}
}

func TestInspectShellCommandRejectsHighRiskOperations(t *testing.T) {
	rejected := []string{
		"reboot",
		"poweroff",
		"setprop persist.hdc.mode 1",
		"param set const.hdc.secure 0",
		"killall hdcd",
		"kill 42 hdcd",
		"pkill /bin/hdcd",
		"rm -rf /system",
		"rm -rf /system_ext/app",
		"rm -rf /data/system",
		"dd if=/dev/zero of=/dev/block/by-name/system",
		"mount -o remount,rw /system",
		"mount -o remount /vendor",
		"echo bad > /system/build.prop",
		"toybox reboot",
		"busybox rm -rf /product",
		"sh -c reboot",
		"sh -c 'rm -rf /system'",
		"A=1 B=2 /system/bin/reboot",
		"nohup poweroff",
		"ls;reboot",
	}
	for _, command := range rejected {
		if InspectShellCommand(command).Allowed {
			t.Fatalf("InspectShellCommand(%q) allowed, want rejected", command)
		}
	}

	allowed := []string{
		"",
		"ls -al",
		"echo reboot",
		"cat /data/local/tmp/log.txt",
		"rm -rf /data/local/tmp/build",
		"mount",
		"setprop persist.sys.locale zh-CN",
		"dd if=/dev/zero of=/data/local/tmp/blob",
	}
	for _, command := range allowed {
		if !InspectShellCommand(command).Allowed {
			t.Fatalf("InspectShellCommand(%q) rejected, want allowed", command)
		}
	}
}

// TestInspectShellCommandRejectsBypassVariants 固化已知绕过手法的拦截结果。
// 这些写法都能让设备真正执行 reboot 等高危命令，任何一条回归都意味着黑名单整体失效。
func TestInspectShellCommandRejectsBypassVariants(t *testing.T) {
	cases := map[string]string{
		"换行分隔":            "ls\nreboot",
		"回车分隔":            "ls\rreboot",
		"NUL 分隔":          "ls\x00reboot",
		"交互窗口累积":          "echo hi\nreboot\n",
		"heredoc":         "cat <<EOF\nreboot\nEOF",
		"if/then 复合语句":    "if true; then reboot; fi",
		"for/do 复合语句":     "for i in 1; do reboot; done",
		"time 关键字":        "time reboot",
		"timeout 包装":      "timeout 5 reboot",
		"nice 包装":         "nice -n 1 reboot",
		"setsid 包装":       "setsid reboot",
		"chroot 包装":       "chroot / reboot",
		"xargs 包装":        "echo | xargs reboot",
		"eval 包装":         "eval reboot",
		"反斜杠前缀":           `\reboot`,
		"反斜杠内嵌":           `re\boot`,
		"命令替换":            "$(echo reboot)",
		"反引号替换":           "`echo reboot`",
		"变量间接":            "a=reboot; $a",
		"花括号变量间接":         "a=reboot; ${a}",
		"管道给 sh":          "echo reboot | sh",
		"base64 管道":       "echo cmVib290 | base64 -d | sh",
		"组合短选项 -xc":       "sh -xc reboot",
		"下划线赋值前缀":         "_A=1 reboot",
		"of= 赋值前缀":        "of=1 reboot",
		"rm -r 无 -f":      "rm -r /system",
		"rm --recursive":  "rm --recursive /system",
		"双引号重定向目标":        `echo x > "/system/build.prop"`,
		"单引号重定向目标":        "echo x > '/system/build.prop'",
		"追加重定向":           "echo x >> /system/build.prop",
		"mount --options": "mount --options remount,rw /system",
		"mount --remount": "mount --remount /system",
		"换行加引号拆分":         "ls\n\"re\"boot",
		"关键字套包装器":         "if true; then timeout 5 reboot; fi",

		// 双引号只抑制分词与分隔符，不抑制命令替换；真实 shell 会展开 "$(...)"。
		"双引号内命令替换":     `echo "$(reboot)"`,
		"双引号内反引号":      "echo \"`reboot`\"",
		"双引号内嵌替换":      `echo "x$(reboot)y"`,
		"双引号赋值替换":      `X="$(reboot)"`,
		"双引号内 rm":      `ls "$(rm -rf /system)"`,
		"双引号内 setprop": `echo "$(setprop persist.hdc.mode 1)"`,
		"双引号内 mount":   `echo "$(mount -o remount,rw /system)"`,
		"双引号内 pidof":   `kill -9 "$(pidof hdcd)"`,
		// 空段不能抹掉管道关系。
		"管道后接括号": "echo reboot | (sh)",
		"跨行管道":   "echo reboot |\nsh",
		// 包装器段的候选可执行名不止首个。
		"管道给 nohup sh":   "echo reboot | nohup sh",
		"管道给 timeout sh": "echo reboot | timeout 5 sh",
		"nohup 变量间接":     "a=reboot; nohup $a",
		"eval 变量间接":      "a=reboot; eval $a",
		// 包装器的操作数不能挡住其后的 sh -c。
		"timeout 套 sh -c": "timeout 5 sh -c 'rm -rf /system'",
		"nice 套 sh -c":    "nice -n 1 sh -c 'rm -rf /system'",
		"chroot 套 sh -c":  "chroot / sh -c 'rm -rf /system'",
		"timeout 套重定向":    "timeout 5 sh -c 'echo x > /system/build.prop'",
		"选项终止符":           "sh -c -- reboot",
		"强制覆盖重定向":         "echo x >| /system/build.prop",
		"未闭合双引号":          `echo "; reboot`,
	}
	for name, command := range cases {
		if InspectShellCommand(command).Allowed {
			t.Errorf("%s: InspectShellCommand(%q) allowed, want rejected", name, command)
		}
	}
}

// TestInspectShellCommandAllowsRoutineDebugging 防止收紧规则误伤日常调试命令。
func TestInspectShellCommandAllowsRoutineDebugging(t *testing.T) {
	cases := map[string]string{
		"管道给 grep":  "ps -ef | grep hdcd",
		"替换作为参数":    "echo $(date)",
		"变量作为参数":    "ls $HOME",
		"多行安全命令":    "cd /data/local/tmp\nls -al\n",
		"带空格的引号路径":  `ls "/data/local/tmp/my dir"`,
		"重定向到临时目录":  "echo hi > /data/local/tmp/out.txt",
		"递归删临时目录":   "rm -r /data/local/tmp/build",
		"仅 --force": "rm --force /data/local/tmp/x",
		"find 通配":   "find /data/local/tmp -name '*.hap'",
		// 双引号内的单引号是字面量，不能被当成引号切换。
		"双引号内撇号":     `echo "it's fine"`,
		"双引号内替换作为参数": `echo "today is $(date)"`,
		"单引号包住元字符":   "echo '$(reboot)'",
		"单引号内分号":     "ls '/data/local/tmp/x;reboot'",
		// 交互输入逐字累积时会出现半截引号，不能因此拒绝。
		"半截双引号":   `echo "hello`,
		"包装器正常用法": "timeout 5 ls -al",
		"多重管道":    "ls | grep a | grep b",
	}
	for name, command := range cases {
		if decision := InspectShellCommand(command); !decision.Allowed {
			t.Errorf("%s: InspectShellCommand(%q) rejected by %q, want allowed", name, command, decision.Rule)
		}
	}
}

// TestPolicyExtraDeniedExecutablesNormalizesPath 确认配置项按 basename 归一，
// 使 HDC_REMOTE_EXTRA_DENIED_EXECUTABLES 写成绝对路径时同样生效。
func TestPolicyExtraDeniedExecutablesNormalizesPath(t *testing.T) {
	engine := New(Config{ExtraDeniedExecutables: []string{"/system/bin/curl"}})
	for _, command := range []string{"curl http://x", "/system/bin/curl http://x"} {
		if engine.InspectShell(ProfileStudioDebug, command).Allowed {
			t.Errorf("InspectShell(%q) allowed, want denied by extra rule", command)
		}
	}
}

func TestInspectShellCommandRejectReasonIsStable(t *testing.T) {
	decision := InspectShellCommand("reboot")
	if decision.Allowed || decision.Reason != ReasonProhibited {
		t.Fatalf("InspectShellCommand(reboot) = %+v", decision)
	}
}

func TestFirstExecutableStripsWrappersAndPath(t *testing.T) {
	cases := map[string]string{
		"/system/bin/ls -al": "ls",
		"A=1 env B=2 reboot": "reboot",
		"toybox mount":       "mount",
		"sh -c reboot":       "reboot",
		"":                   "",
	}
	for command, want := range cases {
		if got := FirstExecutable(command); got != want {
			t.Fatalf("FirstExecutable(%q) = %q, want %q", command, got, want)
		}
	}
}

func TestInspectFrameCommandReportsRuleName(t *testing.T) {
	decision := InspectFrameCommand(protocol.CommandUnityReboot)
	if decision.Allowed || decision.Rule == "" {
		t.Fatalf("InspectFrameCommand(reboot) = %+v, want denied with a rule name", decision)
	}
	if decision.Reason != ReasonProhibited {
		t.Fatalf("reason = %q, want %q", decision.Reason, ReasonProhibited)
	}
}

func TestPolicyExtraDeniedExecutables(t *testing.T) {
	engine := New(Config{ExtraDeniedExecutables: []string{"curl", "WGET"}})
	denied := []string{"curl http://x", "/system/bin/curl x", "wget http://x", "sh -c 'wget http://x'"}
	for _, command := range denied {
		if decision := engine.InspectShell(ProfileStudioDebug, command); decision.Allowed {
			t.Fatalf("InspectShell(%q) allowed, want denied by extra rule", command)
		}
	}
	// 未配置追加时，默认策略放行 curl（不改变内置基线）。
	if decision := Default().InspectShell(ProfileStudioDebug, "curl http://x"); !decision.Allowed {
		t.Fatalf("default policy should allow curl, got %+v", decision)
	}
}

func TestPolicyRestrictedProfileBlocksNetworkTools(t *testing.T) {
	engine := New(Config{})
	networkTools := []string{"curl http://x", "wget http://x", "nc 10.0.0.1 80", "sh -c 'curl http://x'"}
	for _, command := range networkTools {
		if decision := engine.InspectShell(ProfileRestricted, command); decision.Allowed {
			t.Fatalf("restricted InspectShell(%q) allowed, want denied", command)
		}
		if decision := engine.InspectShell(ProfileStudioDebug, command); !decision.Allowed {
			t.Fatalf("studio-debug InspectShell(%q) denied, want allowed", command)
		}
	}
}

func TestPolicyUnknownProfileFailsSafeToRestricted(t *testing.T) {
	engine := New(Config{})
	// 未知档位回退最严 restricted：网络工具被拦。
	if decision := engine.InspectShell(Profile("bogus"), "curl http://x"); decision.Allowed {
		t.Fatalf("unknown profile should fail-safe to restricted and deny curl, got %+v", decision)
	}
	// 空档位视为默认 studio-debug：放行 curl。
	if decision := engine.InspectShell(Profile(""), "curl http://x"); !decision.Allowed {
		t.Fatalf("empty profile should behave as studio-debug and allow curl, got %+v", decision)
	}
}

func TestValidProfile(t *testing.T) {
	for _, valid := range []string{"studio-debug", "restricted"} {
		if !ValidProfile(valid) {
			t.Fatalf("ValidProfile(%q) = false, want true", valid)
		}
	}
	for _, invalid := range []string{"", "trusted", "foo"} {
		if ValidProfile(invalid) {
			t.Fatalf("ValidProfile(%q) = true, want false", invalid)
		}
	}
}
