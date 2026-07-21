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
