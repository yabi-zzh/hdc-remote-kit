package protocol

// Command 是 HDC daemon 协议命令码。
type Command uint32

// Family 是命令所属协议族，gateway 据此把帧路由到对应 bridge。
type Family string

const (
	FamilyUnknown   Family = "unknown"
	FamilyKernel    Family = "kernel"
	FamilyShell     Family = "shell"
	FamilyUnity     Family = "unity"
	FamilyForward   Family = "forward"
	FamilyFile      Family = "file"
	FamilyApp       Family = "app"
	FamilyFlash     Family = "flash" // 永久 fail-closed，不桥接
	FamilyHeartbeat Family = "heartbeat"
)

// CommandOrigin 标记命令码来源：现行命令还是历史遗留别名。
type CommandOrigin string

const (
	CommandOriginOfficial CommandOrigin = "official"
	CommandOriginLegacy   CommandOrigin = "legacy"
)

const (
	CommandKernelHelp             Command = 0
	CommandKernelHandshake        Command = 1
	CommandKernelChannelClose     Command = 2
	CommandKernelTargetDiscover   Command = 4
	CommandKernelTargetList       Command = 5
	CommandKernelTargetAny        Command = 6
	CommandKernelTargetConnect    Command = 7
	CommandKernelTargetDisconnect Command = 8
	CommandKernelEcho             Command = 9
	CommandKernelEchoRaw          Command = 10
	CommandKernelEnableKeepalive  Command = 11
	CommandKernelWakeupSlaveTask  Command = 12
	CommandCheckServer            Command = 13
	CommandCheckDevice            Command = 14
	CommandWaitFor                Command = 15
	CommandServerKill             Command = 16
	CommandServiceStart           Command = 17
	CommandSSLHandshake           Command = 20

	CommandUnityCommandHead    Command = 1000
	CommandUnityExecute        Command = 1001
	CommandUnityRemount        Command = 1002
	CommandUnityReboot         Command = 1003
	CommandUnityRunmode        Command = 1004
	CommandUnityHilog          Command = 1005
	CommandUnityRootrun        Command = 1007
	CommandJDWPList            Command = 1008
	CommandJDWPTrack           Command = 1009
	CommandUnityCommandTail    Command = 1010
	CommandUnityBugreportInit  Command = 1011
	CommandUnityBugreportData  Command = 1012
	CommandUnityExecuteEx      Command = 1200
	CommandShellInit           Command = 2000
	CommandShellData           Command = 2001
	CommandForwardInit         Command = 2500
	CommandForwardCheck        Command = 2501
	CommandForwardCheckResult  Command = 2502
	CommandForwardActiveSlave  Command = 2503
	CommandForwardActiveMaster Command = 2504
	CommandForwardData         Command = 2505
	CommandForwardFreeContext  Command = 2506
	CommandForwardList         Command = 2507
	CommandForwardRemove       Command = 2508
	CommandForwardSuccess      Command = 2509
	CommandFileInit            Command = 3000
	CommandFileCheck           Command = 3001
	CommandFileBegin           Command = 3002
	CommandFileData            Command = 3003
	CommandFileFinish          Command = 3004
	CommandAppSideload         Command = 3005
	CommandFileMode            Command = 3006
	CommandDirMode             Command = 3007
	CommandAppInit             Command = 3500
	CommandAppCheck            Command = 3501
	CommandAppBegin            Command = 3502
	CommandAppData             Command = 3503
	CommandAppFinish           Command = 3504
	CommandAppUninstall        Command = 3505
	CommandFlashUpdateInit     Command = 4000
	CommandFlashFlashInit      Command = 4001
	CommandFlashCheck          Command = 4002
	CommandFlashBegin          Command = 4003
	CommandFlashData           Command = 4004
	CommandFlashFinish         Command = 4005
	CommandFlashErase          Command = 4006
	CommandFlashFormat         Command = 4007
	CommandFlashProgress       Command = 4008
	CommandHeartbeatMessage    Command = 5000
)

const (
	CommandLegacyKernelServerKill   Command = 3
	CommandLegacyClientKeyGenerate  Command = 18
	CommandLegacyUnityTerminate     Command = 1006
	CommandLegacyForwardRportInit   Command = 2510
	CommandLegacyForwardRportList   Command = 2511
	CommandLegacyForwardRportRemove Command = 2512
	CommandLegacyFileRecvInit       Command = 3008
	CommandLegacyUartFinish         Command = 4009
)

// CommandDescriptor 描述一个命令码的可读名、所属族与来源。
type CommandDescriptor struct {
	Name   string
	Family Family
	Origin CommandOrigin
}

var officialCommands = map[Command]CommandDescriptor{
	CommandKernelHelp:             official("KernelHelp", FamilyKernel),
	CommandKernelHandshake:        official("KernelHandshake", FamilyKernel),
	CommandKernelChannelClose:     official("KernelChannelClose", FamilyKernel),
	CommandKernelTargetDiscover:   official("KernelTargetDiscover", FamilyKernel),
	CommandKernelTargetList:       official("KernelTargetList", FamilyKernel),
	CommandKernelTargetAny:        official("KernelTargetAny", FamilyKernel),
	CommandKernelTargetConnect:    official("KernelTargetConnect", FamilyKernel),
	CommandKernelTargetDisconnect: official("KernelTargetDisconnect", FamilyKernel),
	CommandKernelEcho:             official("KernelEcho", FamilyKernel),
	CommandKernelEchoRaw:          official("KernelEchoRaw", FamilyKernel),
	CommandKernelEnableKeepalive:  official("KernelEnableKeepalive", FamilyKernel),
	CommandKernelWakeupSlaveTask:  official("KernelWakeupSlaveTask", FamilyKernel),
	CommandCheckServer:            official("CheckServer", FamilyKernel),
	CommandCheckDevice:            official("CheckDevice", FamilyKernel),
	CommandWaitFor:                official("WaitFor", FamilyKernel),
	CommandServerKill:             official("ServerKill", FamilyKernel),
	CommandServiceStart:           official("ServiceStart", FamilyKernel),
	CommandSSLHandshake:           official("SSLHandshake", FamilyKernel),
	CommandUnityCommandHead:       official("UnityCommandHead", FamilyUnity),
	CommandUnityExecute:           official("UnityExecute", FamilyShell),
	CommandUnityRemount:           official("UnityRemount", FamilyUnity),
	CommandUnityReboot:            official("UnityReboot", FamilyUnity),
	CommandUnityRunmode:           official("UnityRunmode", FamilyUnity),
	CommandUnityHilog:             official("UnityHilog", FamilyUnity),
	CommandUnityRootrun:           official("UnityRootrun", FamilyUnity),
	CommandJDWPList:               official("JdwpList", FamilyUnity),
	CommandJDWPTrack:              official("JdwpTrack", FamilyUnity),
	CommandUnityCommandTail:       official("UnityCommandTail", FamilyUnity),
	CommandUnityBugreportInit:     official("UnityBugreportInit", FamilyUnity),
	CommandUnityBugreportData:     official("UnityBugreportData", FamilyUnity),
	CommandUnityExecuteEx:         official("UnityExecuteEx", FamilyShell),
	CommandShellInit:              official("ShellInit", FamilyShell),
	CommandShellData:              official("ShellData", FamilyShell),
	CommandForwardInit:            official("ForwardInit", FamilyForward),
	CommandForwardCheck:           official("ForwardCheck", FamilyForward),
	CommandForwardCheckResult:     official("ForwardCheckResult", FamilyForward),
	CommandForwardActiveSlave:     official("ForwardActiveSlave", FamilyForward),
	CommandForwardActiveMaster:    official("ForwardActiveMaster", FamilyForward),
	CommandForwardData:            official("ForwardData", FamilyForward),
	CommandForwardFreeContext:     official("ForwardFreeContext", FamilyForward),
	CommandForwardList:            official("ForwardList", FamilyForward),
	CommandForwardRemove:          official("ForwardRemove", FamilyForward),
	CommandForwardSuccess:         official("ForwardSuccess", FamilyForward),
	CommandFileInit:               official("FileInit", FamilyFile),
	CommandFileCheck:              official("FileCheck", FamilyFile),
	CommandFileBegin:              official("FileBegin", FamilyFile),
	CommandFileData:               official("FileData", FamilyFile),
	CommandFileFinish:             official("FileFinish", FamilyFile),
	CommandAppSideload:            official("AppSideload", FamilyFile),
	CommandFileMode:               official("FileMode", FamilyFile),
	CommandDirMode:                official("DirMode", FamilyFile),
	CommandAppInit:                official("AppInit", FamilyApp),
	CommandAppCheck:               official("AppCheck", FamilyApp),
	CommandAppBegin:               official("AppBegin", FamilyApp),
	CommandAppData:                official("AppData", FamilyApp),
	CommandAppFinish:              official("AppFinish", FamilyApp),
	CommandAppUninstall:           official("AppUninstall", FamilyApp),
	CommandFlashUpdateInit:        official("FlashdUpdateInit", FamilyFlash),
	CommandFlashFlashInit:         official("FlashdFlashInit", FamilyFlash),
	CommandFlashCheck:             official("FlashdCheck", FamilyFlash),
	CommandFlashBegin:             official("FlashdBegin", FamilyFlash),
	CommandFlashData:              official("FlashdData", FamilyFlash),
	CommandFlashFinish:            official("FlashdFinish", FamilyFlash),
	CommandFlashErase:             official("FlashdErase", FamilyFlash),
	CommandFlashFormat:            official("FlashdFormat", FamilyFlash),
	CommandFlashProgress:          official("FlashdProgress", FamilyFlash),
	CommandHeartbeatMessage:       official("HeartbeatMsg", FamilyHeartbeat),
}

var legacyCommands = map[Command]CommandDescriptor{
	CommandLegacyKernelServerKill:   legacyAlias("LegacyKernelServerKill", FamilyKernel),
	CommandLegacyClientKeyGenerate:  legacyAlias("LegacyClientKeyGenerate", FamilyKernel),
	CommandLegacyUnityTerminate:     legacyAlias("LegacyUnityTerminate", FamilyUnity),
	CommandLegacyForwardRportInit:   legacyAlias("LegacyForwardRportInit", FamilyForward),
	CommandLegacyForwardRportList:   legacyAlias("LegacyForwardRportList", FamilyForward),
	CommandLegacyForwardRportRemove: legacyAlias("LegacyForwardRportRemove", FamilyForward),
	CommandLegacyFileRecvInit:       legacyAlias("LegacyFileRecvInit", FamilyFile),
	CommandLegacyUartFinish:         legacyAlias("LegacyUartFinish", FamilyFlash),
}

func official(name string, family Family) CommandDescriptor {
	return CommandDescriptor{Name: name, Family: family, Origin: CommandOriginOfficial}
}

func legacyAlias(name string, family Family) CommandDescriptor {
	return CommandDescriptor{Name: name, Family: family, Origin: CommandOriginLegacy}
}

// LookupCommand 查命令描述符，先查现行命令表再查遗留别名表；未知命令返回 false。
func LookupCommand(command Command) (CommandDescriptor, bool) {
	if descriptor, ok := officialCommands[command]; ok {
		return descriptor, true
	}
	descriptor, ok := legacyCommands[command]
	return descriptor, ok
}

// CommandFamily 返回命令所属族，未登记的命令归入 FamilyUnknown（由 gateway fail-closed）。
func CommandFamily(command Command) Family {
	if descriptor, ok := LookupCommand(command); ok {
		return descriptor.Family
	}
	return FamilyUnknown
}
