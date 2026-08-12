package policy

import "strings"

// shell 安全阀只拦截可证实的设备侧高危操作，
// HDC 协议级命令由帧级安全阀（InspectFrameCommand）负责。
//
// 判定分两步：先由 lexShellSegments 按真实 shell 语义把命令串切成段（处理引号、转义、
// 重定向目标与管道关系），再由 resolveCommands 解出每段的候选可执行名。
// 「这条命令是什么」一律由候选可执行名回答，不再拿原始字符串做子串匹配；
// 参数层面的判定（关键路径、挂载选项、dd 输出目标等）仍在该段已去引号的 tokens 上进行。
// 这样可以避免「静态判定看到的命令」与「设备实际执行的命令」不一致导致的绕过。
//
// 本模块是尽力而为的高危黑名单，不是沙箱：它按 shell 语义重新解析命令串，
// 而设备执行的是原始字节，两种解释之间的任何缝隙都是潜在绕过。因此在拿不准时一律从严。

var (
	hdcPropertyPrefixes   = []string{"persist.hdc", "const.hdc"}
	sensitiveMountTargets = []string{"/", "/system", "/system_ext", "/vendor", "/product", "/odm", "/cust", "/chip_prod"}
	sensitiveWritePaths   = []string{"/dev/block", "/system", "/system_ext", "/vendor", "/product", "/odm", "/cust", "/chip_prod"}
	criticalRemovalPaths  = []string{
		"/", "/system", "/system_ext", "/vendor", "/product", "/odm", "/cust", "/chip_prod",
		"/data/system", "/data/property", "/data/misc",
	}
)

// shellKeywords 是可以出现在命令位、其后才是真正可执行名的 shell 关键字，
// 用于识别 `if true; then reboot; fi` 这类把高危命令藏在复合语句里的写法。
// "--" 是选项终止符，其后才是真正的命令（`sh -c -- reboot`），一并跳过。
var shellKeywords = map[string]struct{}{
	"if": {}, "then": {}, "else": {}, "elif": {}, "fi": {},
	"do": {}, "done": {}, "while": {}, "until": {}, "for": {}, "select": {},
	"case": {}, "esac": {}, "in": {}, "function": {}, "time": {}, "!": {}, "--": {},
}

// argumentWrappers 是「把后续参数当作命令执行」的包装器。这类包装器参数元数不固定
// （`timeout 5 cmd`、`nice -n 1 cmd`、`xargs cmd`），无法可靠定位命令位，
// 因此其后所有词都当作候选可执行名。
//
// 代价是包装器的普通参数也会被当成命令名匹配，
// 例如 `nohup cat /data/local/tmp/reboot` 会因 basename 撞上 reboot 而被拦。
// 这类误伤是有意接受的：反过来漏判意味着 `timeout 5 reboot` 直接放行。
var argumentWrappers = map[string]struct{}{
	"command": {}, "exec": {}, "nohup": {}, "setsid": {}, "eval": {}, "xargs": {},
	"stdbuf": {}, "nice": {}, "ionice": {}, "timeout": {}, "runcon": {}, "chroot": {},
	"unshare": {}, "watch": {}, "script": {}, "strace": {}, "ltrace": {}, "taskset": {},
	"flock": {}, "sudo": {}, "doas": {}, "proot": {},
}

// maxInlineDepth 限制 `sh -c` 内联命令的递归展开层数，防止深层嵌套耗尽调用栈；
// 超限的段按无法静态解析处理（indirect），走 fail-closed。
const maxInlineDepth = 8

// shellSegment 是按 shell 分隔符切出的一段命令及其判定所需的上下文。
type shellSegment struct {
	tokens    []string // 已去引号、已展开转义的词
	redirects []string // 本段 > / >> 的写入目标
	commands  []string // 候选可执行名（已剥离路径前缀）
	pipedIn   bool     // 本段 stdin 来自管道
	indirect  bool     // 命令位是替换/展开结果，无法静态解析
}

func (s shellSegment) isEmpty() bool {
	return len(s.tokens) == 0 && len(s.redirects) == 0 && !s.indirect
}

// shellRule 是 shell 高危拦截的一条声明式规则。
type shellRule struct {
	name  string
	match func(segments []shellSegment) bool
}

// coreShellRules 是所有 profile 都启用的核心高危拦截规则。
var coreShellRules = []shellRule{
	{"indirect-command", hasIndirectCommand},
	{"power-control", isPowerControlCommand},
	{"hdc-daemon-state", changesHdcDaemonState},
	{"kill-hdcd", killsHdcDaemon},
	{"remount-fs", remountsFilesystem},
	{"remove-critical-path", removesCriticalPath},
	{"write-device-node", writesDeviceNode},
}

// restrictedExecutables 是 restricted 档位额外禁止的可执行名（网络下载/外连工具）。
var restrictedExecutables = []string{"curl", "wget", "nc", "ncat", "telnet", "ftp", "tftp"}

// InspectShell 按 profile 对 shell 命令做高危操作拦截。
// 核心规则对所有 profile 生效；restricted 档位额外禁网络工具；配置追加的禁止可执行名对所有 profile 生效。
func (p *Policy) InspectShell(profile Profile, command string) Decision {
	segments := analyzeShellCommand(command)
	if len(segments) == 0 {
		return allow()
	}
	for _, rule := range coreShellRules {
		if rule.match(segments) {
			return deny(rule.name)
		}
	}
	if resolveProfile(profile) == ProfileRestricted {
		if hit := matchAnyExecutable(segments, restrictedExecutables); hit != "" {
			return deny("restricted-exec:" + hit)
		}
	}
	if hit := p.matchExtraExecutable(segments); hit != "" {
		return deny("extra-denied:" + hit)
	}
	return allow()
}

// InspectShellCommand 用默认策略与默认档位做 shell 判定（包级兼容入口，行为等价 studio-debug）。
func InspectShellCommand(command string) Decision {
	return defaultPolicy.InspectShell(ProfileStudioDebug, command)
}

// FirstExecutable 返回命令中第一个可解析出的可执行名（剥离包装器、赋值前缀与路径），仅用于审计摘要。
// 取的是首个能解析出名字的段，而非严格的第一段：`; ls` 会返回 ls，`env` 这种解析不出名字的返回空串。
func FirstExecutable(command string) string {
	for _, segment := range analyzeShellCommand(command) {
		for _, name := range segment.commands {
			// 包装器只是壳，审计摘要要的是它包着的那个命令。
			if isArgumentWrapper(name) {
				continue
			}
			return name
		}
	}
	return ""
}

// analyzeShellCommand 把原始命令串切段并解出各段候选可执行名。
func analyzeShellCommand(command string) []shellSegment {
	segments := lexShellSegments(strings.ToLower(command))
	return expandSegments(segments, 0)
}

// expandSegments 解析各段候选可执行名，并把 `sh -c` 的内联命令递归展开为独立段一并判定。
func expandSegments(segments []shellSegment, depth int) []shellSegment {
	result := make([]shellSegment, 0, len(segments))
	for _, segment := range segments {
		segment.commands = resolveCommands(segment.tokens, 0)
		result = append(result, segment)
		inline := inlineShellCommand(segment.tokens)
		if inline == "" {
			continue
		}
		if depth >= maxInlineDepth {
			// 嵌套过深不再展开，按无法静态解析处理，避免深层嵌套既耗栈又绕过判定。
			result = append(result, shellSegment{indirect: true})
			continue
		}
		result = append(result, expandSegments(lexShellSegments(inline), depth+1)...)
	}
	return result
}

// lexShellSegments 单趟扫描切分命令串：识别引号、反斜杠转义、命令分隔符、
// 重定向目标与命令替换边界。换行、回车与 NUL 与 `;` 同为命令分隔符，
// 不能折叠成空格，否则换行后的命令会退化成前一条命令的参数而逃过判定。
//
// 双引号只抑制分词与分隔符，不抑制命令替换：真实 shell 会展开 "$(...)" 与 "`...`"，
// 若把双引号内一律当字面量，`echo "$(reboot)"` 这类命令就完全看不见了。
func lexShellSegments(command string) []shellSegment {
	runes := []rune(command)
	var segments []shellSegment
	var current shellSegment
	var token strings.Builder
	singleQuoted, doubleQuoted := false, false
	// substitutionDepth/inBacktick 记录当前是否位于命令替换内部；
	// 替换内部即使被双引号包着也要正常分词。
	substitutionDepth, inBacktick := 0, false
	pendingRedirect := false
	// tokenStarted 区分「没有词」与「空词」：`> "" cmd` 里的 "" 是一个空的重定向目标，
	// 只看 token.Len() 会把 pendingRedirect 一直挂着，把后面的命令误当成重定向目标。
	tokenStarted := false

	flushToken := func() {
		if !tokenStarted {
			return
		}
		value := token.String()
		token.Reset()
		tokenStarted = false
		if pendingRedirect {
			current.redirects = append(current.redirects, value)
			pendingRedirect = false
			return
		}
		current.tokens = append(current.tokens, value)
	}
	flushSegment := func(nextPiped bool) {
		flushToken()
		emitted := !current.isEmpty()
		if emitted {
			segments = append(segments, current)
		}
		piped := nextPiped
		if !emitted && !nextPiped {
			// 空段不改变管道关系：`cmd | (sh)` 与跨行管道里，
			// 括号/换行只是分隔符，不该把 sh 的「输入来自管道」抹掉。
			piped = current.pipedIn
		}
		current = shellSegment{pipedIn: piped}
		pendingRedirect = false
	}
	writeRune := func(value rune) {
		token.WriteRune(value)
		tokenStarted = true
	}

	for index := 0; index < len(runes); index++ {
		value := runes[index]
		// 双引号内的字面量模式：仅当不在命令替换内部时才生效。
		literal := doubleQuoted && substitutionDepth == 0 && !inBacktick
		switch {
		case singleQuoted:
			if value == '\'' {
				singleQuoted = false
				continue
			}
			writeRune(value)
		case value == '\\' && index+1 < len(runes):
			// 转义符：取下一个字符的字面值，使 `\reboot` / `re\boot` 与 `reboot` 判定一致。
			index++
			writeRune(runes[index])
		case value == '\'' && !literal:
			singleQuoted = true
			tokenStarted = true
		case value == '"':
			doubleQuoted = !doubleQuoted
			tokenStarted = true
		case value == '$' && index+1 < len(runes) && runes[index+1] == '(':
			index++
			substitutionDepth++
			markCommandSubstitution(&current, tokenStarted)
			flushSegment(false)
		case value == '`':
			inBacktick = !inBacktick
			markCommandSubstitution(&current, tokenStarted)
			flushSegment(false)
		case value == ')' && substitutionDepth > 0:
			substitutionDepth--
			flushSegment(false)
		case literal:
			writeRune(value)
		case value == '|':
			// `>|` 是强制覆盖重定向，这里的 | 属于重定向符而非管道。
			if pendingRedirect {
				continue
			}
			// `||` 是逻辑或，不构成管道。
			if index+1 < len(runes) && runes[index+1] == '|' {
				index++
				flushSegment(false)
				continue
			}
			flushSegment(true)
		case isSegmentSeparator(value):
			flushSegment(false)
		case value == '>':
			flushToken()
			pendingRedirect = true
		case isTokenSeparator(value):
			flushToken()
		default:
			writeRune(value)
		}
	}
	flushSegment(false)
	if singleQuoted || doubleQuoted {
		// 引号未闭合时无法按 shell 语义可靠分段，未闭合的引号会把后面的命令
		// 整个吞进一个词里。去掉引号再扫一遍并把结果并入，走 fail-closed。
		segments = append(segments, lexShellSegments(stripQuotes(command))...)
	}
	return segments
}

// stripQuotes 把引号替换为空格，用于未闭合引号时的兜底重扫。
// 替换结果不含引号，重扫必然终止。
func stripQuotes(command string) string {
	return strings.NewReplacer(`"`, " ", "'", " ").Replace(command)
}

// markCommandSubstitution 在命令替换出现于命令位时标记该段无法静态解析。
func markCommandSubstitution(segment *shellSegment, tokenStarted bool) {
	if len(segment.tokens) == 0 && !tokenStarted {
		segment.indirect = true
	}
}

func isSegmentSeparator(value rune) bool {
	return value == ';' || value == '&' || value == '(' || value == ')' ||
		value == '\n' || value == '\r' || value == '\x00'
}

func isTokenSeparator(value rune) bool {
	return value == ' ' || value == '\t' || value == '\f' || value == '\v' ||
		value == '<' || value == '{' || value == '}'
}

// resolveCommands 解出一段 tokens 的候选可执行名：跳过环境赋值与 shell 关键字，
// 展开 env/applet/`sh -c` 包装器；对参数元数不定的包装器返回其后全部词。
func resolveCommands(tokens []string, start int) []string {
	index := start
	for {
		index = skipAssignmentsAndKeywords(tokens, index)
		if index >= len(tokens) {
			return nil
		}
		command := baseExecutable(tokens[index])
		switch {
		case command == "env":
			index = skipEnvironmentCommandArguments(tokens, index+1)
		case isAppletDispatcher(command):
			if index+1 >= len(tokens) {
				return nil
			}
			return resolveCommands(tokens, index+1)
		case isStringCommandWrapper(command):
			if inline := findInlineFlagIndex(tokens, index+1); inline >= 0 && inline+1 < len(tokens) {
				return resolveCommands(tokens, inline+1)
			}
			return []string{command}
		case isArgumentWrapper(command):
			return collectBasenames(command, tokens[index+1:])
		default:
			return []string{command}
		}
	}
}

func collectBasenames(command string, rest []string) []string {
	commands := make([]string, 0, len(rest)+1)
	commands = append(commands, command)
	for _, token := range rest {
		commands = append(commands, baseExecutable(token))
	}
	return commands
}

func skipAssignmentsAndKeywords(tokens []string, start int) int {
	index := start
	for index < len(tokens) {
		token := tokens[index]
		if _, keyword := shellKeywords[token]; keyword || isEnvironmentAssignment(token) {
			index++
			continue
		}
		return index
	}
	return index
}

func skipEnvironmentCommandArguments(tokens []string, start int) int {
	index := start
	for index < len(tokens) {
		token := tokens[index]
		if isEnvironmentAssignment(token) || strings.HasPrefix(token, "-") {
			index++
			continue
		}
		break
	}
	return index
}

// isEnvironmentAssignment 按 shell 变量名规则（[A-Za-z_][A-Za-z0-9_]*=）判断赋值前缀。
func isEnvironmentAssignment(token string) bool {
	equalsIndex := strings.Index(token, "=")
	if equalsIndex <= 0 {
		return false
	}
	for position := 0; position < equalsIndex; position++ {
		character := token[position]
		switch {
		case character == '_',
			character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z':
		case position > 0 && character >= '0' && character <= '9':
		default:
			return false
		}
	}
	return true
}

func isArgumentWrapper(command string) bool {
	_, wrapper := argumentWrappers[command]
	return wrapper
}

func isAppletDispatcher(command string) bool {
	return command == "toybox" || command == "busybox" || command == "toolbox"
}

func isStringCommandWrapper(command string) bool {
	return command == "sh" || command == "bash" || command == "mksh" || command == "toysh" || command == "su"
}

// findInlineFlagIndex 定位 shell 包装器的内联命令开关。除精确的 `-c` 外，
// 还要识别 `-xc` 这类组合短选项，否则 `sh -xc reboot` 可绕过判定。
func findInlineFlagIndex(tokens []string, start int) int {
	for index := start; index < len(tokens); index++ {
		token := tokens[index]
		if token == "--" {
			return -1
		}
		if len(token) > 1 && token[0] == '-' && token[1] != '-' && strings.ContainsRune(token[1:], 'c') {
			return index
		}
	}
	return -1
}

// inlineShellCommand 取出 `sh -c <command>` 的内联命令串，供递归展开判定。
//
// 直接在整段里搜索 shell 包装器，而不是沿命令位逐层剥：包装器的操作数个数不固定
// （`timeout 5 sh -c ...`、`nice -n 1 sh -c ...`、`chroot / sh -c ...`），
// 按命令位推进会停在操作数上，从而完全看不到后面的 `sh -c`。
func inlineShellCommand(tokens []string) string {
	for index := range tokens {
		if !isStringCommandWrapper(baseExecutable(tokens[index])) {
			continue
		}
		flag := findInlineFlagIndex(tokens, index+1)
		if flag < 0 || flag+1 >= len(tokens) {
			continue
		}
		return strings.Join(tokens[flag+1:], " ")
	}
	return ""
}

// hasIndirectCommand 拦截命令位无法静态解析的写法：命令替换结果、变量展开，
// 以及从管道读取命令的 shell（`echo ... | sh`）。这类写法可以承载任意命令，
// 放行等于让整张高危黑名单失效。
//
// 检查全部候选可执行名而不只是第一个：包装器段的候选形如 [nohup, sh]，
// 只看首个就只能看到包装器本身，`... | nohup sh`、`nohup $a` 都会漏过。
// 代价是包装器参数里的变量展开也会被拦（如 `nohup echo $HOME`），属于可接受的误伤。
func hasIndirectCommand(segments []shellSegment) bool {
	for _, segment := range segments {
		if segment.indirect {
			return true
		}
		for _, command := range segment.commands {
			if strings.ContainsRune(command, '$') {
				return true
			}
			if segment.pipedIn && isStringCommandWrapper(command) {
				return true
			}
		}
	}
	return false
}

func isPowerControlCommand(segments []shellSegment) bool {
	return segmentsHaveExecutable(segments, "reboot") || segmentsHaveExecutable(segments, "poweroff")
}

func changesHdcDaemonState(segments []shellSegment) bool {
	for _, segment := range segments {
		parameterWrite := segmentHasExecutable(segment, "param") && containsToken(segment.tokens, "set") &&
			containsTokenWithPrefix(segment.tokens, hdcPropertyPrefixes)
		propertyWrite := segmentHasExecutable(segment, "setprop") && containsTokenWithPrefix(segment.tokens, hdcPropertyPrefixes)
		if parameterWrite || propertyWrite {
			return true
		}
	}
	return false
}

// killsHdcDaemon 在整条命令范围内关联判定：只要任一段的可执行名是结束进程的命令，
// 且任一段的词里出现 hdcd，即拦截。这样 `kill -9 $(pidof hdcd)` 这类目标落在
// 替换子命令里的写法也能覆盖。代价是跨段误关联，
// 例如 `ps -ef | grep hdcd; kill 1234` 也会被拦。
func killsHdcDaemon(segments []shellSegment) bool {
	killer, daemon := false, false
	for _, segment := range segments {
		if segmentHasExecutable(segment, "kill") || segmentHasExecutable(segment, "killall") ||
			segmentHasExecutable(segment, "pkill") {
			killer = true
		}
		if containsHdcDaemonToken(segment.tokens) {
			daemon = true
		}
	}
	return killer && daemon
}

func remountsFilesystem(segments []shellSegment) bool {
	for _, segment := range segments {
		if segmentHasExecutable(segment, "mount") && hasRemountOption(segment.tokens) &&
			hasSensitiveMountTarget(segment.tokens) {
			return true
		}
	}
	return false
}

// removesCriticalPath 只要求递归标志：非交互 shell 下 `rm -r` 同样会无提示删除。
func removesCriticalPath(segments []shellSegment) bool {
	for _, segment := range segments {
		if segmentHasExecutable(segment, "rm") && hasRecursiveOption(segment.tokens) &&
			hasCriticalPathArgument(segment.tokens) {
			return true
		}
	}
	return false
}

func writesDeviceNode(segments []shellSegment) bool {
	for _, segment := range segments {
		if segmentHasExecutable(segment, "dd") && hasDangerousOutputOption(segment.tokens) {
			return true
		}
		for _, target := range segment.redirects {
			if isPathUnderAny(target, sensitiveWritePaths) {
				return true
			}
		}
	}
	return false
}

// matchExtraExecutable 检查各段候选可执行名是否在配置追加的禁止集内，命中返回其名称。
func (p *Policy) matchExtraExecutable(segments []shellSegment) string {
	if len(p.extraExecutables) == 0 {
		return ""
	}
	for _, segment := range segments {
		for _, command := range segment.commands {
			if _, denied := p.extraExecutables[command]; denied {
				return command
			}
		}
	}
	return ""
}

// matchAnyExecutable 返回 segments 中首个命中 executables 列表的可执行名。
func matchAnyExecutable(segments []shellSegment, executables []string) string {
	for _, executable := range executables {
		if segmentsHaveExecutable(segments, executable) {
			return executable
		}
	}
	return ""
}

func segmentsHaveExecutable(segments []shellSegment, executable string) bool {
	for _, segment := range segments {
		if segmentHasExecutable(segment, executable) {
			return true
		}
	}
	return false
}

func segmentHasExecutable(segment shellSegment, executable string) bool {
	for _, command := range segment.commands {
		if command == executable {
			return true
		}
	}
	return false
}

// baseExecutable 剥离路径前缀，返回可执行名 basename。
func baseExecutable(token string) string {
	if slash := strings.LastIndex(token, "/"); slash >= 0 {
		return token[slash+1:]
	}
	return token
}

func containsToken(tokens []string, expected string) bool {
	for _, token := range tokens {
		if token == expected {
			return true
		}
	}
	return false
}

func containsTokenWithPrefix(tokens, prefixes []string) bool {
	for _, token := range tokens {
		for _, prefix := range prefixes {
			if strings.HasPrefix(token, prefix) {
				return true
			}
		}
	}
	return false
}

func containsHdcDaemonToken(tokens []string) bool {
	for _, token := range tokens {
		if baseExecutable(token) == "hdcd" {
			return true
		}
	}
	return false
}

func hasRemountOption(tokens []string) bool {
	for index, token := range tokens {
		switch {
		case token == "remount" || token == "--remount":
			return true
		case token == "-o" || token == "--options":
			if index+1 < len(tokens) && containsCommaOption(tokens[index+1], "remount") {
				return true
			}
		case strings.HasPrefix(token, "--options="):
			if containsCommaOption(strings.TrimPrefix(token, "--options="), "remount") {
				return true
			}
		case strings.HasPrefix(token, "-o") && token != "-o":
			if containsCommaOption(strings.TrimPrefix(token, "-o"), "remount") {
				return true
			}
		}
	}
	return false
}

func containsCommaOption(optionText, expected string) bool {
	for _, option := range strings.Split(optionText, ",") {
		if option == expected {
			return true
		}
	}
	return false
}

func hasSensitiveMountTarget(tokens []string) bool {
	for _, token := range tokens {
		if isPathUnderAny(token, sensitiveMountTargets) || isSensitiveBlockPartition(token) {
			return true
		}
	}
	return false
}

func isSensitiveBlockPartition(token string) bool {
	return strings.HasPrefix(token, "/dev/block") &&
		(strings.Contains(token, "/by-name/system") ||
			strings.Contains(token, "/by-name/vendor") ||
			strings.Contains(token, "/by-name/product") ||
			strings.Contains(token, "/by-name/odm"))
}

// hasRecursiveOption 精确解析长短选项，避免 `--force` 因含字母 r 被误判为递归。
func hasRecursiveOption(tokens []string) bool {
	for _, token := range tokens {
		if len(token) < 2 || token[0] != '-' {
			continue
		}
		if strings.HasPrefix(token, "--") {
			if token == "--recursive" {
				return true
			}
			continue
		}
		if strings.ContainsAny(token[1:], "rR") {
			return true
		}
	}
	return false
}

func hasCriticalPathArgument(tokens []string) bool {
	for _, token := range tokens {
		normalizedPath := normalizePathToken(token)
		if normalizedPath == "/data" || isPathUnderAny(normalizedPath, criticalRemovalPaths) {
			return true
		}
	}
	return false
}

func hasDangerousOutputOption(tokens []string) bool {
	for _, token := range tokens {
		if strings.HasPrefix(token, "of=") && isPathUnderAny(strings.TrimPrefix(token, "of="), sensitiveWritePaths) {
			return true
		}
	}
	return false
}

func isPathUnderAny(value string, roots []string) bool {
	normalizedPath := normalizePathToken(value)
	for _, root := range roots {
		if normalizedPath == root || (root != "/" && strings.HasPrefix(normalizedPath, root+"/")) {
			return true
		}
	}
	return false
}

func normalizePathToken(token string) string {
	normalized := token
	for len(normalized) > 1 && strings.HasSuffix(normalized, "/") {
		normalized = normalized[:len(normalized)-1]
	}
	return normalized
}
