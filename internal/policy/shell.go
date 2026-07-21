package policy

import "strings"

// shell 安全阀只拦截可证实的设备侧高危操作，
// HDC 协议级命令由帧级安全阀（InspectFrameCommand）负责。

var (
	hdcPropertyPrefixes   = []string{"persist.hdc", "const.hdc"}
	sensitiveMountTargets = []string{"/", "/system", "/system_ext", "/vendor", "/product", "/odm", "/cust", "/chip_prod"}
	sensitiveWritePaths   = []string{"/dev/block", "/system", "/system_ext", "/vendor", "/product", "/odm", "/cust", "/chip_prod"}
	criticalRemovalPaths  = []string{
		"/", "/system", "/system_ext", "/vendor", "/product", "/odm", "/cust", "/chip_prod",
		"/data/system", "/data/property", "/data/misc",
	}
)

// shellRule 是 shell 高危拦截的一条声明式规则。
type shellRule struct {
	name  string
	match func(normalized string, segments [][]string) bool
}

// coreShellRules 是所有 profile 都启用的核心高危拦截规则。
var coreShellRules = []shellRule{
	{"power-control", func(normalized string, segments [][]string) bool { return isPowerControlCommand(segments) }},
	{"hdc-daemon-state", func(normalized string, segments [][]string) bool { return changesHdcDaemonState(segments) }},
	{"kill-hdcd", func(normalized string, segments [][]string) bool { return killsHdcDaemon(normalized, segments) }},
	{"remount-fs", func(normalized string, segments [][]string) bool { return remountsFilesystem(segments) }},
	{"remove-critical-path", func(normalized string, segments [][]string) bool { return removesCriticalPath(segments) }},
	{"write-device-node", func(normalized string, segments [][]string) bool { return writesDeviceNode(normalized, segments) }},
}

// restrictedExecutables 是 restricted 档位额外禁止的可执行名（网络下载/外连工具）。
var restrictedExecutables = []string{"curl", "wget", "nc", "ncat", "telnet", "ftp", "tftp"}

// InspectShell 按 profile 对规范化后的 shell 命令做高危操作拦截。
// 核心规则对所有 profile 生效；restricted 档位额外禁网络工具；配置追加的禁止可执行名对所有 profile 生效。
func (p *Policy) InspectShell(profile Profile, command string) Decision {
	normalized := normalizeShellCommand(command)
	if normalized == "" {
		return allow()
	}
	segments := splitSegmentTokens(normalized)
	for _, rule := range coreShellRules {
		if rule.match(normalized, segments) {
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

// matchExtraExecutable 检查各段首个可执行名是否在配置追加的禁止集内，命中返回其名称。
func (p *Policy) matchExtraExecutable(segments [][]string) string {
	if len(p.extraExecutables) == 0 {
		return ""
	}
	for _, tokens := range segments {
		index := findCommandIndex(tokens, 0)
		if index < 0 || index >= len(tokens) {
			continue
		}
		if executable := baseExecutable(tokens[index]); executable != "" {
			if _, denied := p.extraExecutables[executable]; denied {
				return executable
			}
		}
	}
	return ""
}

// matchAnyExecutable 返回 segments 中首个命中 executables 列表的可执行名。
func matchAnyExecutable(segments [][]string, executables []string) string {
	for _, executable := range executables {
		if segmentsHaveExecutable(segments, executable) {
			return executable
		}
	}
	return ""
}

// baseExecutable 剥离路径前缀，返回可执行名 basename。
func baseExecutable(token string) string {
	if slash := strings.LastIndex(token, "/"); slash >= 0 {
		return token[slash+1:]
	}
	return token
}

// FirstExecutable 返回 shell 命令首段的可执行名（剥离包装器、赋值前缀与路径），仅用于审计摘要。
func FirstExecutable(command string) string {
	segments := splitSegmentTokens(normalizeShellCommand(command))
	if len(segments) == 0 {
		return ""
	}
	tokens := segments[0]
	index := findCommandIndex(tokens, 0)
	if index < 0 || index >= len(tokens) {
		return ""
	}
	executable := tokens[index]
	if slash := strings.LastIndex(executable, "/"); slash >= 0 {
		executable = executable[slash+1:]
	}
	return executable
}

func isPowerControlCommand(segments [][]string) bool {
	return segmentsHaveExecutable(segments, "reboot") || segmentsHaveExecutable(segments, "poweroff")
}

func changesHdcDaemonState(segments [][]string) bool {
	for _, tokens := range segments {
		parameterWrite := segmentExecutable(tokens, "param") && containsToken(tokens, "set") && containsTokenWithPrefix(tokens, hdcPropertyPrefixes)
		propertyWrite := segmentExecutable(tokens, "setprop") && containsTokenWithPrefix(tokens, hdcPropertyPrefixes)
		if parameterWrite || propertyWrite {
			return true
		}
	}
	return false
}

func killsHdcDaemon(normalized string, segments [][]string) bool {
	if segmentsHaveExecutable(segments, "kill") && containsHdcDaemonWord(normalized) {
		return true
	}
	for _, tokens := range segments {
		if (segmentExecutable(tokens, "killall") || segmentExecutable(tokens, "pkill") || segmentExecutable(tokens, "kill")) &&
			containsHdcDaemonToken(tokens) {
			return true
		}
	}
	return false
}

func remountsFilesystem(segments [][]string) bool {
	for _, tokens := range segments {
		if segmentExecutable(tokens, "mount") && hasRemountOption(tokens) && hasSensitiveMountTarget(tokens) {
			return true
		}
	}
	return false
}

func removesCriticalPath(segments [][]string) bool {
	for _, tokens := range segments {
		if segmentExecutable(tokens, "rm") && hasRecursiveForceOption(tokens) && hasCriticalPathArgument(tokens) {
			return true
		}
	}
	return false
}

func writesDeviceNode(normalized string, segments [][]string) bool {
	for _, tokens := range segments {
		if segmentExecutable(tokens, "dd") && hasDangerousOutputOption(tokens) {
			return true
		}
	}
	return redirectsToSensitivePath(normalized)
}

func segmentsHaveExecutable(segments [][]string, executable string) bool {
	for _, tokens := range segments {
		if segmentExecutable(tokens, executable) {
			return true
		}
	}
	return false
}

func segmentExecutable(tokens []string, executable string) bool {
	index := findCommandIndex(tokens, 0)
	return index >= 0 && index < len(tokens) && matchesExecutable(tokens[index], executable)
}

// findCommandIndex 定位一段 tokens 中真正的可执行位置，跳过环境赋值与包装器（command/exec/nohup/env/applet/sh -c）。
func findCommandIndex(tokens []string, start int) int {
	index := skipEnvironmentAssignments(tokens, start)
	if index >= len(tokens) {
		return -1
	}
	command := tokens[index]
	switch {
	case isDirectWrapper(command):
		return findCommandIndex(tokens, index+1)
	case command == "env":
		return findCommandIndex(tokens, skipEnvironmentCommandArguments(tokens, index+1))
	case isAppletDispatcher(command):
		if index+1 < len(tokens) {
			return index + 1
		}
		return -1
	case isStringCommandWrapper(command):
		inline := findToken(tokens, "-c", index+1)
		if inline >= 0 {
			return findCommandIndex(tokens, inline+1)
		}
		return index
	default:
		return index
	}
}

func findShellWrapperIndex(tokens []string, start int) int {
	index := skipEnvironmentAssignments(tokens, start)
	if index >= len(tokens) {
		return -1
	}
	command := tokens[index]
	switch {
	case isDirectWrapper(command):
		return findShellWrapperIndex(tokens, index+1)
	case command == "env":
		return findShellWrapperIndex(tokens, skipEnvironmentCommandArguments(tokens, index+1))
	case isAppletDispatcher(command):
		if index+1 < len(tokens) {
			return index + 1
		}
		return -1
	default:
		return index
	}
}

func skipEnvironmentAssignments(tokens []string, start int) int {
	index := start
	for index < len(tokens) && isEnvironmentAssignment(tokens[index]) {
		index++
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

func isEnvironmentAssignment(token string) bool {
	equalsIndex := strings.Index(token, "=")
	if equalsIndex <= 0 || strings.HasPrefix(token, "of=") {
		return false
	}
	first := token[0]
	return (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')
}

func isDirectWrapper(command string) bool {
	return command == "command" || command == "exec" || command == "nohup"
}

func isAppletDispatcher(command string) bool {
	return command == "toybox" || command == "busybox" || command == "toolbox"
}

func isStringCommandWrapper(command string) bool {
	return command == "sh" || command == "bash" || command == "mksh" || command == "toysh" || command == "su"
}

func findToken(tokens []string, expected string, start int) int {
	for index := start; index < len(tokens); index++ {
		if tokens[index] == expected {
			return index
		}
	}
	return -1
}

func matchesExecutable(token, executable string) bool {
	return token == executable || strings.HasSuffix(token, "/"+executable)
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
		if token == "hdcd" || strings.HasSuffix(token, "/hdcd") {
			return true
		}
	}
	return false
}

func containsHdcDaemonWord(command string) bool {
	padded := " " + command + " "
	return strings.Contains(padded, " hdcd ") || strings.Contains(padded, "/hdcd ") ||
		strings.Contains(padded, " hdcd)") || strings.Contains(padded, "/hdcd)")
}

func hasRemountOption(tokens []string) bool {
	for index, token := range tokens {
		if token == "remount" {
			return true
		}
		if token == "-o" && index+1 < len(tokens) && containsCommaOption(tokens[index+1], "remount") {
			return true
		}
		if strings.HasPrefix(token, "-o") && containsCommaOption(strings.TrimPrefix(token, "-o"), "remount") {
			return true
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

func hasRecursiveForceOption(tokens []string) bool {
	recursive := false
	force := false
	for _, token := range tokens {
		if strings.HasPrefix(token, "-") {
			recursive = recursive || strings.Contains(token, "r") || token == "--recursive"
			force = force || strings.Contains(token, "f") || token == "--force"
		}
	}
	return recursive && force
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

func redirectsToSensitivePath(command string) bool {
	compact := strings.ReplaceAll(command, " ", "")
	for _, sensitivePath := range sensitiveWritePaths {
		if strings.Contains(compact, ">"+sensitivePath) {
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

// splitSegmentTokens 将命令按 shell 分隔符拆段并分词，同时递归展开 sh -c 内联命令。
func splitSegmentTokens(command string) [][]string {
	var result [][]string
	for _, segment := range splitShellSegments(command) {
		tokens := splitTokens(segment)
		if len(tokens) == 0 {
			continue
		}
		result = append(result, tokens)
		for _, inline := range inlineShellCommand(tokens) {
			result = append(result, splitSegmentTokens(inline)...)
		}
	}
	return result
}

func inlineShellCommand(tokens []string) []string {
	commandIndex := findShellWrapperIndex(tokens, 0)
	if commandIndex < 0 || commandIndex >= len(tokens) || !isStringCommandWrapper(tokens[commandIndex]) {
		return nil
	}
	flagIndex := findToken(tokens, "-c", commandIndex+1)
	if flagIndex < 0 || flagIndex+1 >= len(tokens) {
		return nil
	}
	return []string{strings.Join(tokens[flagIndex+1:], " ")}
}

func splitShellSegments(command string) []string {
	var segments []string
	var segment strings.Builder
	singleQuoted := false
	doubleQuoted := false
	flush := func() {
		if value := strings.TrimSpace(segment.String()); value != "" {
			segments = append(segments, value)
		}
		segment.Reset()
	}
	for _, value := range command {
		switch {
		case value == '\'' && !doubleQuoted:
			singleQuoted = !singleQuoted
			segment.WriteRune(value)
		case value == '"' && !singleQuoted:
			doubleQuoted = !doubleQuoted
			segment.WriteRune(value)
		case !singleQuoted && (isSegmentSeparator(value) || value == '`'):
			flush()
		default:
			segment.WriteRune(value)
		}
	}
	flush()
	return segments
}

func isSegmentSeparator(value rune) bool {
	return value == ';' || value == '|' || value == '&' || value == '(' || value == ')'
}

func splitTokens(command string) []string {
	var tokens []string
	var token strings.Builder
	singleQuoted := false
	doubleQuoted := false
	flush := func() {
		if value := strings.TrimSpace(token.String()); value != "" {
			tokens = append(tokens, value)
		}
		token.Reset()
	}
	for _, value := range command {
		switch {
		case value == '\'' && !doubleQuoted:
			singleQuoted = !singleQuoted
		case value == '"' && !singleQuoted:
			doubleQuoted = !doubleQuoted
		case !singleQuoted && !doubleQuoted && isTokenSeparator(value):
			flush()
		default:
			token.WriteRune(value)
		}
	}
	flush()
	return tokens
}

func isTokenSeparator(value rune) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r' || value == '\f' || value == '\v' ||
		value == '<' || value == '>' || value == '{' || value == '}'
}

func normalizeShellCommand(command string) string {
	replacer := strings.NewReplacer("\x00", " ", "\r", " ", "\n", " ", "\t", " ")
	command = replacer.Replace(command)
	command = strings.Join(strings.Fields(command), " ")
	return strings.ToLower(command)
}
