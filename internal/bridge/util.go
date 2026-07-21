package bridge

import "strings"

// quoteCommandArg 为传给主 HDC client-channel 的命令参数做最小化引用：
// 仅当参数含空白或双引号时才加双引号并转义内部双引号，避免路径含空格时被主 HDC 拆成多参。
// file 与 app 两族桥接共用同一规则。
func quoteCommandArg(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\r\n\"") {
		return value
	}
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

// hasUnsafeText 判定文本是否含会破坏命令行或协议帧的危险控制字符（NUL/CR/LF）。
// file、app 等族在把远端传入的路径/包名拼进主 HDC 命令前统一用它做 fail-closed 校验。
func hasUnsafeText(value string) bool {
	return strings.ContainsAny(value, "\x00\r\n")
}
