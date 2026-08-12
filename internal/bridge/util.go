package bridge

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"
)

// tempFileSizePollInterval 是外部进程写入临时文件时的大小巡检周期。
const tempFileSizePollInterval = time.Second

// closeOnContext 在 ctx 结束时调用 closer，返回的 stop 用于在读循环结束后回收看门狗 goroutine。
//
// TargetChannel 的读取是阻塞式的且不设读超时，只有关闭底层 channel 才能把它从阻塞里解出来。
// 因此凡是「带 timeout 的 context + 阻塞读 TargetChannel」的地方都必须挂这个看门狗，
// 否则 context 到期后没有任何东西去关 channel，超时形同虚设，goroutine 与连接会一直挂着。
// stop 只能调用一次，通常紧跟 defer。
func closeOnContext(ctx context.Context, closer func()) (stop func()) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closer()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// drainTargetChannel 读到 channel 结束后关闭它，用于「只关心命令是否执行完、不关心输出」的收尾场景。
// 读取本身是阻塞的，因此必须挂 ctx 看门狗：设备被拔掉或主 HDC 卡住时，
// 没有看门狗的话这个循环会永远停在这里，把等它的 WaitGroup 一起拖住。
func drainTargetChannel(ctx context.Context, target TargetChannel) {
	defer target.Close()
	stop := closeOnContext(ctx, func() { _ = target.Close() })
	defer stop()
	drained := 0
	for {
		payload, err := target.ReadPayload()
		if err != nil {
			return
		}
		if drained += len(payload); drained > forwardCleanupDrainBytes {
			return
		}
	}
}

// watchTempFileSize 周期性巡检由外部进程（主 HDC）写入的临时文件，
// 一旦超过 limit 就调用 abort 中止传输。返回的 stop 可重复调用。
//
// 写入方是另一个进程，本进程无法在写入路径上拦截；不巡检的话，
// 一个超大设备文件会先把本机磁盘写满，才在事后的大小检查里被拒绝。
func watchTempFileSize(ctx context.Context, path string, limit int64, abort func()) (stop func()) {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		ticker := time.NewTicker(tempFileSizePollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				if info, err := os.Stat(path); err == nil && info.Size() > limit {
					abort()
					return
				}
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

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
