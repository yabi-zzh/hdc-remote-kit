package hdc

import (
	"fmt"
	"net"
	"sync"
)

// TargetChannel 是一条已握手的主 HDC server client-channel 长连接，
// 绑定到某个 USB 目标设备，用于向设备流式收发某条命令（shell/hilog/file/app/forward 等）的负载。
// 读阻塞、写串行；由各 bridge 族持有并在会话结束时 Close。
type TargetChannel struct {
	conn            net.Conn
	maxPayloadBytes int
	writeMu         sync.Mutex // 串行化写，允许多个 goroutine（读循环与控制路径）并发写同一 channel
	closeOnce       sync.Once
}

// NewTargetChannel 包装一条已完成 channel 握手且已写入命令的连接。
func NewTargetChannel(conn net.Conn, maxPayloadBytes int) *TargetChannel {
	return &TargetChannel{conn: conn, maxPayloadBytes: maxPayloadBytes}
}

// ReadPayload 阻塞读取一帧设备侧负载；连接关闭或对端结束时返回错误，调用方据此结束读循环。
func (c *TargetChannel) ReadPayload() ([]byte, error) {
	return readChannelFrame(c.conn, c.maxPayloadBytes)
}

// WritePayload 向设备写入一帧负载，写操作串行化以支持并发调用。
func (c *TargetChannel) WritePayload(payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := writeChannelFrame(c.conn, payload); err != nil {
		return fmt.Errorf("write target channel payload: %w", err)
	}
	return nil
}

// Close 幂等关闭底层连接，释放该 target channel 对应的主 HDC 会话资源。
func (c *TargetChannel) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.conn.Close()
	})
	return err
}
