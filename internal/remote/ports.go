package remote

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
)

// portPool 管理 [minPort, maxPort] 范围内的稳定代理端口分配。
// 端口一旦分配给某设备 Binding 即从 available 移入 reserved，只有 Binding 显式 RELEASED 才 release 回池，
// 保证同一设备重复 acquire 时尽量拿到同一稳定端口（配合 store 快照恢复）。
type portPool struct {
	host      string
	minPort   int
	maxPort   int
	available []int
	reserved  map[int]struct{}
	// blocked 记录探测时被其它进程占用的端口。这类占用往往是暂时的（对端 TIME_WAIT、
	// 另一进程短暂绑定），直接丢弃会让端口池只减不增，长时间运行后必然耗尽且无法自愈。
	blocked map[int]struct{}
	mu      sync.Mutex
}

func newPortPool(host string, minPort, maxPort int) *portPool {
	ports := make([]int, 0, maxPort-minPort+1)
	for port := minPort; port <= maxPort; port++ {
		ports = append(ports, port)
	}
	return &portPool{
		host: host, minPort: minPort, maxPort: maxPort,
		available: ports, reserved: make(map[int]struct{}), blocked: make(map[int]struct{}),
	}
}

// reserve 占用一个指定端口（用于从 JSON 快照恢复已有 Binding）；越界、重复或不在可用集内均报错。
func (p *portPool) reserve(port int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if port < p.minPort || port > p.maxPort {
		return fmt.Errorf("port %d is outside configured range", port)
	}
	if _, exists := p.reserved[port]; exists {
		return fmt.Errorf("port %d is already reserved", port)
	}
	for index, candidate := range p.available {
		if candidate != port {
			continue
		}
		p.available = append(p.available[:index], p.available[index+1:]...)
		p.reserved[port] = struct{}{}
		return nil
	}
	if p.takeBlockedLocked(port) {
		p.reserved[port] = struct{}{}
		return nil
	}
	return fmt.Errorf("port %d is not available", port)
}

// allocate 取一个可用且当前确实能监听的端口：逐个试 Listen 以跳过被系统其它进程占用的端口，避免后续 gateway 监听失败。
// 被占用的端口移入 blocked，等本轮候选耗尽时再整体放回重试，使暂时性占用能够自愈。
// 探测在锁外进行：Listen/Close 是系统调用，持锁执行会把整个端口池串行阻塞在其上。
func (p *portPool) allocate() (int, error) {
	if port, err := p.allocateOnce(); err == nil {
		return port, nil
	}
	// 可用集跑空了：把之前探测失败的端口放回去再试一轮，
	// 它们的占用可能已经解除。仍然拿不到才算真的耗尽。
	p.mu.Lock()
	retryable := len(p.blocked) > 0 || len(p.available) > 0
	p.recycleBlockedLocked()
	p.mu.Unlock()
	if !retryable {
		return 0, fmt.Errorf("proxy port pool is exhausted")
	}
	return p.allocateOnce()
}

// allocateOnce 遍历一遍当前可用集，返回第一个能成功监听的端口。
// 端口在探测前就登记进 reserved，探测失败再转入 blocked：
// 这样它在任何时刻都归属于某个集合，reserve 不会在探测窗口里查无此端口。
func (p *portPool) allocateOnce() (int, error) {
	for {
		p.mu.Lock()
		if len(p.available) == 0 {
			p.mu.Unlock()
			return 0, fmt.Errorf("proxy port pool is exhausted")
		}
		port := p.available[0]
		p.available = p.available[1:]
		p.reserved[port] = struct{}{}
		p.mu.Unlock()

		listener, err := net.Listen("tcp", net.JoinHostPort(p.host, strconv.Itoa(port)))
		if err != nil {
			p.mu.Lock()
			delete(p.reserved, port)
			p.blocked[port] = struct{}{}
			p.mu.Unlock()
			continue
		}
		_ = listener.Close()
		return port, nil
	}
}

// recycleBlockedLocked 把此前探测失败的端口放回可用集，供下一轮重试。
func (p *portPool) recycleBlockedLocked() {
	if len(p.blocked) == 0 {
		return
	}
	for port := range p.blocked {
		p.available = append(p.available, port)
		delete(p.blocked, port)
	}
	sort.Ints(p.available)
}

// release 把端口归还可用集并保持有序；仅在 Binding 彻底 RELEASED 时调用。
func (p *portPool) release(port int) {
	if port <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.reserved[port]; !exists {
		return
	}
	delete(p.reserved, port)
	p.available = append(p.available, port)
	sort.Ints(p.available)
}

// takeBlockedLocked 把指定端口从 blocked 中取出，供 reserve 使用：
// 快照里的端口可能刚好处于探测失败状态，此时仍应允许恢复它的 Binding。
func (p *portPool) takeBlockedLocked(port int) bool {
	if _, exists := p.blocked[port]; !exists {
		return false
	}
	delete(p.blocked, port)
	return true
}
