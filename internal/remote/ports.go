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
	mu        sync.Mutex
}

func newPortPool(host string, minPort, maxPort int) *portPool {
	ports := make([]int, 0, maxPort-minPort+1)
	for port := minPort; port <= maxPort; port++ {
		ports = append(ports, port)
	}
	return &portPool{
		host: host, minPort: minPort, maxPort: maxPort,
		available: ports, reserved: make(map[int]struct{}),
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
	return fmt.Errorf("port %d is not available", port)
}

// allocate 取一个可用且当前确实能监听的端口：逐个试 Listen 以跳过被系统其它进程占用的端口，避免后续 gateway 监听失败。
func (p *portPool) allocate() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.available) > 0 {
		port := p.available[0]
		p.available = p.available[1:]
		listener, err := net.Listen("tcp", net.JoinHostPort(p.host, strconv.Itoa(port)))
		if err != nil {
			// 端口被占用则丢弃（不放回），继续尝试下一个。
			continue
		}
		_ = listener.Close()
		p.reserved[port] = struct{}{}
		return port, nil
	}
	return 0, fmt.Errorf("proxy port pool is exhausted")
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
