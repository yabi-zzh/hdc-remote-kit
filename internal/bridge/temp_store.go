package bridge

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// TempStore 管理 file/app 传输的临时目录与总量配额（maxBytes）：
// allocate 预占配额并打开文件（send/install 已知大小），prepareDownload+account 用于事后登记（recv 大小未知）。
type TempStore struct {
	root     string
	maxBytes int64

	mu        sync.Mutex
	usedBytes int64
}

// NewTempStore 在 root 下创建临时目录并初始化总量配额（maxBytes 必须为正），拒绝把文件系统根作为临时根。
func NewTempStore(root string, maxBytes int64) (*TempStore, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("temporary storage limit must be positive")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve transfer temp directory: %w", err)
	}
	if filepath.Dir(absoluteRoot) == absoluteRoot {
		return nil, fmt.Errorf("transfer temp directory cannot be a filesystem root")
	}
	if err := os.MkdirAll(absoluteRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create transfer temp directory: %w", err)
	}
	return &TempStore{root: absoluteRoot, maxBytes: maxBytes}, nil
}

func (s *TempStore) allocate(size int64) (*tempAllocation, error) {
	if size < 0 {
		return nil, fmt.Errorf("temporary file size cannot be negative")
	}
	s.mu.Lock()
	if size > s.maxBytes-s.usedBytes {
		s.mu.Unlock()
		return nil, fmt.Errorf("temporary storage quota exceeded")
	}
	s.usedBytes += size
	s.mu.Unlock()

	directory, err := os.MkdirTemp(s.root, "file-send-")
	if err != nil {
		s.release(size)
		return nil, fmt.Errorf("create transfer temp directory: %w", err)
	}
	path := filepath.Join(directory, "payload")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		_ = os.RemoveAll(directory)
		s.release(size)
		return nil, fmt.Errorf("create transfer temp file: %w", err)
	}
	return &tempAllocation{store: s, directory: directory, path: path, file: file, size: size}, nil
}

func (s *TempStore) release(size int64) {
	s.mu.Lock()
	s.usedBytes -= size
	if s.usedBytes < 0 {
		s.usedBytes = 0
	}
	s.mu.Unlock()
}

// reserveExtra 无条件补记超出预留的部分。调用点在文件已经落盘之后，
// 此时拒绝也收不回磁盘占用，如实记账比让计数偏小更安全。
func (s *TempStore) reserveExtra(size int64) {
	s.mu.Lock()
	s.usedBytes += size
	s.mu.Unlock()
}

// prepareDownload 为 file recv 创建供外部进程（主 HDC）写入的临时目录与路径。
// 下载大小事先未知，因此按上限 reserve 预占配额，落盘后再由 settle 调整为实际大小。
// 不预占的话，多个并发 recv 各自绕过配额，峰值占用可以是配额的任意倍。
func (s *TempStore) prepareDownload(reserve int64) (*tempAllocation, error) {
	if reserve <= 0 {
		return nil, fmt.Errorf("temporary download reservation must be positive")
	}
	s.mu.Lock()
	if reserve > s.maxBytes-s.usedBytes {
		s.mu.Unlock()
		return nil, fmt.Errorf("temporary storage quota exceeded")
	}
	s.usedBytes += reserve
	s.mu.Unlock()

	directory, err := os.MkdirTemp(s.root, "file-recv-")
	if err != nil {
		s.release(reserve)
		return nil, fmt.Errorf("create transfer temp directory: %w", err)
	}
	path := filepath.Join(directory, "payload")
	return &tempAllocation{store: s, directory: directory, path: path, file: nil, size: reserve}, nil
}

type tempAllocation struct {
	store     *TempStore
	directory string

	mu       sync.Mutex
	path     string
	file     *os.File
	size     int64
	released bool

	closeOnce sync.Once
}

// currentPath 返回临时文件当前路径（renameToName 会改动它）。
func (a *tempAllocation) currentPath() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.path
}

// settle 把预占的配额调整为实际占用大小，供 recv 落盘后登记。
// close 已归还配额时不再调整，否则会按已作废的预留值重复归还，把总用量算少。
func (a *tempAllocation) settle(actual int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.released {
		return
	}
	if delta := a.size - actual; delta > 0 {
		a.store.release(delta)
	} else if delta < 0 {
		a.store.reserveExtra(-delta)
	}
	a.size = actual
}

func (a *tempAllocation) seal() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	if err := a.file.Sync(); err != nil {
		return fmt.Errorf("flush transfer temp file: %w", err)
	}
	if err := a.file.Close(); err != nil {
		return fmt.Errorf("close transfer temp file: %w", err)
	}
	a.file = nil
	return nil
}

// write 把一段数据追加写入临时文件。
func (a *tempAllocation) write(data []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return 0, fmt.Errorf("transfer temp file is closed")
	}
	return a.file.Write(data)
}

// writeAt 把一段数据写入临时文件的指定偏移。
func (a *tempAllocation) writeAt(data []byte, offset int64) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return 0, fmt.Errorf("transfer temp file is closed")
	}
	return a.file.WriteAt(data, offset)
}

// renameToName 将已 seal 的临时文件在同目录下重命名为 name（仅接受纯 basename）。
// 用于 app install 与 file send：设备侧按文件名识别包类型/落盘名，
// 临时文件默认名 "payload" 会导致安装失败或写出错误的目标文件名。
func (a *tempAllocation) renameToName(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file != nil {
		return fmt.Errorf("cannot rename an open temp file")
	}
	if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return fmt.Errorf("invalid temp file name %q", name)
	}
	target := filepath.Join(a.directory, name)
	if err := os.Rename(a.path, target); err != nil {
		return fmt.Errorf("rename transfer temp file: %w", err)
	}
	a.path = target
	return nil
}

func (a *tempAllocation) close() {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		if a.file != nil {
			_ = a.file.Close()
			a.file = nil
		}
		size := a.size
		a.size = 0
		a.released = true
		a.mu.Unlock()
		_ = os.RemoveAll(a.directory)
		a.store.release(size)
	})
}
