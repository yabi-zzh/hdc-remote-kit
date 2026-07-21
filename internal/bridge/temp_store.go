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

// prepareDownload 为 file recv 创建供外部进程（主 HDC）写入的临时目录与路径。
// 与 allocate 不同：不预占配额、不打开文件；下载大小事先未知，落盘后再由 account 登记。
func (s *TempStore) prepareDownload() (*tempAllocation, error) {
	directory, err := os.MkdirTemp(s.root, "file-recv-")
	if err != nil {
		return nil, fmt.Errorf("create transfer temp directory: %w", err)
	}
	path := filepath.Join(directory, "payload")
	return &tempAllocation{store: s, directory: directory, path: path, file: nil, size: 0}, nil
}

// account 在下载完成后按实际文件大小登记配额；超过总量上限返回错误。
func (s *TempStore) account(size int64) error {
	if size < 0 {
		return fmt.Errorf("temporary file size cannot be negative")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if size > s.maxBytes-s.usedBytes {
		return fmt.Errorf("temporary storage quota exceeded")
	}
	s.usedBytes += size
	return nil
}

type tempAllocation struct {
	store     *TempStore
	directory string
	path      string
	file      *os.File
	size      int64

	closeOnce sync.Once
}

func (a *tempAllocation) seal() error {
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

// renameToName 将已 seal 的临时文件在同目录下重命名为 name（仅接受纯 basename）。
// 用于 app install：设备侧 bm install 依赖文件扩展名识别包类型，临时文件默认名 "payload" 无后缀会导致安装失败。
func (a *tempAllocation) renameToName(name string) error {
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
		if a.file != nil {
			_ = a.file.Close()
			a.file = nil
		}
		_ = os.RemoveAll(a.directory)
		a.store.release(a.size)
	})
}
