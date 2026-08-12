// Package store 以原子写加主备快照持久化稳定 Binding 映射，支持损坏回退与版本校验；活跃 Lease 不持久化。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
)

const bindingSchemaVersion = 1

type bindingSnapshot struct {
	Version  int             `json:"version"`
	Bindings []model.Binding `json:"bindings"`
}

// BindingStore 仅持久化稳定的“设备 → 代理端口”映射；活跃 Lease 有意不持久化（重启后按设备事实重建）。
type BindingStore struct {
	path       string
	backupPath string
	minPort    int
	maxPort    int

	// saveMu 串行化 Save：Save 内部是「写临时文件 → 主文件转备份 → 临时文件转正」的多步序列，
	// 两次 Save 交错会把彼此的中间状态混在一起，可能同时毁掉主文件与备份。
	saveMu sync.Mutex
}

// NewBindingStore 在 stateDir 下管理 bindings.json 及其 .bak 备份；minPort/maxPort 用于恢复时校验端口范围。
func NewBindingStore(stateDir string, minPort, maxPort int) *BindingStore {
	path := filepath.Join(stateDir, "bindings.json")
	return &BindingStore{path: path, backupPath: path + ".bak", minPort: minPort, maxPort: maxPort}
}

// Load 恢复稳定 Binding 快照：主文件有效则用主文件，损坏则退回 .bak 备份，两者都不存在返回空（首次启动），
// 都损坏则返回错误由上层决定是否启动失败（不静默覆盖）。
func (s *BindingStore) Load() ([]model.Binding, error) {
	bindings, primaryErr := s.loadFile(s.path)
	if primaryErr == nil {
		return bindings, nil
	}
	bindings, backupErr := s.loadFile(s.backupPath)
	if backupErr == nil {
		return bindings, nil
	}
	if errors.Is(primaryErr, os.ErrNotExist) && errors.Is(backupErr, os.ErrNotExist) {
		return nil, nil
	}
	return nil, fmt.Errorf("load binding snapshot: primary: %v; backup: %v", primaryErr, backupErr)
}

// Save 原子持久化 Binding 快照：写 .tmp → Flush+Sync → 旧文件转 .bak → rename 替换主文件，
// 保证任意时刻崩溃都能从主文件或备份恢复出一致快照。
func (s *BindingStore) Save(bindings []model.Binding) error {
	normalized, err := s.validate(bindings)
	if err != nil {
		return err
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create binding state directory: %w", err)
	}
	// 固定临时文件名：Save 已由 saveMu 串行化，不会互相踩；
	// 用唯一名字反而会在进程被强杀时留下永远没人清理的残留文件。
	temporaryPath := s.path + ".tmp"
	file, err := os.OpenFile(temporaryPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create binding snapshot: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(bindingSnapshot{Version: bindingSchemaVersion, Bindings: normalized})
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("write binding snapshot: %w", errors.Join(writeErr, closeErr))
	}

	_ = os.Remove(s.backupPath)
	if err := os.Rename(s.path, s.backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("backup binding snapshot: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		_ = os.Rename(s.backupPath, s.path)
		_ = os.Remove(temporaryPath)
		syncDirectory(directory)
		return fmt.Errorf("replace binding snapshot: %w", err)
	}
	// 文件内容已 Sync，但把它挂上去的两次 rename 只改了目录项。
	// 不同步父目录的话，掉电后可能主文件与备份同时丢失。
	syncDirectory(directory)
	return nil
}

// syncDirectory 尽力把目录项变更刷盘。部分平台（如 Windows）不支持对目录 Sync，忽略即可。
func syncDirectory(path string) {
	handle, err := os.Open(path)
	if err != nil {
		return
	}
	_ = handle.Sync()
	_ = handle.Close()
}

func (s *BindingStore) loadFile(path string) ([]model.Binding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4*1024*1024))
	decoder.DisallowUnknownFields()
	var snapshot bindingSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, fmt.Errorf("decode %s: %w", filepath.Base(path), err)
	}
	if snapshot.Version != bindingSchemaVersion {
		return nil, fmt.Errorf("unsupported binding snapshot version %d", snapshot.Version)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode %s: %w", filepath.Base(path), err)
	}
	return s.validate(snapshot.Bindings)
}

// validate 校验快照一致性：ID/deviceID/publicHost 非空、端口在范围内、设备与端口无重复；恢复的 Binding 一律置为 RESERVED。
func (s *BindingStore) validate(bindings []model.Binding) ([]model.Binding, error) {
	result := append([]model.Binding(nil), bindings...)
	deviceIDs := make(map[string]struct{}, len(result))
	ports := make(map[int]struct{}, len(result))
	for index := range result {
		binding := &result[index]
		if strings.TrimSpace(binding.ID) == "" || strings.TrimSpace(binding.DeviceID) == "" || strings.TrimSpace(binding.PublicHost) == "" {
			return nil, fmt.Errorf("binding identity is incomplete")
		}
		if binding.Port < s.minPort || binding.Port > s.maxPort {
			return nil, fmt.Errorf("binding port %d is outside configured range", binding.Port)
		}
		if _, exists := deviceIDs[binding.DeviceID]; exists {
			return nil, fmt.Errorf("duplicate binding device %q", binding.DeviceID)
		}
		if _, exists := ports[binding.Port]; exists {
			return nil, fmt.Errorf("duplicate binding port %d", binding.Port)
		}
		deviceIDs[binding.DeviceID] = struct{}{}
		ports[binding.Port] = struct{}{}
		binding.Status = model.BindingReserved
	}
	sort.Slice(result, func(i, j int) bool { return result[i].DeviceID < result[j].DeviceID })
	return result, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("multiple JSON values are not allowed")
}
