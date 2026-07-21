package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
)

func TestBindingStoreSaveLoadAndBackupFallback(t *testing.T) {
	stateDir := t.TempDir()
	bindingStore := NewBindingStore(stateDir, 55000, 55010)
	first := model.Binding{
		ID: "binding-1", DeviceID: "node:device-1", PublicHost: "example.test", Port: 55001,
		Status: model.BindingListening, CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(2, 0),
	}
	if err := bindingStore.Save([]model.Binding{first}); err != nil {
		t.Fatalf("Save(first) error = %v", err)
	}
	loaded, err := bindingStore.Load()
	if err != nil {
		t.Fatalf("Load(first) error = %v", err)
	}
	if len(loaded) != 1 || loaded[0].Port != first.Port || loaded[0].Status != model.BindingReserved {
		t.Fatalf("unexpected restored bindings = %+v", loaded)
	}

	second := first
	second.UpdatedAt = time.Unix(3, 0)
	if err := bindingStore.Save([]model.Binding{second}); err != nil {
		t.Fatalf("Save(second) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "bindings.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("corrupt primary snapshot: %v", err)
	}
	loaded, err = bindingStore.Load()
	if err != nil {
		t.Fatalf("Load(backup) error = %v", err)
	}
	if len(loaded) != 1 || !loaded[0].UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("backup was not used: %+v", loaded)
	}
}

func TestBindingStoreRejectsDuplicatePorts(t *testing.T) {
	bindingStore := NewBindingStore(t.TempDir(), 55000, 55010)
	bindings := []model.Binding{
		{ID: "binding-1", DeviceID: "node:device-1", PublicHost: "example.test", Port: 55001},
		{ID: "binding-2", DeviceID: "node:device-2", PublicHost: "example.test", Port: 55001},
	}
	if err := bindingStore.Save(bindings); err == nil {
		t.Fatal("Save(duplicate ports) error = nil")
	}
}
