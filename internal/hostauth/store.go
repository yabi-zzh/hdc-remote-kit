package hostauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const knownHostsSchemaVersion = 1

type knownHostsSnapshot struct {
	Version int         `json:"version"`
	Hosts   []KnownHost `json:"hosts"`
}

func loadKnownHosts(path string) ([]KnownHost, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open known_hosts: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 2*1024*1024))
	decoder.DisallowUnknownFields()
	var snapshot knownHostsSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, fmt.Errorf("decode known_hosts: %w", err)
	}
	if snapshot.Version != knownHostsSchemaVersion {
		return nil, fmt.Errorf("unsupported known_hosts version %d", snapshot.Version)
	}
	hosts := make([]KnownHost, 0, len(snapshot.Hosts))
	seen := make(map[string]struct{}, len(snapshot.Hosts))
	for _, host := range snapshot.Hosts {
		fingerprint := strings.TrimSpace(host.Fingerprint)
		if fingerprint == "" {
			continue
		}
		if _, exists := seen[fingerprint]; exists {
			continue
		}
		seen[fingerprint] = struct{}{}
		if host.CreatedAt.IsZero() {
			host.CreatedAt = time.Now().UTC()
		}
		host.Fingerprint = fingerprint
		host.Hostname = strings.TrimSpace(host.Hostname)
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func writeKnownHosts(path string, hosts []KnownHost) error {
	directory := filepath.Dir(path)
	temporaryPath := path + ".tmp"
	file, err := os.OpenFile(temporaryPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create known_hosts: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(knownHostsSnapshot{Version: knownHostsSchemaVersion, Hosts: hosts})
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("write known_hosts: %w", errors.Join(writeErr, closeErr))
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("replace known_hosts: %w", err)
	}
	if handle, err := os.Open(directory); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
	return nil
}
