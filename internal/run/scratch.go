package run

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Scratch cleanup is journaled before allocation. Failed cleanup remains
// owned across daemon restarts rather than disappearing with a request.
func (d *DockerRuntime) ownScratch(args ...string) (func() error, error) {
	record := ""
	if d.CleanupRoot != "" {
		if err := os.MkdirAll(d.CleanupRoot, 0700); err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(strings.Join(args, "\x00")))
		record = filepath.Join(d.CleanupRoot, hex.EncodeToString(sum[:])+".json")
		data, _ := json.Marshal(args)
		if err := os.WriteFile(record, data, 0600); err != nil {
			return nil, err
		}
	}
	return func() error {
		if err := d.cleanup(args...); err != nil {
			return err
		}
		if record != "" {
			return os.Remove(record)
		}
		return nil
	}, nil
}
func (d *DockerRuntime) RecoverScratch() error {
	if d.CleanupRoot == "" {
		return nil
	}
	entries, err := os.ReadDir(d.CleanupRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(d.CleanupRoot, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var args []string
		if json.Unmarshal(data, &args) != nil {
			return fmt.Errorf("invalid sandbox cleanup journal")
		}
		valid := len(args) == 3 && args[0] == "rm" && args[1] == "-f" && (strings.HasPrefix(args[2], "sbx-snapseed-") || strings.HasPrefix(args[2], "sbx-imgseed-"))
		valid = valid || (len(args) == 2 && args[0] == "rmi" && strings.HasPrefix(args[1], SnapshotRepo+":") && strings.HasSuffix(args[1], "-stage"))
		if !valid {
			return fmt.Errorf("refusing invalid sandbox cleanup ownership")
		}
		if err := d.cleanup(args...); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}
