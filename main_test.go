package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

func TestParseRetention(t *testing.T) {
	for raw, want := range map[string]time.Duration{
		"336h":   336 * time.Hour,
		"90m":    90 * time.Minute,
		"1h30m":  90 * time.Minute,
		"1s":     time.Second,
		"0.5h":   30 * time.Minute,
		"336h0s": 336 * time.Hour,
	} {
		got, err := parseRetention(raw)
		if err != nil || got != want {
			t.Fatalf("parseRetention(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	// Malformed or non-positive refuses the start.
	for _, raw := range []string{"", "14d", "two weeks", "14", "0", "0s", "-1h", "h"} {
		if got, err := parseRetention(raw); err == nil {
			t.Fatalf("parseRetention(%q) = %v, want an error", raw, got)
		}
	}
	// The flag's default is the documented 14 days and parses as itself.
	got, err := parseRetention(run.DefaultStoppedRetention.String())
	if err != nil || got != 14*24*time.Hour {
		t.Fatalf("default retention: %v %v", got, err)
	}
}

func TestProbeWritableDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")
	if err := probeWritableDir(dir); err != nil {
		t.Fatalf("a creatable dir must pass: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("the probe must leave nothing behind: %v", entries)
	}
	file := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probeWritableDir(filepath.Join(file, "state")); err == nil {
		t.Fatal("a dir that cannot be created must fail")
	}
}

func TestUsageIntervalBounds(t *testing.T) {
	for interval, ok := range map[time.Duration]bool{
		0: true, time.Second: true, time.Minute: true,
		-time.Second: false, time.Millisecond: false, 999 * time.Millisecond: false,
	} {
		if err := checkUsageInterval(interval); (err == nil) != ok {
			t.Errorf("%s: %v", interval, err)
		}
	}
}
