package main

import (
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
