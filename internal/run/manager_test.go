package run

import (
	"strings"
	"testing"
	"time"
)

func TestValidateWorkPath(t *testing.T) {
	for path, wantErr := range map[string]bool{
		"a.txt":        false,
		"notes/a.txt":  false,
		"":             true,
		"/etc/passwd":  true,
		"../escape":    true,
		"a/../../b":    true,
		"a//b":         true,
		"nested/../ok": true,
	} {
		got, err := ValidateWorkPath(path)
		if wantErr && err == nil {
			t.Fatalf("%q: expected rejection, got %q", path, got)
		}
		if !wantErr {
			if err != nil {
				t.Fatalf("%q: unexpected error %v", path, err)
			}
			if !strings.HasPrefix(got, WorkDir+"/") {
				t.Fatalf("%q resolved outside workdir: %q", path, got)
			}
		}
	}
}

func TestULIDShape(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		id := NewULID(time.Now())
		if len(id) != 26 {
			t.Fatalf("ULID length: %q", id)
		}
		for _, r := range id {
			if !strings.ContainsRune(ulidAlphabet, r) {
				t.Fatalf("ULID char %q outside alphabet", r)
			}
		}
		if seen[id] {
			t.Fatalf("duplicate ULID: %q", id)
		}
		seen[id] = true
	}
	// timestamps order lexicographically
	early := NewULID(time.UnixMilli(1_000_000))
	late := NewULID(time.UnixMilli(2_000_000_000_000))
	if early >= late {
		t.Fatalf("ULIDs must sort by time: %q >= %q", early, late)
	}
}
