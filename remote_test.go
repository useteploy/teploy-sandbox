package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost"
	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func parseRemoteFlags(t *testing.T, args ...string) *remoteFlags {
	t.Helper()
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	remote := addRemoteFlags(flags)
	if err := flags.Parse(args); err != nil {
		t.Fatal(err)
	}
	return remote
}

// The numbers a daemon may be given: one bound for chains everywhere
// (review B3), a grace that cannot be shorter than what it has to
// outlast (A2), and a snapshot retry inside it (R2).
func TestRemoteFlagBounds(t *testing.T) {
	if err := parseRemoteFlags(t).validate(); err != nil {
		t.Fatalf("the defaults: %v", err)
	}
	refused := map[string][]string{
		"a chain no daemon restores through": {"--remote-max-chain", "65"},
		"no chain":                           {"--remote-max-chain", "0"},
		"a grace of minutes":                 {"--remote-gc-grace", "30m"},
		"no grace":                           {"--remote-gc-grace", "0"},
		"a retry as long as the grace":       {"--remote-snapshot-retry", "24h"},
		"a retry longer than the grace":      {"--remote-gc-grace", "2h", "--remote-snapshot-retry", "3h"},
		"no transfers":                       {"--remote-transfers", "0"},
		"a negative scrub interval":          {"--remote-scrub-interval", "-1h"},
		"an unknown local policy":            {"--remote-local", "maybe"},
	}
	for name, args := range refused {
		if err := parseRemoteFlags(t, args...).validate(); err == nil {
			t.Errorf("%s was accepted: %v", name, args)
		}
	}
	accepted := map[string][]string{
		"the longest chain":  {"--remote-max-chain", "64"},
		"the shortest grace": {"--remote-gc-grace", "1h", "--remote-snapshot-retry", "30m"},
		"no retry":           {"--remote-snapshot-retry", "0"},
		"no scrub":           {"--remote-scrub-interval", "0"},
	}
	for name, args := range accepted {
		if err := parseRemoteFlags(t, args...).validate(); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	if run.DefaultSnapshotRetry >= 24*time.Hour {
		t.Fatal("the default snapshot retry is not shorter than the default grace")
	}
}

// Review A10: a key file others can read is refused, and a secret taken
// from the environment does not stay in it for children to inherit.
func TestSecretsAreNotLeftLyingAbout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "remote.key")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := secretFrom(path); err != nil || string(got) != "secret\n" {
		t.Fatalf("a key file of mode 0600: %q, %v", got, err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := secretFrom(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("a key file of mode %04o: %v", mode, err)
		}
	}
	if _, err := secretFrom(filepath.Join(dir, "missing")); err == nil {
		t.Error("a key file that is not there was read")
	}
	t.Setenv("SBX_TEST_SECRET_B", "from the environment")
	got, err := secretFrom("", "SBX_TEST_SECRET_A", "SBX_TEST_SECRET_B")
	if err != nil || string(got) != "from the environment" {
		t.Fatalf("a secret from the environment: %q, %v", got, err)
	}
	if value, set := os.LookupEnv("SBX_TEST_SECRET_B"); set {
		t.Fatalf("the secret is still in the daemon's environment (%q), for every child to inherit", value)
	}
}

// Review A10: the daemon's identity is written whole or not at all.
func TestDaemonIdentityIsWrittenOnce(t *testing.T) {
	dir := t.TempDir()
	first, err := daemonIdentity(dir)
	if err != nil || len(first) != 32 {
		t.Fatalf("daemonIdentity = %q, %v", first, err)
	}
	if again, err := daemonIdentity(dir); err != nil || again != first {
		t.Fatalf("a second start: %q, %v", again, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "daemon-id" {
		t.Fatalf("the state directory holds %v", entries)
	}
	if info, _ := entries[0].Info(); info.Mode().Perm() != 0o600 {
		t.Fatalf("daemon-id has mode %04o", info.Mode().Perm())
	}
	// A file a crash cut short refuses the start rather than rename the
	// daemon.
	if err := os.WriteFile(filepath.Join(dir, "daemon-id"), []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := daemonIdentity(dir); err == nil {
		t.Fatal("a truncated identity was accepted")
	}
}

// Review B6: a daemon started against another bucket or prefix than the
// one its registry was written against does not start. Before, it found
// none of its runs' records there and concluded they were destroyed.
func TestADaemonPointedAtAnotherBucketDoesNotStart(t *testing.T) {
	ctx := context.Background()
	bucket := offhosttest.NewMemory()
	keys, err := offhost.NewKeyring(bytes.Repeat([]byte{7}, offhost.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	store := func(prefix string) *offhost.Store {
		s := offhost.NewStore(bucket, prefix, keys, quietLogger())
		if err := s.Probe(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	}
	stateDir := t.TempDir()
	if err := checkFleetIdentity(ctx, store("fleet"), stateDir); err != nil {
		t.Fatalf("first use: %v", err)
	}
	remembered, err := os.ReadFile(filepath.Join(stateDir, fleetIdentityFile))
	if err != nil || len(strings.TrimSpace(string(remembered))) != 32 {
		t.Fatalf("the state directory remembers %q, %v", remembered, err)
	}
	if err := checkFleetIdentity(ctx, store("fleet"), stateDir); err != nil {
		t.Fatalf("a restart against the same storage: %v", err)
	}
	// A second daemon joins the same storage and agrees on its name.
	other := t.TempDir()
	if err := checkFleetIdentity(ctx, store("fleet"), other); err != nil {
		t.Fatal(err)
	}
	if joined, _ := os.ReadFile(filepath.Join(other, fleetIdentityFile)); !bytes.Equal(joined, remembered) {
		t.Fatalf("two daemons on one bucket remember %q and %q", joined, remembered)
	}
	// A typo in the prefix: nothing there at all.
	if err := checkFleetIdentity(ctx, store("fleeet"), stateDir); err == nil || !strings.Contains(err.Error(), "no name at all") {
		t.Fatalf("a start against an empty prefix: %v", err)
	}
	if left := bucket.Keys("fleeet/"); len(left) != 0 {
		t.Fatalf("a refused start wrote %v into the wrong prefix", left)
	}
	// Another fleet's prefix.
	if err := checkFleetIdentity(ctx, store("another"), t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := checkFleetIdentity(ctx, store("another"), stateDir); err == nil || !strings.Contains(err.Error(), "are named") {
		t.Fatalf("a start against another fleet's prefix: %v", err)
	}
	// The objects were lost, the identity with them.
	for _, key := range bucket.Keys("fleet/") {
		bucket.Remove(key)
	}
	if err := checkFleetIdentity(ctx, store("fleet"), stateDir); err == nil {
		t.Fatal("a start against storage that lost its identity was accepted without being told to")
	}
	// The operator says this is the storage to use from now on.
	if err := os.Remove(filepath.Join(stateDir, fleetIdentityFile)); err != nil {
		t.Fatal(err)
	}
	if err := checkFleetIdentity(ctx, store("fleet"), stateDir); err != nil {
		t.Fatalf("after the operator's word: %v", err)
	}
}

// What open refuses before it talks to anything: a weak or exposed
// master key (A10), and a plain-http endpoint on another host (A8).
func TestRemoteOpenRefusals(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, offhost.KeySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := write("good.key", []byte(hex.EncodeToString(raw)+"\n"), 0o600)
	cases := map[string]struct {
		args []string
		want string
	}{
		"http to another host": {[]string{"--remote-endpoint", "http://s3.example.com", "--remote-key-file", good}, "plain http"},
		"a key file others can read": {[]string{"--remote-endpoint", "https://s3.example.com",
			"--remote-key-file", write("open.key", []byte(hex.EncodeToString(raw)), 0o644)}, "chmod 600"},
		"a key of zeros": {[]string{"--remote-endpoint", "https://s3.example.com",
			"--remote-key-file", write("zero.key", make([]byte, offhost.KeySize), 0o600)}, "not random"},
		"a passphrase for a key": {[]string{"--remote-endpoint", "https://s3.example.com",
			"--remote-key-file", write("text.key", []byte("correct horse battery staple 123"), 0o600)}, "not a key"},
		"a previous key others can read": {[]string{"--remote-endpoint", "https://s3.example.com", "--remote-key-file", good,
			"--remote-previous-key-file", write("old.key", []byte(hex.EncodeToString(raw)), 0o640)}, "chmod 600"},
	}
	for name, test := range cases {
		t.Setenv("SBX_REMOTE_SECRET_KEY", "secret")
		args := append([]string{"--remote-bucket", "b", "--remote-access-key", "a"}, test.args...)
		service, err := parseRemoteFlags(t, args...).open(context.Background(), noSnapshots{}, t.TempDir(), quietLogger())
		if err == nil || service != nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: %v (want an error naming %q)", name, err, test.want)
		}
	}
	// And the secret the daemon was handed in its environment is not
	// there for a child any more.
	if _, set := os.LookupEnv("SBX_REMOTE_SECRET_KEY"); set {
		t.Error("SBX_REMOTE_SECRET_KEY is still in the environment after open read it")
	}
}

// noSnapshots stands in for a driver's snapshots where none is reached.
type noSnapshots struct{ offhost.Snapshots }
