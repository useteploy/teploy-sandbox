package main

import (
	"flag"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

func parseAccessFlags(t *testing.T, args ...string) *accessFlags {
	t.Helper()
	t.Setenv("SBX_ACCESS_ADDR", "")
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	parsed := addAccessFlags(flags)
	if err := flags.Parse(args); err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestAccessFlags(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := func() *run.Manager { return run.NewManager(nil, log) }

	// Off by default: nothing is opened and the manager is untouched.
	m := manager()
	setup, err := parseAccessFlags(t).prepare(driverDocker, 0, 0, "", m, log)
	if err != nil || setup != nil || m.AccessEnabled() {
		t.Fatalf("default: %v %v %v", setup, err, m.AccessEnabled())
	}
	for _, tc := range []struct {
		args    []string
		driver  string
		maxRuns int
		want    string
	}{
		{[]string{"--access-tls-cert", "x"}, driverVM, 4, "--access-addr is not"},
		{[]string{"--access-addr", "10.0.0.1:7448"}, driverDocker, 0, "must be set explicitly"},
		{[]string{"--access-addr", "10.0.0.1:7448"}, driverVM, 0, "must be set explicitly"},
		{[]string{"--access-addr", "10.0.0.1:7448", "--access-streams-max", "100000", "--access-memory-mb", "1024"}, driverVM, 0, "access memory budget"},
		{[]string{"--access-addr", "127.0.0.1:0"}, driverVM, 4, "never plain TCP"},
		{[]string{"--access-addr", "127.0.0.1:0", "--access-streams-max", "-1"}, driverVM, 4, "must not be negative"},
	} {
		m := manager()
		_, err := parseAccessFlags(t, tc.args...).prepare(tc.driver, tc.maxRuns, 200, "", m, log)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.args, err, tc.want)
		}
		if m.AccessEnabled() {
			t.Errorf("%v: access turned on by a refused configuration", tc.args)
		}
	}
}

func TestAccessFlagsRefuseTheFootGuns(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for name, args := range map[string][]string{
		"unspecified bind": {"--access-addr", "0.0.0.0:7448", "--access-tls-cert", "c", "--access-tls-key", "k", "--access-client-ca", "a"},
		"unspecified ipv6": {"--access-addr", "[::]:7448", "--access-tls-cert", "c", "--access-tls-key", "k", "--access-client-ca", "a"},
		"negative anon":    {"--access-addr", "127.0.0.1:7448", "--access-anon-mbit", "-5"},
		"negative total":   {"--access-addr", "127.0.0.1:7448", "--access-total-mbit", "-5"},
		"mbit below -1":    {"--access-addr", "127.0.0.1:7448", "--access-mbit", "-2"},
	} {
		m := run.NewManager(nil, log)
		if _, err := parseAccessFlags(t, args...).prepare(driverDocker, 0, 0, "", m, log); err == nil || !strings.Contains(err.Error(), "access-") {
			t.Errorf("%s: refused with %v, want an access flag error", name, err)
		}
	}
}
