//go:build !linux

package guest

// The agent runs on Linux. Elsewhere (tests) there is nothing to flush
// that a later step depends on.
func platformSync() error { return nil }
