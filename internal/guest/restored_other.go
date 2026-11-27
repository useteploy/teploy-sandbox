//go:build !linux

package guest

import "errors"

// The agent runs on Linux. Elsewhere (tests) the handshake's platform
// steps are refused, so a test that wants them supplies its own.
func platformSetClock(int64) error { return errNotLinux }

func platformAddEntropy([]byte) (bool, error) { return false, errNotLinux }

func platformVMGenIDSeen() bool { return false }

var errNotLinux = errors.New("restoring a VM is a Linux guest's")
