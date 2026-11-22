//go:build !linux && !darwin

package run

import "errors"

func statfsUsage(string) (used, free int64, err error) {
	return 0, 0, errors.New("filesystem usage is not available on this platform")
}
