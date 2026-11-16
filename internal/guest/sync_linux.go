package guest

import "syscall"

func platformSync() error {
	syscall.Sync()
	return nil
}
