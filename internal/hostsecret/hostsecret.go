// Package hostsecret keeps a host's secret: 32 random bytes in a file
// only the daemon's user can read, made the first time a daemon needs it.
//
// The secret is the root of what stays on one host. Today it wraps the
// keys of the VM driver's memory images (teploy-sandbox --vm-memory-
// snapshots); whatever else a host keeps for itself is sealed under it
// too, so that a copy of a host's state directory on another machine
// opens nothing: the state directory travels in backups, and the secret
// must not. Keep the file outside --state-dir (the daemon refuses one
// inside it) and leave it out of backups. Losing it loses nothing that is
// durable: every memory image becomes unusable and the runs it belonged
// to resume from their disks.
package hostsecret

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Size is the secret's: 32 bytes, a key's worth.
const Size = 32

// DefaultPath is where the secret lives unless the daemon is told
// otherwise: beside the state directory, never in it.
const DefaultPath = "/var/lib/teploy-sandbox/host-secret"

// ErrReadByOthers: a secret file anyone but its owner can read.
var ErrReadByOthers = errors.New("the host secret is readable by others than its owner")

// Load reads the host's secret from path, making it if it is not there
// yet. A file that is there must be a regular file of exactly Size
// bytes, owned by the daemon's user and readable by that user alone: a
// secret a copy of the machine would carry is worse than a lost one,
// which is why it is not made in a place others can read.
func Load(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return create(path)
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%w (mode %04o); chmod 600 it", ErrReadByOthers, mode)
	}
	if owner := ownerOf(info); owner >= 0 && owner != os.Geteuid() {
		return nil, fmt.Errorf("%s belongs to uid %d, and the daemon runs as %d", path, owner, os.Geteuid())
	}
	secret, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(secret) != Size {
		return nil, fmt.Errorf("%s holds %d bytes, and the host secret is %d", path, len(secret), Size)
	}
	if !random(secret) {
		return nil, fmt.Errorf("%s does not hold random bytes", path)
	}
	return secret, nil
}

// Outside reports whether path is inside dir, as far as the two can be
// told without either existing: a secret kept in the state directory
// would be cloned and backed up with it.
func Outside(path, dir string) error {
	if dir == "" {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	inside, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	abs, inside = filepath.Clean(abs), filepath.Clean(inside)
	if abs == inside || strings.HasPrefix(abs, inside+string(filepath.Separator)) {
		return fmt.Errorf("the host secret %s is inside the state directory %s: a copy of the state directory would carry it", path, dir)
	}
	return nil
}

// create makes the secret, whole or not at all: a file cut short by a
// crash must not be read as a secret later.
func create(path string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	secret := make([]byte, Size)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		// Made by another start in the same moment.
		return Load(path)
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(secret); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		file = nil
		return nil, err
	}
	file = nil
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return secret, nil
}

// random: 32 random bytes essentially never have fewer than 16 distinct
// values; a file of zeros, of one repeated byte or of text does.
func random(secret []byte) bool {
	distinct := map[byte]struct{}{}
	for _, b := range secret {
		distinct[b] = struct{}{}
	}
	return len(distinct) >= 16
}
