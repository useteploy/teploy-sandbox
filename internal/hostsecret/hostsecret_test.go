package hostsecret

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMakesTheSecretOnceAndReadsItAfter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "var", "lib", "teploy-sandbox", "host-secret")
	first, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != Size || bytes.Equal(first, make([]byte, Size)) {
		t.Fatalf("the secret made is %d bytes: %x", len(first), first)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the secret file has mode %04o, want 0600", mode)
	}
	if dir, err := os.Stat(filepath.Dir(path)); err != nil || dir.Mode().Perm() != 0o700 {
		t.Errorf("the directory holding it has mode %v (%v), want 0700", dir, err)
	}
	second, err := Load(path)
	if err != nil || !bytes.Equal(second, first) {
		t.Fatalf("the second start read %x (%v), want the same secret %x", second, err, first)
	}
}

func TestLoadRefusesASecretOthersCouldReadOrThatIsNotOne(t *testing.T) {
	good := make([]byte, Size)
	for i := range good {
		good[i] = byte(i * 7)
	}
	for name, write := range map[string]func(t *testing.T, path string){
		"readable by others": func(t *testing.T, path string) {
			if err := os.WriteFile(path, good, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"too short": func(t *testing.T, path string) {
			if err := os.WriteFile(path, good[:31], 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"zeros": func(t *testing.T, path string) {
			if err := os.WriteFile(path, make([]byte, Size), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a directory": func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	} {
		path := filepath.Join(t.TempDir(), "host-secret")
		write(t, path)
		if secret, err := Load(path); err == nil {
			t.Errorf("%s: loaded %x", name, secret)
		}
	}
	// The one it refused to read as a secret is not replaced either: a
	// new secret beside a lost one would silently make every image
	// sealed under the old one unusable, and the operator must choose.
	path := filepath.Join(t.TempDir(), "host-secret")
	if err := os.WriteFile(path, good[:31], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a short secret was loaded")
	}
	if again, _ := os.ReadFile(path); len(again) != 31 {
		t.Fatalf("the file the daemon refused was replaced by one of %d bytes", len(again))
	}
}

func TestOutsideRefusesAStateDirectoryAndItsChildren(t *testing.T) {
	for name, c := range map[string]struct{ path, dir, want string }{
		"inside the state dir":      {"/var/lib/sbx/state/host-secret", "/var/lib/sbx/state", "inside"},
		"is the state dir":          {"/var/lib/sbx/state", "/var/lib/sbx/state", "inside"},
		"beside it":                 {"/var/lib/sbx/host-secret", "/var/lib/sbx/state", ""},
		"a sibling with the prefix": {"/var/lib/sbx/state2/host-secret", "/var/lib/sbx/state", ""},
		"no state dir":              {"/var/lib/sbx/state/host-secret", "", ""},
	} {
		err := Outside(c.path, c.dir)
		if (err == nil) != (c.want == "") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
