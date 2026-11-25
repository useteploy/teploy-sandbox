// Package access is the daemon's access listener: the separate, mutually
// authenticated listener edges open byte streams to guest ports on
// (docs/wire-contract.md, "Access"). It never shares a server, a mux or a
// credential with the control API.
//
// Every stream is checked in this order: the peer is an edge (a client
// certificate from the edge-client CA with a teploy-edge:// name that is
// not on the denylist, verified during the TLS handshake before any HTTP
// is read; or, on a unix socket, a permitted peer uid/gid); the grant, if
// any, verifies (signature, audience, expiry, run, scope); the stream fits
// the caps; and then, under the manager's lock, the run is here and
// running, the grant's epoch is at least the run's, and a stream without
// a grant is to a public port. A connection serves one run and one kind
// of stream (anonymous or granted) and is closed when its certificate
// expires. A granted stream is closed at its grant's expiry and when its
// issuer key is removed or replaced; every stream of a run is closed on
// revoke, stop and destroy; a public port's anonymous streams on
// unpublish; an anonymous stream that stalls with bytes waiting after
// Limits.AnonStall.
package access

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/useteploy/teploy-sandbox/accessgrant"
)

// Config is the access configuration, as PUT /v1/access/config takes it
// and as the configuration file holds it.
type Config struct {
	// Audience is the user-content domain grants must be issued for.
	Audience string `json:"audience"`
	// IssuerKeys verify grants.
	IssuerKeys []IssuerKey `json:"issuerKeys"`
	// EdgeDenylist names edges whose certificates are refused at the
	// handshake, whatever they are signed by.
	EdgeDenylist []string `json:"edgeDenylist"`
}

// IssuerKey is one grant verification key.
type IssuerKey struct {
	Kid string `json:"kid"`
	// Ed25519 is the public key, base64.
	Ed25519  string     `json:"ed25519"`
	NotAfter *time.Time `json:"notAfter,omitempty"`
}

const (
	maxDenylist     = 256
	maxEdgeName     = 128
	maxAudience     = 253
	configFileName  = "access-config.json"
	configFileMode  = 0o600
	configDirectory = 0o700
)

// ErrManagedByFile: the configuration comes from a file the operator
// names (serve --access-config), and is changed there.
var ErrManagedByFile = errors.New("the access configuration is managed by --access-config; edit that file and send the daemon SIGHUP")

// state is one configuration as the listener uses it.
type state struct {
	config  Config
	keyring *accessgrant.Keyring
	deny    map[string]bool
	// keys is the keyring by kid: the public key's bytes and its notAfter.
	keys map[string]issuerKey
}

type issuerKey struct {
	public   string
	notAfter time.Time
}

// keeps reports whether this configuration still accepts the key a
// stream was admitted with (the same kid, the same public key), and that
// key's notAfter.
func (st *state) keeps(kid, public string) (bool, time.Time) {
	key, ok := st.keys[kid]
	if !ok || key.public != public {
		return false, time.Time{}
	}
	return true, key.notAfter
}

// Store holds the current configuration. Readers never block.
type Store struct {
	// persist is where a PUT configuration is kept ("" memory only);
	// file is the operator's file (serve --access-config), which, when
	// set, is the only source.
	persist string
	file    string

	mu      sync.Mutex
	current atomic.Pointer[state]
	// changed are told after every configuration change (the listener
	// closes the streams of removed issuer keys).
	changed map[int]func()
	serial  int
}

// OnChange registers fn to run after every configuration change, until
// the returned function unregisters it.
func (s *Store) OnChange(fn func()) (unregister func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serial++
	id := s.serial
	if s.changed == nil {
		s.changed = map[int]func(){}
	}
	s.changed[id] = fn
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.changed, id)
	}
}

// watchers is how many functions OnChange holds.
func (s *Store) watchers() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.changed)
}

func (s *Store) notify() {
	s.mu.Lock()
	fns := make([]func(), 0, len(s.changed))
	for _, fn := range s.changed {
		fns = append(fns, fn)
	}
	s.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// OpenStore loads the configuration: from file when given, else from
// stateDir's access-config.json when it exists, else empty (no issuer
// keys: only public ports can be reached).
func OpenStore(stateDir, file string) (*Store, error) {
	s := &Store{file: file}
	if stateDir != "" {
		s.persist = filepath.Join(stateDir, configFileName)
	}
	source := s.file
	if source == "" {
		source = s.persist
	}
	config := Config{}
	if source != "" {
		data, err := os.ReadFile(source)
		switch {
		case err == nil:
			if err := json.Unmarshal(data, &config); err != nil {
				return nil, fmt.Errorf("access config %s: %w", source, err)
			}
		case errors.Is(err, os.ErrNotExist) && s.file == "":
		default:
			return nil, fmt.Errorf("access config: %w", err)
		}
	}
	compiled, err := compile(config)
	if err != nil {
		return nil, fmt.Errorf("access config %s: %w", source, err)
	}
	s.current.Store(compiled)
	return s, nil
}

// compile validates a configuration and builds what verification uses.
func compile(config Config) (*state, error) {
	if config.Audience != "" && !validAudience(config.Audience) {
		return nil, fmt.Errorf("audience %q must be a lowercase domain name", config.Audience)
	}
	if len(config.IssuerKeys) > 0 && config.Audience == "" {
		return nil, errors.New("issuer keys need an audience")
	}
	keys := make([]accessgrant.Key, 0, len(config.IssuerKeys))
	byKid := map[string]issuerKey{}
	for _, key := range config.IssuerKeys {
		public, err := accessgrant.ParsePublicKey(key.Ed25519)
		if err != nil {
			return nil, fmt.Errorf("issuer key %q: %w", key.Kid, err)
		}
		converted := accessgrant.Key{Kid: key.Kid, Public: public}
		if key.NotAfter != nil {
			converted.NotAfter = *key.NotAfter
		}
		keys = append(keys, converted)
		byKid[key.Kid] = issuerKey{public: string(public), notAfter: converted.NotAfter}
	}
	ring, err := accessgrant.NewKeyring(keys...)
	if err != nil {
		return nil, err
	}
	if len(config.EdgeDenylist) > maxDenylist {
		return nil, fmt.Errorf("%d denylisted edges, at most %d", len(config.EdgeDenylist), maxDenylist)
	}
	deny := map[string]bool{}
	for _, name := range config.EdgeDenylist {
		if !ValidEdgeName(name) {
			return nil, fmt.Errorf("denylisted edge %q is not an edge name ([A-Za-z0-9._-], at most %d)", name, maxEdgeName)
		}
		deny[name] = true
	}
	if config.IssuerKeys == nil {
		config.IssuerKeys = []IssuerKey{}
	}
	if config.EdgeDenylist == nil {
		config.EdgeDenylist = []string{}
	}
	return &state{config: config, keyring: ring, deny: deny, keys: byKid}, nil
}

// Set replaces the configuration and persists it (0600) before it takes
// effect.
func (s *Store) Set(config Config) error {
	if s.file != "" {
		return ErrManagedByFile
	}
	compiled, err := compile(config)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.persist != "" {
		if err := writeConfigFile(s.persist, compiled.config); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("persist access config: %w", err)
		}
	}
	s.current.Store(compiled)
	s.mu.Unlock()
	s.notify()
	return nil
}

// Reload rereads the operator's file (SIGHUP). Without one it does
// nothing. A file that does not parse leaves the current configuration.
func (s *Store) Reload() error {
	if s.file == "" {
		return nil
	}
	data, err := os.ReadFile(s.file)
	if err != nil {
		return err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	compiled, err := compile(config)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.current.Store(compiled)
	s.mu.Unlock()
	s.notify()
	return nil
}

// ManagedByFile reports whether the configuration comes from the
// operator's file.
func (s *Store) ManagedByFile() bool { return s.file != "" }

// Config is the current configuration.
func (s *Store) Config() Config {
	c := s.current.Load().config
	c.IssuerKeys = slices.Clone(c.IssuerKeys)
	c.EdgeDenylist = slices.Clone(c.EdgeDenylist)
	return c
}

func (s *Store) state() *state { return s.current.Load() }

// Denied reports whether an edge name is on the denylist.
func (s *Store) Denied(name string) bool { return s.current.Load().deny[name] }

func writeConfigFile(path string, config Config) (result error) {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, configDirectory); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+configFileName+"-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(configFileMode); err != nil {
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ValidEdgeName reports whether name can name an edge: 1-128 characters
// of [A-Za-z0-9._-].
func ValidEdgeName(name string) bool {
	if name == "" || len(name) > maxEdgeName {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validAudience(audience string) bool {
	if audience == "" || len(audience) > maxAudience || strings.HasPrefix(audience, ".") || strings.HasSuffix(audience, ".") || strings.Contains(audience, "..") {
		return false
	}
	for i := 0; i < len(audience); i++ {
		c := audience[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}
