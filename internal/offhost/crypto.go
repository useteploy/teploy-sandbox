// Package offhost keeps a stopped run's disk in object storage, so the
// host that ran it can be lost and the run resumed on any other daemon.
//
// A snapshot is uploaded as a stream cut into chunks, each one encrypted
// before it leaves the host, with a manifest written last that names every
// chunk. A run has a small record beside it, in numbered generations that
// are only ever created, never overwritten: which daemon may resume a run
// is decided by who creates the next generation first.
//
// Layout, under the configured prefix:
//
//	v1/snap/<id>/<attempt>/<index>   one encrypted chunk of a stream
//	v1/snap/<id>/manifest            the snapshot: its chunks, their hashes,
//	                                 and the snapshot its stream builds on
//	v1/run/<id>/<generation>         one generation of a run's record
//
// Nothing here knows what a snapshot is on the host: that is the driver's
// side (Snapshots).
package offhost

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// KeySize is the size of every key: AES-256.
const KeySize = 32

// label prefixes every domain-separation string.
const label = "teploy-sandbox/v1/"

// Keyring holds the master key every daemon that shares a bucket is
// given. It never encrypts data: it wraps the key of each run.
type Keyring struct {
	master cipher.AEAD
	// id names the master key in what it wraps (a digest, not the key),
	// so the wrong key is reported as that and not as corruption.
	id string
}

// ParseMasterKey reads a master key: 32 raw bytes, or their base64 or hex
// spelling (surrounding whitespace ignored).
func ParseMasterKey(raw []byte) ([]byte, error) {
	if len(raw) == KeySize {
		return bytes.Clone(raw), nil
	}
	text := strings.TrimSpace(string(raw))
	if decoded, err := hex.DecodeString(text); err == nil && len(decoded) == KeySize {
		return decoded, nil
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(text); err == nil && len(decoded) == KeySize {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("a master key is %d bytes, raw, base64 or hex", KeySize)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewKeyring makes a keyring from a master key.
func NewKeyring(master []byte) (*Keyring, error) {
	if len(master) != KeySize {
		return nil, fmt.Errorf("a master key is %d bytes, got %d", KeySize, len(master))
	}
	// The master key is used for one thing, under its own derived key.
	wrapping, err := hkdf.Key(sha256.New, master, nil, label+"wrap", KeySize)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(wrapping)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte(label+"key-id/"), master...))
	return &Keyring{master: aead, id: hex.EncodeToString(digest[:6])}, nil
}

// Key is one run's data key: every chunk, manifest and record of the run
// is encrypted under a key derived from it. Wrapped is how it is stored,
// here and in the bucket: encrypted under the master key.
type Key struct {
	// Owner is what the key belongs to (a run ID, or a base image's ID).
	Owner   string
	Wrapped string
	raw     []byte
}

// ErrWrongKey: something was encrypted under another master key.
var ErrWrongKey = errors.New("encrypted under a different master key")

// ErrCorrupt: an object failed authentication, or is not what its name
// says it is.
var ErrCorrupt = errors.New("object failed verification")

// NewKey mints a data key for owner.
func (k *Keyring) NewKey(owner string) (Key, error) {
	raw := make([]byte, KeySize)
	if _, err := rand.Read(raw); err != nil {
		return Key{}, err
	}
	nonce := make([]byte, k.master.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Key{}, err
	}
	sealed := k.master.Seal(nonce, nonce, raw, []byte(label+"key/"+owner))
	return Key{Owner: owner, Wrapped: k.id + "." + base64.RawStdEncoding.EncodeToString(sealed), raw: raw}, nil
}

// Open unwraps a stored key. It fails for a key wrapped for another owner.
func (k *Keyring) Open(owner, wrapped string) (Key, error) {
	id, encoded, ok := strings.Cut(wrapped, ".")
	if !ok {
		return Key{}, fmt.Errorf("%w: malformed wrapped key", ErrCorrupt)
	}
	if id != k.id {
		return Key{}, fmt.Errorf("%w (key %s, this daemon has %s)", ErrWrongKey, id, k.id)
	}
	sealed, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(sealed) < k.master.NonceSize() {
		return Key{}, fmt.Errorf("%w: malformed wrapped key", ErrCorrupt)
	}
	nonce, ciphertext := sealed[:k.master.NonceSize()], sealed[k.master.NonceSize():]
	raw, err := k.master.Open(nil, nonce, ciphertext, []byte(label+"key/"+owner))
	if err != nil || len(raw) != KeySize {
		return Key{}, fmt.Errorf("%w: the wrapped key of %s does not open", ErrCorrupt, owner)
	}
	return Key{Owner: owner, Wrapped: wrapped, raw: raw}, nil
}

// derive is the key for one purpose under a data key: a key is never used
// for two kinds of thing, and chunks of two snapshots never share one.
func (k Key) derive(purpose, name string) (cipher.AEAD, error) {
	if len(k.raw) != KeySize {
		return nil, errors.New("offhost: a key that was never opened")
	}
	derived, err := hkdf.Key(sha256.New, k.raw, nil, label+purpose+"/"+name, KeySize)
	if err != nil {
		return nil, err
	}
	return newAEAD(derived)
}

// envelope is a small encrypted document as it is stored: the wrapped key
// it is under, in the clear, and the document.
type envelope struct {
	Version int    `json:"v"`
	Owner   string `json:"owner"`
	Key     string `json:"key"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"`
}

const envelopeVersion = 1

// seal encrypts document under key. kind and name are what the object is
// and where it is stored; a document moved to another name does not open.
func seal(key Key, kind, name string, document []byte) ([]byte, error) {
	aead, err := key.derive(kind, name)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return json.Marshal(envelope{
		Version: envelopeVersion,
		Owner:   key.Owner,
		Key:     key.Wrapped,
		Nonce:   nonce,
		Data:    aead.Seal(nil, nonce, document, []byte(label+kind+"/"+name)),
	})
}

// open decrypts a sealed document stored as kind under name, and returns
// the key it was under.
func (k *Keyring) open(kind, name string, stored []byte) ([]byte, Key, error) {
	var sealed envelope
	if err := json.Unmarshal(stored, &sealed); err != nil {
		return nil, Key{}, fmt.Errorf("%w: %s %s is not a sealed document", ErrCorrupt, kind, name)
	}
	if sealed.Version != envelopeVersion {
		return nil, Key{}, fmt.Errorf("%s %s has version %d, which this daemon does not read", kind, name, sealed.Version)
	}
	key, err := k.Open(sealed.Owner, sealed.Key)
	if err != nil {
		return nil, Key{}, err
	}
	aead, err := key.derive(kind, name)
	if err != nil {
		return nil, Key{}, err
	}
	if len(sealed.Nonce) != aead.NonceSize() {
		return nil, Key{}, fmt.Errorf("%w: %s %s", ErrCorrupt, kind, name)
	}
	document, err := aead.Open(nil, sealed.Nonce, sealed.Data, []byte(label+kind+"/"+name))
	if err != nil {
		return nil, Key{}, fmt.Errorf("%w: %s %s", ErrCorrupt, kind, name)
	}
	return document, key, nil
}
