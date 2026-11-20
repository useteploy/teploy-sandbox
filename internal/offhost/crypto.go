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
	// previous are masters this keyring still opens but no longer wraps
	// with: rotation's half-done state, and a daemon's read path during
	// one. Wrapping always uses master.
	previous map[string]cipher.AEAD
}

// ParseMasterKey reads a master key: 32 random bytes, as 64 hex digits,
// as base64 (standard or URL alphabet, with or without padding), or raw
// (a file of exactly 32 bytes). Surrounding whitespace is ignored for
// the two text forms.
//
//	head -c 32 /dev/urandom | xxd -p -c 64 > remote.key
//
// A key that is plainly not random is refused: 32 bytes of text (a
// passphrase typed into the file is not a key, and neither is the text
// of a hex or base64 key cut short), or bytes that hardly vary.
func ParseMasterKey(raw []byte) ([]byte, error) {
	var key []byte
	text := strings.TrimSpace(string(raw))
	if decoded, err := hex.DecodeString(text); err == nil && len(decoded) == KeySize {
		key = decoded
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key != nil {
			break
		}
		if decoded, err := encoding.DecodeString(text); err == nil && len(decoded) == KeySize {
			key = decoded
		}
	}
	if key == nil && len(raw) == KeySize {
		printable := true
		for _, b := range raw {
			printable = printable && b >= 0x20 && b < 0x7f
		}
		if printable {
			return nil, errors.New("the master key file holds 32 characters of text, which is not a key: give 32 random bytes as 64 hex digits or as base64")
		}
		key = bytes.Clone(raw)
	}
	if key == nil {
		return nil, fmt.Errorf("a master key is %d random bytes: 64 hex digits, base64, or the raw bytes", KeySize)
	}
	distinct := map[byte]struct{}{}
	for _, b := range key {
		distinct[b] = struct{}{}
	}
	// 32 random bytes essentially never have fewer than 16 distinct
	// values; zeros, a repeated byte or a short pattern always do.
	if len(distinct) < 16 {
		return nil, errors.New("the master key is not random (its bytes hardly vary); generate one, for example with: head -c 32 /dev/urandom | xxd -p -c 64")
	}
	return key, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// masterKey derives the wrapping AEAD and the id of one master key.
func masterKey(master []byte) (cipher.AEAD, string, error) {
	// The master key is used for one thing, under its own derived key.
	wrapping, err := hkdf.Key(sha256.New, master, nil, label+"wrap", KeySize)
	if err != nil {
		return nil, "", err
	}
	aead, err := newAEAD(wrapping)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(append([]byte(label+"key-id/"), master...))
	return aead, hex.EncodeToString(digest[:6]), nil
}

// NewKeyring makes a keyring from a master key.
func NewKeyring(master []byte) (*Keyring, error) {
	if len(master) != KeySize {
		return nil, fmt.Errorf("a master key is %d bytes, got %d", KeySize, len(master))
	}
	aead, id, err := masterKey(master)
	if err != nil {
		return nil, err
	}
	return &Keyring{master: aead, id: id}, nil
}

// AddPrevious lets the keyring open, never wrap with, another master:
// the state between a rotation's start and its end.
func (k *Keyring) AddPrevious(master []byte) error {
	if len(master) != KeySize {
		return fmt.Errorf("a master key is %d bytes, got %d", KeySize, len(master))
	}
	aead, id, err := masterKey(master)
	if err != nil {
		return err
	}
	if id == k.id {
		return errors.New("a previous master key is the current one")
	}
	if k.previous == nil {
		k.previous = map[string]cipher.AEAD{}
	}
	k.previous[id] = aead
	return nil
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

// Open unwraps a stored key. It fails for a key wrapped for another
// owner, and for a master this keyring has neither as its current one
// nor among its previous ones.
func (k *Keyring) Open(owner, wrapped string) (Key, error) {
	id, encoded, ok := strings.Cut(wrapped, ".")
	if !ok {
		return Key{}, fmt.Errorf("%w: malformed wrapped key", ErrCorrupt)
	}
	aead := k.master
	if id != k.id {
		var known bool
		aead, known = k.previous[id]
		if !known {
			return Key{}, fmt.Errorf("%w (key %s, this daemon has %s)", ErrWrongKey, id, k.id)
		}
	}
	sealed, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(sealed) < aead.NonceSize() {
		return Key{}, fmt.Errorf("%w: malformed wrapped key", ErrCorrupt)
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	raw, err := aead.Open(nil, nonce, ciphertext, []byte(label+"key/"+owner))
	if err != nil || len(raw) != KeySize {
		return Key{}, fmt.Errorf("%w: the wrapped key of %s does not open", ErrCorrupt, owner)
	}
	return Key{Owner: owner, Wrapped: wrapped, raw: raw}, nil
}

// Wrap wraps a data key this daemon already has the raw bytes of, under
// the current master: what rotation does with every key it opens.
func (k *Keyring) Wrap(owner string, raw []byte) (Key, error) {
	if len(raw) != KeySize {
		return Key{}, fmt.Errorf("a data key is %d bytes, got %d", KeySize, len(raw))
	}
	nonce := make([]byte, k.master.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Key{}, err
	}
	sealed := k.master.Seal(nonce, nonce, raw, []byte(label+"key/"+owner))
	return Key{Owner: owner, Wrapped: k.id + "." + base64.RawStdEncoding.EncodeToString(sealed), raw: bytes.Clone(raw)}, nil
}

// Current says whether a wrapped key is already under the master this
// keyring wraps with.
func (k *Keyring) Current(key Key) bool {
	id, _, ok := strings.Cut(key.Wrapped, ".")
	return ok && id == k.id
}

// Rewrap takes an opened key and returns it wrapped under the current
// master, raw bytes unchanged: every object sealed under the key still
// decrypts, and only the wrapped spelling moves.
func (k *Keyring) Rewrap(key Key) (Key, error) {
	if k.Current(key) {
		return key, nil
	}
	return k.Wrap(key.Owner, key.raw)
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
