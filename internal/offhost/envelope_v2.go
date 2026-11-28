package offhost

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

// A v2 envelope is one stored object (a manifest or a generation of a
// record) in two sections:
//
//   - the public section, the graph: who the object belongs to and what
//     it consists of. Sealed under the fleet metadata key, so that
//     collection, scrub, verify, pins and fencing read it without any
//     tenant's key. It is stored as the exact bytes that were sealed.
//   - the sealed section, under the run's hold key: a manifest's stream
//     hashes, a record's payload. Its AAD holds the SHA-256 of the public
//     bytes, so that changing one byte of the public section, under a
//     valid fleet key or not, makes the sealed section unopenable. There
//     is no JSON canonicalisation: the bytes are what is bound.
//
// Base images stay in v1 envelopes under the fleet metadata key (owner
// base-<guid>) and are never sealed as v2. A destroyed record has no
// sealed section and carries no key.
//
// An envelope is read as one JSON document: no unknown field, no key
// written twice (including case variants), exact field-name casing, and
// nothing after it.

// EnvelopeVersionV2 is the "v" of a v2 envelope.
const EnvelopeVersionV2 = 2

// The kinds of object that have sections. The first part of every info
// string and AAD of theirs.
const (
	kindManifest = "manifest"
	kindRecord   = "record"
)

// EnvelopeV2 is a v2 envelope as it is stored.
type EnvelopeV2 struct {
	Version int `json:"v"`
	// FMK is the ID of the fleet metadata key the public section is
	// under.
	FMK string `json:"fmk"`
	// PublicNonce and Public are the public section, sealed under the
	// fleet key.
	PublicNonce []byte `json:"publicNonce"`
	Public      []byte `json:"public"`
	// Key, SealedNonce and Sealed are the sealed section: the hold key
	// it is under, wrapped, and the section itself. All three are absent
	// when there is none.
	Key         string `json:"key,omitempty"`
	SealedNonce []byte `json:"sealedNonce,omitempty"`
	Sealed      []byte `json:"sealed,omitempty"`
}

// ManifestPublicV2 is the public section of a v2 manifest. Every v2
// manifest belongs to a tenant run (base images stay in v1 envelopes
// under the fleet key) and carries its stream hashes in the sealed
// section, never in the public section.
type ManifestPublicV2 struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Purpose string `json:"purpose"`
	Tenant  string `json:"tenant"`
	// Run is the run the snapshot was taken of.
	Run       string    `json:"run"`
	KID       string    `json:"kid"`
	CreatedAt time.Time `json:"createdAt"`
	// Parent is the snapshot the stream is incremental against; "" is a
	// full stream.
	Parent string `json:"parent,omitempty"`
	// GUID and ParentGUID are the ZFS identities of the snapshot and of
	// the one its stream builds on.
	GUID       string `json:"guid"`
	ParentGUID string `json:"parentGuid,omitempty"`
	// Depth is how many streams lie between this snapshot and its base.
	Depth int `json:"depth"`
	// Attempt names the upload whose chunks these are.
	Attempt string `json:"attempt"`
	// ChunkBytes is the stream bytes in every chunk but the last.
	ChunkBytes int `json:"chunkBytes"`
	// Chunks, each as stored: its size and the SHA-256 of its ciphertext.
	Chunks []Chunk `json:"chunks"`
	// StreamBytes and StoredBytes are the stream's own size and what the
	// chunks occupy.
	StreamBytes int64 `json:"streamBytes"`
	StoredBytes int64 `json:"storedBytes"`
}

// ManifestSealedV2 is the sealed section of a v2 manifest.
type ManifestSealedV2 struct {
	StreamSHA256       string `json:"streamSha256"`
	ParentStreamSHA256 string `json:"parentStreamSha256,omitempty"`
}

// RecordPublicV2 is the public section of one generation of a v2 record.
// KID names the hold key the sealed section is under, and is worth
// trusting only in an envelope that has one (OpenedPublicV2.HasSealed):
// a destroyed record's public section is all anyone sealed.
type RecordPublicV2 struct {
	Version    int    `json:"version"`
	Tenant     string `json:"tenant"`
	Run        string `json:"run"`
	KID        string `json:"kid,omitempty"`
	Generation uint64 `json:"generation"`
	State      string `json:"state"`
	// Owner is the identity of the daemon that wrote it.
	Owner     string    `json:"owner"`
	WrittenAt time.Time `json:"writtenAt"`
	// Snapshot is the ID of the snapshot the state refers to.
	Snapshot string `json:"snapshot,omitempty"`
	// Write tells one write of a generation from another.
	Write string `json:"write"`
}

// RecordSealedV2 is the sealed section of a v2 record.
type RecordSealedV2 struct {
	Payload json.RawMessage `json:"payload"`
}

// oneJSONDocument reports whether data is one whole JSON document, and
// one with no key written twice (case-insensitively) at any depth.
// encoding/json matches field names case-insensitively and keeps the
// last of two equal keys without a word; another reader may keep the
// first, and two programs would then have read two documents out of one.
// The error says what is wrong and wraps nothing; the caller says what
// it was reading.
func oneJSONDocument(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var value func() error
	value = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil // a literal
		}
		switch delim {
		case '{':
			var keys []string
			for decoder.More() {
				token, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok {
					return errors.New("an object has a key that is not a string")
				}
				if slices.ContainsFunc(keys, func(seen string) bool { return strings.EqualFold(seen, key) }) {
					return fmt.Errorf("the key %s is written twice", quoted(key))
				}
				keys = append(keys, key)
				if err := value(); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := value(); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return errors.New("a bracket closes what was never opened")
		}
	}
	if err := value(); err != nil {
		return fmt.Errorf("not one whole JSON document: %v", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("bytes follow the JSON document")
	}
	return nil
}

var (
	rawMessageType      = reflect.TypeOf(json.RawMessage(nil))
	jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	textUnmarshalerType = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
)

// decodeJSON decodes data, which oneJSONDocument found whole, into v.
// With strict set, a field v does not have — including any case variant
// of a known field name — is refused rather than skipped or matched
// case-insensitively by encoding/json. The error says nothing of the
// data beyond what kind of thing was wrong: what comes out of a bucket
// is not this daemon's to put in a log.
func decodeJSON(data []byte, v any, strict bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	err := decoder.Decode(v)
	var (
		syntax *json.SyntaxError
		wrong  *json.UnmarshalTypeError
	)
	switch {
	case err == nil:
	case errors.As(err, &syntax):
		return fmt.Errorf("it is not JSON: %v", err)
	case errors.As(err, &wrong):
		// Says a JSON type, a field of v and a Go type; never the data.
		return fmt.Errorf("a field is not what this daemon reads there: %v", err)
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		// The name of the field is the data's, and may be anything.
		return errors.New("it has a field this daemon does not know")
	default:
		return errors.New("it cannot be read as one")
	}
	if _, more := decoder.Token(); !errors.Is(more, io.EOF) {
		return errors.New("bytes follow the JSON document")
	}
	if strict {
		if err := checkExactJSONFields(data, reflect.TypeOf(v)); err != nil {
			return err
		}
	}
	return nil
}

// checkExactJSONFields verifies that every JSON object key in data
// matches the exact case-sensitive json tag name of the corresponding
// struct field in t, closing encoding/json's case-insensitive matching.
func checkExactJSONFields(data []byte, t reflect.Type) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	return checkExactJSONValue(decoder, t)
}

func checkExactJSONValue(decoder *json.Decoder, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessageType ||
		(t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8) ||
		t.Implements(jsonUnmarshalerType) || reflect.PointerTo(t).Implements(jsonUnmarshalerType) ||
		t.Implements(textUnmarshalerType) || reflect.PointerTo(t).Implements(textUnmarshalerType) {
		return skipJSONValue(decoder)
	}
	switch t.Kind() {
	case reflect.Struct:
		tok, err := decoder.Token()
		if err != nil {
			return err
		}
		if tok == nil {
			return nil
		}
		delim, ok := tok.(json.Delim)
		if !ok || delim != '{' {
			return errors.New("it cannot be read as one")
		}
		fields := exactStructJSONFields(t)
		for decoder.More() {
			keyTok, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return errors.New("it cannot be read as one")
			}
			ft, known := fields[key]
			if !known {
				return errors.New("it has a field this daemon does not know")
			}
			if err := checkExactJSONValue(decoder, ft); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case reflect.Slice, reflect.Array:
		tok, err := decoder.Token()
		if err != nil {
			return err
		}
		if tok == nil {
			return nil
		}
		delim, ok := tok.(json.Delim)
		if !ok || delim != '[' {
			return errors.New("it cannot be read as one")
		}
		for decoder.More() {
			if err := checkExactJSONValue(decoder, t.Elem()); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case reflect.Map:
		tok, err := decoder.Token()
		if err != nil {
			return err
		}
		if tok == nil {
			return nil
		}
		delim, ok := tok.(json.Delim)
		if !ok || delim != '{' {
			return errors.New("it cannot be read as one")
		}
		for decoder.More() {
			if _, err := decoder.Token(); err != nil {
				return err
			}
			if err := checkExactJSONValue(decoder, t.Elem()); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return skipJSONValue(decoder)
	}
}

func exactStructJSONFields(t reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" && f.Anonymous {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for k, v := range exactStructJSONFields(ft) {
					fields[k] = v
				}
				continue
			}
		}
		if name == "" {
			name = f.Name
		}
		fields[name] = f.Type
	}
	return fields
}

func skipJSONValue(decoder *json.Decoder) error {
	tok, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		for decoder.More() {
			if _, err := decoder.Token(); err != nil {
				return err
			}
			if err := skipJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := skipJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("it cannot be read as one")
	}
}

// splitRecordName takes "<run>/<generation>", the name of one
// generation of a run's record. The generation is in canonical decimal:
// no leading zero, no sign, from 1 up.
func splitRecordName(name string) (run string, generation uint64, err error) {
	run, digits, ok := strings.Cut(name, "/")
	if !ok || !validAADSegment(run) {
		return "", 0, invalidSegment("record name", name)
	}
	if digits == "" || digits[0] == '0' || strings.Trim(digits, "0123456789") != "" {
		return "", 0, fmt.Errorf("%w: %s is not the name of a generation (a run's ID, a slash, and a number from 1 up)", ErrCorrupt, quoted(name))
	}
	if generation, err = strconv.ParseUint(digits, 10, 64); err != nil {
		return "", 0, fmt.Errorf("%w: %s is not the name of a generation", ErrCorrupt, quoted(name))
	}
	return run, generation, nil
}

// checkKindName validates the kind and the name of the object an
// envelope is the envelope of, wherever an info string or an AAD is
// built from them.
func checkKindName(kind, name string) error {
	switch kind {
	case kindManifest:
		if !validAADSegment(name) {
			return invalidSegment("snapshot ID", name)
		}
	case kindRecord:
		if _, _, err := splitRecordName(name); err != nil {
			return err
		}
	default:
		return fmt.Errorf("offhost: %s is not a kind with a public section (manifest or record)", quoted(kind))
	}
	return nil
}

// publicAADV2 is what a public section is bound to: its kind and name.
func publicAADV2(kind, name string) []byte {
	return []byte(labelV2 + "public/" + kind + "/" + name)
}

// sealedAADV2 is what a sealed section is bound to: its kind, the tenant
// and run of the hold key, its name, and the public bytes as they are
// stored.
func sealedAADV2(kind, tenant, run, name string, publicHash [sha256.Size]byte) []byte {
	return []byte(labelV2 + kind + "/" + tenant + "/" + run + "/" + name + "/" + hex.EncodeToString(publicHash[:]))
}

// DecodeManifestPublicV2 decodes the public section of the manifest of
// id as this daemon wrote it, and refuses one that is not a v2 manifest
// of that ID: another version, another ID, a tenant or key ID that is
// not one, or a base image (which stays in a v1 envelope under the
// fleet key).
func DecodeManifestPublicV2(data []byte, id string) (*ManifestPublicV2, error) {
	if !validAADSegment(id) {
		return nil, invalidSegment("snapshot ID", id)
	}
	var public ManifestPublicV2
	if err := oneJSONDocument(data); err != nil {
		return nil, fmt.Errorf("%w: the public section of manifest %s %v", ErrCorrupt, id, err)
	}
	if err := decodeJSON(data, &public, true); err != nil {
		return nil, fmt.Errorf("%w: the public section of manifest %s %v", ErrCorrupt, id, err)
	}
	if err := public.check(id); err != nil {
		return nil, err
	}
	return &public, nil
}

func (m *ManifestPublicV2) check(id string) error {
	fail := func(why string) error {
		return fmt.Errorf("%w: the public section of manifest %s %s", ErrCorrupt, id, why)
	}
	if m.Version != EnvelopeVersionV2 {
		return fail(fmt.Sprintf("has version %d, which this daemon does not read", m.Version))
	}
	if m.ID != id {
		return fail("does not say it is the manifest of that snapshot")
	}
	if !ValidTenant(m.Tenant) {
		return fail(fmt.Sprintf("names the tenant %s, which is not a tenant", quoted(m.Tenant)))
	}
	// Base images stay in v1 envelopes under the fleet key (owner
	// base-<guid>): a v2 manifest is always a tenant run's snapshot.
	if IsBaseID(id) || m.Purpose == PurposeBase {
		return fail("is a base image, which stays in a v1 envelope under the fleet key rather than v2")
	}
	switch m.Purpose {
	case PurposeStop, PurposeSnapshot:
		if !validAADSegment(m.Run) {
			return fail("does not say which run it is the snapshot of")
		}
		if !ValidKID(m.KID) {
			return fail("does not name the hold key it is under")
		}
	default:
		return fail(fmt.Sprintf("has the purpose %s, which this daemon does not know", quoted(m.Purpose)))
	}
	if !validAttempt(m.Attempt) || m.ChunkBytes <= 0 || len(m.Chunks) == 0 {
		return fail("is not a manifest of a stream")
	}
	return nil
}

// DecodeRecordPublicV2 decodes the public section of generation gen of
// run's record as this daemon wrote it, and refuses one that is not it.
func DecodeRecordPublicV2(data []byte, run string, generation uint64) (*RecordPublicV2, error) {
	if !validAADSegment(run) {
		return nil, invalidSegment("run ID", run)
	}
	if generation == 0 {
		return nil, errors.New("offhost: generation 0 is not a generation")
	}
	var public RecordPublicV2
	if err := oneJSONDocument(data); err != nil {
		return nil, fmt.Errorf("%w: the public section of generation %d of %s %v", ErrCorrupt, generation, run, err)
	}
	if err := decodeJSON(data, &public, true); err != nil {
		return nil, fmt.Errorf("%w: the public section of generation %d of %s %v", ErrCorrupt, generation, run, err)
	}
	if err := public.check(run, generation); err != nil {
		return nil, err
	}
	return &public, nil
}

func (r *RecordPublicV2) check(run string, generation uint64) error {
	fail := func(why string) error {
		return fmt.Errorf("%w: the public section of generation %d of %s %s", ErrCorrupt, generation, run, why)
	}
	if r.Version != EnvelopeVersionV2 {
		return fail(fmt.Sprintf("has version %d, which this daemon does not read", r.Version))
	}
	if r.Run != run || r.Generation != generation {
		return fail("is not the record of that generation of that run")
	}
	if !ValidTenant(r.Tenant) {
		return fail(fmt.Sprintf("names the tenant %s, which is not a tenant", quoted(r.Tenant)))
	}
	switch r.State {
	case RecordDestroyed:
		// A destroyed record is the last of a run and carries nothing.
		if r.KID != "" {
			return fail("puts a destroyed record under a hold key")
		}
	case RecordStopped, RecordRunning, RecordForked:
		if !ValidKID(r.KID) {
			return fail("does not name the hold key it is under")
		}
	default:
		return fail(fmt.Sprintf("has the state %s, which this daemon does not know", quoted(r.State)))
	}
	return nil
}

// DecodeManifestSealedV2 decodes the sealed section of a v2 manifest.
func DecodeManifestSealedV2(data []byte) (ManifestSealedV2, error) {
	var sealed ManifestSealedV2
	if err := oneJSONDocument(data); err != nil {
		return ManifestSealedV2{}, fmt.Errorf("%w: the sealed section of a manifest %v", ErrCorrupt, err)
	}
	if err := decodeJSON(data, &sealed, true); err != nil {
		return ManifestSealedV2{}, fmt.Errorf("%w: the sealed section of a manifest %v", ErrCorrupt, err)
	}
	if !validSHA256(sealed.StreamSHA256) || (sealed.ParentStreamSHA256 != "" && !validSHA256(sealed.ParentStreamSHA256)) {
		return ManifestSealedV2{}, fmt.Errorf("%w: the sealed section of a manifest carries no stream hashes", ErrCorrupt)
	}
	return sealed, nil
}

// DecodeRecordSealedV2 decodes the sealed section of a v2 record.
func DecodeRecordSealedV2(data []byte) (RecordSealedV2, error) {
	var sealed RecordSealedV2
	if err := oneJSONDocument(data); err != nil {
		return RecordSealedV2{}, fmt.Errorf("%w: the sealed section of a record %v", ErrCorrupt, err)
	}
	if err := decodeJSON(data, &sealed, true); err != nil {
		return RecordSealedV2{}, fmt.Errorf("%w: the sealed section of a record %v", ErrCorrupt, err)
	}
	// The payload is the run as the registry holds it: a JSON object,
	// and never a bare string, number or array.
	if len(sealed.Payload) == 0 || sealed.Payload[0] != '{' {
		return RecordSealedV2{}, fmt.Errorf("%w: the sealed section of a record carries no payload", ErrCorrupt)
	}
	if err := oneJSONDocument(sealed.Payload); err != nil {
		return RecordSealedV2{}, fmt.Errorf("%w: a record's payload %v", ErrCorrupt, err)
	}
	return sealed, nil
}

// sealSection encrypts plain under aead with a fresh nonce: the nonce in
// front, as an envelope stores it.
func sealSection(aead cipher.AEAD, plain, aad []byte) ([]byte, error) {
	nonce, err := randomNonce(aead)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, aad), nil
}

// SealV2 seals an envelope: publicBytes, exactly as given, under the
// fleet metadata key, and sealedBytes under holdKey. kind and name are
// what the object is and where it is stored.
//
// holdKey is nil only for a destroyed record, which has no sealed
// section: sealedBytes must then be empty. For every v2 manifest and
// every live record, holdKey must be the run's hold key, and the public
// section must say so: its tenant, run and kid are held to the key's,
// so an envelope is never written that OpenPublicV2 would refuse. Both
// sections are read as this daemon would read them before they are
// sealed: nothing is stored that cannot be opened again.
func SealV2(fmk *Keyring, kind, name string, publicBytes []byte, holdKey *HoldKey, sealedBytes []byte) ([]byte, error) {
	if fmk == nil {
		return nil, errors.New("offhost: sealing needs a keyring")
	}
	if err := checkKindName(kind, name); err != nil {
		return nil, err
	}
	if len(publicBytes) == 0 {
		return nil, fmt.Errorf("offhost: the public section of %s %s is empty", kind, name)
	}
	var blob *WrappedHoldKey
	if holdKey != nil {
		parsed, err := ParseWrappedHoldKey(holdKey.Wrapped)
		if err != nil {
			return nil, fmt.Errorf("the hold key of %s %s: %w", kind, name, err)
		}
		blob = &parsed
	}
	manifest, record, err := checkPublicV2(kind, name, publicBytes, blob)
	if err != nil {
		return nil, err
	}
	public, err := fmk.PublicAEAD(fmk.id, kind, name)
	if err != nil {
		return nil, err
	}
	envelope := EnvelopeV2{Version: EnvelopeVersionV2, FMK: fmk.id}
	sealed, err := sealSection(public, publicBytes, publicAADV2(kind, name))
	if err != nil {
		return nil, err
	}
	envelope.PublicNonce, envelope.Public = sealed[:public.NonceSize()], sealed[public.NonceSize():]
	if holdKey == nil {
		if len(sealedBytes) != 0 {
			return nil, fmt.Errorf("offhost: %s %s takes no sealed section (a destroyed record), and bytes were given for one", kind, name)
		}
		return json.Marshal(envelope)
	}
	if err := holdKey.binds(manifest, record); err != nil {
		return nil, fmt.Errorf("%s %s: %w", kind, name, err)
	}
	switch kind {
	case kindManifest:
		_, err = DecodeManifestSealedV2(sealedBytes)
	case kindRecord:
		_, err = DecodeRecordSealedV2(sealedBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", kind, name, err)
	}
	aead, err := holdKey.sealedAEAD(kind, name)
	if err != nil {
		return nil, err
	}
	sealed, err = sealSection(aead, sealedBytes, sealedAADV2(kind, holdKey.Tenant, holdKey.Run, name, sha256.Sum256(publicBytes)))
	if err != nil {
		return nil, err
	}
	envelope.Key = holdKey.Wrapped
	envelope.SealedNonce, envelope.Sealed = sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	return json.Marshal(envelope)
}

// resealPublic is a v2 envelope with its public section sealed again
// under fmk's current key, and nothing else changed: the public bytes are
// the ones that were opened, and the sealed section, its nonce and the
// wrapped hold key are carried over exactly. So the sealed section still
// opens: its AAD holds the SHA-256 of the public bytes, which did not
// move. This is the fleet key's rotation of a v2 manifest — it needs the
// fleet key alone, never the run's hold key.
//
// opened must have been opened as kind name, and must be under another
// key than fmk's current one: a caller that reseals what is current gets
// a new nonce for nothing.
func resealPublic(fmk *Keyring, kind, name string, opened *OpenedPublicV2) ([]byte, error) {
	if opened.kind != kind || opened.name != name {
		return nil, fmt.Errorf("%w: the envelope was opened as %s %s, and is asked for as %s %s", ErrCorrupt, opened.kind, opened.name, kind, name)
	}
	public, err := fmk.PublicAEAD(fmk.id, kind, name)
	if err != nil {
		return nil, err
	}
	section, err := sealSection(public, opened.PublicBytes, publicAADV2(kind, name))
	if err != nil {
		return nil, err
	}
	envelope := EnvelopeV2{
		Version: EnvelopeVersionV2, FMK: fmk.id,
		PublicNonce: section[:public.NonceSize()], Public: section[public.NonceSize():],
		Key: opened.WrappedKey, SealedNonce: opened.sealedNonce, Sealed: opened.sealedBytes,
	}
	return json.Marshal(envelope)
}

// OpenedPublicV2 is the public section of a v2 envelope, opened: all of
// it that any host in the fleet may read. It needs no tenant key, and it
// is what OpenSealedV2 is given with the run's hold key.
type OpenedPublicV2 struct {
	// PublicBytes are the public section exactly as it was sealed.
	PublicBytes []byte
	// FMKID is the fleet metadata key the public section was under.
	FMKID string
	// WrappedKey is the hold key the sealed section is under, wrapped,
	// and "" when there is no sealed section.
	WrappedKey string
	// HasSealed says whether the envelope has a sealed section. A public
	// section's KID is worth trusting only when it does.
	HasSealed bool

	// kind and name are what the object was opened as; OpenSealedV2 is
	// asked for the same or not at all.
	kind, name string
	manifest   *ManifestPublicV2
	record     *RecordPublicV2
	// sealedNonce and sealedBytes are the sealed section as stored.
	sealedNonce, sealedBytes []byte
}

// Kind and Name are what the object is and where it is stored.
func (o OpenedPublicV2) Kind() string { return o.kind }
func (o OpenedPublicV2) Name() string { return o.name }

// Manifest is a copy of the decoded public section, for a manifest; nil else.
func (o OpenedPublicV2) Manifest() *ManifestPublicV2 {
	if o.manifest == nil {
		return nil
	}
	cp := *o.manifest
	cp.Chunks = slices.Clone(o.manifest.Chunks)
	return &cp
}

// Record is a copy of the decoded public section, for a record; nil else.
func (o OpenedPublicV2) Record() *RecordPublicV2 {
	if o.record == nil {
		return nil
	}
	cp := *o.record
	return &cp
}

// OpenPublicV2 opens the public section of kind name: under the one
// fleet metadata key the envelope names, and only for the kind and name
// it was sealed for. The section is then decoded and held to what the
// envelope says of it (checkPublicV2). No tenant key is needed or
// wanted: collection, scrub, verify, pins and the fence read this.
func OpenPublicV2(fmk *Keyring, kind, name string, stored []byte) (OpenedPublicV2, error) {
	if err := checkKindName(kind, name); err != nil {
		return OpenedPublicV2{}, err
	}
	if fmk == nil {
		return OpenedPublicV2{}, errors.New("offhost: opening needs a keyring")
	}
	if err := oneJSONDocument(stored); err != nil {
		return OpenedPublicV2{}, fmt.Errorf("%w: %s %s is not a sealed document: %v", ErrCorrupt, kind, name, err)
	}
	version, err := envelopeVersionOf(stored)
	if err != nil {
		return OpenedPublicV2{}, fmt.Errorf("%w: %s %s is not a sealed document: %v", ErrCorrupt, kind, name, err)
	}
	if version != EnvelopeVersionV2 {
		return OpenedPublicV2{}, fmt.Errorf("%s %s has version %d: not a v2 envelope", kind, name, version)
	}
	var envelope EnvelopeV2
	if err := decodeJSON(stored, &envelope, true); err != nil {
		return OpenedPublicV2{}, fmt.Errorf("%w: %s %s %v", ErrCorrupt, kind, name, err)
	}
	sealed := envelope.Key != "" || len(envelope.SealedNonce) > 0 || len(envelope.Sealed) > 0
	// All of a sealed section or none: a key, a nonce of the one size
	// there is, and the section itself.
	if sealed && (envelope.Key == "" || len(envelope.Sealed) == 0 || len(envelope.SealedNonce) != nonceSizeV2) {
		return OpenedPublicV2{}, fmt.Errorf("%w: %s %s has part of a sealed section and not all of it", ErrCorrupt, kind, name)
	}
	public, err := fmk.PublicAEAD(envelope.FMK, kind, name)
	if err != nil {
		return OpenedPublicV2{}, fmt.Errorf("%s %s: %w", kind, name, err)
	}
	if len(envelope.PublicNonce) != public.NonceSize() {
		return OpenedPublicV2{}, fmt.Errorf("%w: %s %s: the public section's nonce is not one", ErrCorrupt, kind, name)
	}
	publicBytes, err := public.Open(nil, envelope.PublicNonce, envelope.Public, publicAADV2(kind, name))
	if err != nil {
		return OpenedPublicV2{}, fmt.Errorf("%w: %s %s: the public section does not open under fleet key %s", ErrCorrupt, kind, name, quoted(envelope.FMK))
	}
	var blob *WrappedHoldKey
	if sealed {
		parsed, err := ParseWrappedHoldKey(envelope.Key)
		if err != nil {
			return OpenedPublicV2{}, fmt.Errorf("%w: the key of %s %s: %v", ErrCorrupt, kind, name, err)
		}
		blob = &parsed
	}
	manifest, record, err := checkPublicV2(kind, name, publicBytes, blob)
	if err != nil {
		return OpenedPublicV2{}, fmt.Errorf("%s %s: %w", kind, name, err)
	}
	return OpenedPublicV2{
		PublicBytes: publicBytes, FMKID: envelope.FMK, WrappedKey: envelope.Key, HasSealed: sealed,
		kind: kind, name: name, manifest: manifest, record: record,
		sealedNonce: envelope.SealedNonce, sealedBytes: envelope.Sealed,
	}, nil
}

// OpenSealedV2 opens the sealed section of an envelope whose public
// section is opened, under holdKey: the key of the run, selected by the
// kid the envelope names. It fails (ErrCorrupt) when any of these is not
// so:
//
//   - the envelope has no sealed section, or is not asked for as the kind
//     and name it was opened as;
//   - the hold key is not the one the envelope names: another kid or
//     another tenant (a re-wrapped blob of the same key is accepted, as
//     the sealed section's AAD does not bind the wrapping spelling);
//   - the hold key is not the key of what the public section says: its
//     tenant, its run, its key;
//   - the public bytes are not the bytes the sealed section was sealed
//     over, changed and sealed again under a valid fleet key or not.
func OpenSealedV2(kind, name string, opened OpenedPublicV2, holdKey HoldKey) ([]byte, error) {
	if err := checkKindName(kind, name); err != nil {
		return nil, err
	}
	if opened.kind == "" {
		return nil, errors.New("offhost: a public section that was never opened")
	}
	// Before the key is compared with anything: a key that is none is
	// said to be none, not to be another key's.
	if _, err := holdKey.key(); err != nil {
		return nil, err
	}
	if opened.kind != kind || opened.name != name {
		return nil, fmt.Errorf("%w: the envelope was opened as %s %s, and is asked for as %s %s", ErrCorrupt, opened.kind, opened.name, kind, name)
	}
	if !opened.HasSealed || opened.WrappedKey == "" {
		return nil, fmt.Errorf("%w: %s %s has no sealed section", ErrCorrupt, kind, name)
	}
	blob, err := ParseWrappedHoldKey(opened.WrappedKey)
	if err != nil {
		return nil, err
	}
	if blob.Tenant != holdKey.Tenant || blob.KID != holdKey.KID {
		return nil, fmt.Errorf("%w: %s %s is under hold key %s of tenant %s, and the key given is %s of tenant %s",
			ErrCorrupt, kind, name, blob.KID, blob.Tenant, quoted(holdKey.KID), quoted(holdKey.Tenant))
	}
	if err := holdKey.binds(opened.manifest, opened.record); err != nil {
		return nil, fmt.Errorf("%s %s: %w", kind, name, err)
	}
	aead, err := holdKey.sealedAEAD(kind, name)
	if err != nil {
		return nil, err
	}
	if len(opened.sealedNonce) != aead.NonceSize() {
		return nil, fmt.Errorf("%w: %s %s: the sealed section's nonce is not one", ErrCorrupt, kind, name)
	}
	plain, err := aead.Open(nil, opened.sealedNonce, opened.sealedBytes,
		sealedAADV2(kind, holdKey.Tenant, holdKey.Run, name, sha256.Sum256(opened.PublicBytes)))
	if err != nil {
		return nil, fmt.Errorf("%w: %s %s: the sealed section does not open under hold key %s: the public section is not the one it was sealed over, or the key is not the one that sealed it",
			ErrCorrupt, kind, name, holdKey.KID)
	}
	return plain, nil
}

// checkPublicV2 decodes the public section of kind name and holds it to
// what the envelope says of it: blob is the hold key the envelope names,
// nil when it has no sealed section. Every v2 manifest and every live
// record is under a hold key; only a destroyed record has no sealed
// section. Where the envelope has a sealed section, the public section
// names the very key it is under.
func checkPublicV2(kind, name string, public []byte, blob *WrappedHoldKey) (manifest *ManifestPublicV2, record *RecordPublicV2, err error) {
	sealed := false
	switch kind {
	case kindManifest:
		if manifest, err = DecodeManifestPublicV2(public, name); err != nil {
			return nil, nil, err
		}
		sealed = true
	case kindRecord:
		run, generation, err := splitRecordName(name)
		if err != nil {
			return nil, nil, err
		}
		if record, err = DecodeRecordPublicV2(public, run, generation); err != nil {
			return nil, nil, err
		}
		sealed = record.State != RecordDestroyed
	default:
		return nil, nil, fmt.Errorf("offhost: %s is not a kind with a public section", quoted(kind))
	}
	if sealed != (blob != nil) {
		if sealed {
			return nil, nil, fmt.Errorf("%w: %s %s is under a hold key, and its envelope has no sealed section", ErrCorrupt, kind, name)
		}
		return nil, nil, fmt.Errorf("%w: %s %s takes no sealed section (a destroyed record), and its envelope has one", ErrCorrupt, kind, name)
	}
	if blob == nil {
		return manifest, record, nil
	}
	// The one the object is: a manifest or a record, never both.
	var tenant, kid string
	if manifest != nil {
		tenant, kid = manifest.Tenant, manifest.KID
	} else {
		tenant, kid = record.Tenant, record.KID
	}
	if blob.Tenant != tenant || blob.KID != kid {
		return nil, nil, fmt.Errorf("%w: %s %s says it is under hold key %s of tenant %s, and the key in its envelope is %s of tenant %s",
			ErrCorrupt, kind, name, kid, tenant, blob.KID, blob.Tenant)
	}
	return manifest, record, nil
}

// binds is whether the hold key is the key of what a public section says
// its object is: that tenant, that run, that key. manifest and record:
// the one the object is.
func (h HoldKey) binds(manifest *ManifestPublicV2, record *RecordPublicV2) error {
	if _, err := h.key(); err != nil {
		return err
	}
	var tenant, kid, run string
	var what string
	switch {
	case manifest != nil:
		tenant, kid, run, what = manifest.Tenant, manifest.KID, manifest.Run, "the manifest of "+manifest.ID
	case record != nil:
		tenant, kid, run, what = record.Tenant, record.KID, record.Run, fmt.Sprintf("generation %d of the record of %s", record.Generation, record.Run)
	default:
		return errors.New("offhost: no public section to hold the hold key to")
	}
	if h.Tenant != tenant || h.KID != kid || h.Run != run {
		return fmt.Errorf("%w: hold key %s is the key of run %s of tenant %s, and %s is of run %s of tenant %s under key %s",
			ErrCorrupt, h.KID, h.Run, h.Tenant, what, run, tenant, kid)
	}
	return nil
}

// sealedAEAD is the AEAD of the hold key for the sealed section of kind
// name: the key of that snapshot, or of that generation of the run's
// record, which is derived only for the run the key is the key of.
func (h HoldKey) sealedAEAD(kind, name string) (cipher.AEAD, error) {
	switch kind {
	case kindManifest:
		return h.ManifestSealedAEAD(name)
	case kindRecord:
		run, generation, err := splitRecordName(name)
		if err != nil {
			return nil, err
		}
		if run != h.Run {
			return nil, fmt.Errorf("%w: hold key %s is the key of run %s, not of %s", ErrCorrupt, h.KID, h.Run, run)
		}
		return h.RecordSealedAEAD(generation)
	}
	return nil, fmt.Errorf("offhost: %s is not a kind with a sealed section", quoted(kind))
}
