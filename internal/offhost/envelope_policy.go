package offhost

import (
	"encoding/json"
	"errors"
	"fmt"
)

// The v1 reader, and when it may be used at all.
//
// With a key source (--remote-kms) a daemon writes v2 and reads v1 only
// as far as the key custody policy allows, and no further once the last
// run is migrated: that is the end condition. A v1 envelope is whole
// under the fleet metadata key alone, so whoever holds that key and the
// bucket can forge one; a v2 envelope's sealed section needs the run's
// hold key, which such an attacker has not.
//
//   - A run Cloud has marked legacy (expect.kid "v1") is read as v1 in
//     pushed mode; in local mode v1 is read while the operator has
//     --remote-legacy-read on, and they take it off after migration.
//   - A base image stays under the fleet key, in a v1 envelope, and is
//     read as one only when the envelope is its own: stored under a base
//     ID, and owned by that ID.
//   - Anything else in a v1 envelope is refused: ErrV1Refused.
//
// What an object is decides which of these applies, not only what the
// caller says of it: an envelope under a base ID, or owned by one, is a
// base image's as far as this is concerned, whatever the policy says.
//
// Without a key source nothing of this is consulted: v1 is read as
// before.

// ErrV1Refused: the object is a v1 envelope, and the key custody policy
// does not allow it to be read as one. Not corruption: a daemon with no
// key source would have opened it.
var ErrV1Refused = errors.New("v1 envelope refused by key custody policy")

// V1ReadPolicy says whether the v1 envelope of one object may be read.
type V1ReadPolicy struct {
	// LegacyRun: the one run marked legacy (pushed mode: Cloud's
	// expect.kid for it is "v1"). Held to the object: the envelope's
	// owner — and for a record, the record's run name — must match
	// LegacyRun.
	LegacyRun string
	// AllowLegacyRead: local mode, with --remote-legacy-read on.
	AllowLegacyRead bool
	// IsBase and BaseID: the caller is reading the manifest of the base
	// image BaseID, which is read as v1 under the fleet key. It is an
	// assertion, held to the object: BaseID must be a base ID, the object
	// must be a manifest stored under it, and the envelope must be owned
	// by it. A base image's manifest is read as one by what it is even
	// when the caller does not say so (IsBase false).
	IsBase bool
	BaseID string
}

// envelopeVersionOf reads exact-case "v" out of an envelope already
// found to be one whole JSON document.
func envelopeVersionOf(stored []byte) (int, error) {
	var fields map[string]json.RawMessage
	if err := decodeJSON(stored, &fields, false); err != nil {
		return 0, err
	}
	raw, ok := fields["v"]
	if !ok {
		return 0, errors.New("it has no version")
	}
	var version *int
	if err := decodeJSON(raw, &version, false); err != nil {
		return 0, err
	}
	if version == nil {
		return 0, errors.New("it has no version")
	}
	return *version, nil
}

// envelopeOwnerOf reads exact-case "owner" out of a v1 envelope already
// found to be one whole JSON document.
func envelopeOwnerOf(stored []byte) (string, error) {
	var fields map[string]json.RawMessage
	if err := decodeJSON(stored, &fields, false); err != nil {
		return "", err
	}
	raw, ok := fields["owner"]
	if !ok {
		return "", nil
	}
	var owner string
	if err := decodeJSON(raw, &owner, false); err != nil {
		return "", err
	}
	return owner, nil
}

// InspectEnvelopeVersion reads the version of a stored envelope without
// opening it: 1 for a v1 object, 2 for v2. No key is needed. ErrCorrupt
// when it is not an envelope at all: not one whole JSON document, or one
// without an integer "v".
func InspectEnvelopeVersion(stored []byte) (int, error) {
	if err := oneJSONDocument(stored); err != nil {
		return 0, fmt.Errorf("%w: not a sealed document: %v", ErrCorrupt, err)
	}
	version, err := envelopeVersionOf(stored)
	if err != nil {
		return 0, fmt.Errorf("%w: not a sealed document: %v", ErrCorrupt, err)
	}
	return version, nil
}

// OpenV1IfAllowed opens a v1 envelope of kind name as the v1 reader
// would, and only as far as policy allows: ErrV1Refused when it is not
// allowed, whatever the envelope would have opened as. The policy is
// decided before anything is decrypted, and by what the object is and
// who owns it:
//
//   - a manifest stored under a base ID, or any envelope owned by a base
//     ID, is a base image's: it is read only when it is a manifest under
//     that very ID, owned by that ID. No legacy allowance reads it;
//   - a policy that says IsBase is held to that, and is refused for
//     anything else;
//   - a policy that names LegacyRun is held to that run: the envelope's
//     owner (and for a record, the record's run) must match LegacyRun;
//   - otherwise AllowLegacyRead must be on.
//
// What is allowed is opened with the keyring's v1 reader, which answers
// for the rest: ErrWrongKey for another master key, ErrCorrupt for a
// document that is not what its name says.
func OpenV1IfAllowed(fmk *Keyring, kind, name string, stored []byte, policy V1ReadPolicy) ([]byte, Key, error) {
	if fmk == nil {
		return nil, Key{}, errors.New("offhost: opening needs a keyring")
	}
	version, err := InspectEnvelopeVersion(stored)
	if err != nil {
		return nil, Key{}, err
	}
	if version != envelopeVersion {
		return nil, Key{}, fmt.Errorf("%s %s has version %d: not a v1 envelope", kind, name, version)
	}
	owner, err := envelopeOwnerOf(stored)
	if err != nil {
		return nil, Key{}, fmt.Errorf("%w: %s %s is not a sealed document: %v", ErrCorrupt, kind, name, err)
	}
	base := kind == kindManifest && IsBaseID(name)
	if policy.IsBase && (!base || policy.BaseID != name || !validID(name)) {
		return nil, Key{}, fmt.Errorf("%w: the policy allows the v1 manifest of the base image %s, and this is the v1 %s of %s",
			ErrV1Refused, quoted(policy.BaseID), kind, name)
	}
	if base {
		if owner != name {
			return nil, Key{}, fmt.Errorf("%w: the v1 manifest of %s is owned by %s, and a base image's is read only under its own ID",
				ErrV1Refused, name, quoted(owner))
		}
		return fmk.open(kind, name, stored)
	}
	if IsBaseID(owner) {
		return nil, Key{}, fmt.Errorf("%w: the v1 %s of %s is owned by the base image %s, and a base image's is read only under its own ID",
			ErrV1Refused, kind, name, quoted(owner))
	}
	if policy.LegacyRun != "" {
		if !validAADSegment(policy.LegacyRun) || owner != policy.LegacyRun {
			return nil, Key{}, fmt.Errorf("%w: the policy allows legacy run %s, and this v1 %s of %s is owned by %s",
				ErrV1Refused, quoted(policy.LegacyRun), kind, name, quoted(owner))
		}
		if kind == kindRecord {
			run, _, err := splitRecordName(name)
			if err != nil {
				return nil, Key{}, err
			}
			if run != policy.LegacyRun {
				return nil, Key{}, fmt.Errorf("%w: the policy allows legacy run %s, and this v1 record is for %s",
					ErrV1Refused, quoted(policy.LegacyRun), quoted(run))
			}
		}
		return fmk.open(kind, name, stored)
	}
	if !policy.AllowLegacyRead {
		return nil, Key{}, fmt.Errorf("%w: %s %s is not marked legacy", ErrV1Refused, kind, name)
	}
	return fmk.open(kind, name, stored)
}
