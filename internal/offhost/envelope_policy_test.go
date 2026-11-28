package offhost

import (
	"errors"
	"strings"
	"testing"
)

// The v1 reader's end condition: a v1 envelope opens only where the key
// custody policy allows, and nowhere else.

func v1Envelope(t *testing.T, keys *Keyring, kind, name, owner, document string) []byte {
	t.Helper()
	key, err := keys.NewKey(owner)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := seal(key, kind, name, []byte(document))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

const v1Document = `{"version":1,"run":"` + runA + `"}`

func TestV1IsReadOnlyAsFarAsPolicyAllows(t *testing.T) {
	keys := testKeyring(t, 1)
	open := func(kind, name string, stored []byte, policy V1ReadPolicy) ([]byte, Key, error) {
		return OpenV1IfAllowed(keys, kind, name, stored, policy)
	}
	for _, c := range []struct {
		kind, name string
	}{
		{kindRecord, recordName(runA, 1)},
		{kindManifest, snapA},
	} {
		stored := v1Envelope(t, keys, c.kind, c.name, runA, v1Document)
		// Nothing allows it.
		for name, policy := range map[string]V1ReadPolicy{
			"no policy":          {},
			"a base's policy":    {IsBase: true, BaseID: baseSeven},
			"a base ID, unsaid":  {BaseID: baseSeven},
			"another legacy run": {LegacyRun: runB},
			"another legacy run alongside AllowLegacyRead": {LegacyRun: runB, AllowLegacyRead: true},
			"allowances, in a policy for another object":   {IsBase: true, BaseID: snapA, AllowLegacyRead: true},
		} {
			if _, _, err := open(c.kind, c.name, stored, policy); !errors.Is(err, ErrV1Refused) {
				t.Errorf("%s %s, %s: %v, want ErrV1Refused", c.kind, c.name, name, err)
			}
		}
		// Either allowance opens it, as the v1 reader would.
		for name, policy := range map[string]V1ReadPolicy{
			"a legacy run": {LegacyRun: runA},
			"legacy read":  {AllowLegacyRead: true},
			"both":         {LegacyRun: runA, AllowLegacyRead: true},
		} {
			document, key, err := open(c.kind, c.name, stored, policy)
			if err != nil || string(document) != v1Document || key.Owner != runA || !strings.HasPrefix(key.Wrapped, keys.id+".") {
				t.Errorf("%s %s, %s: %q, %v", c.kind, c.name, name, document, err)
			}
		}
		// Opened by the v1 reader, it answers as the v1 reader does:
		// another name is corrupt, and not a policy refusal.
		wrongName := snapB
		if c.kind == kindRecord {
			wrongName = recordName(runA, 2)
		}
		if _, _, err := open(c.kind, wrongName, stored, V1ReadPolicy{LegacyRun: runA}); !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrV1Refused) {
			t.Errorf("%s under another name with an allowance: %v, want ErrCorrupt and not ErrV1Refused", c.kind, err)
		}
	}
}

func TestThePolicyIsDecidedBeforeAnythingIsOpened(t *testing.T) {
	keys := testKeyring(t, 1)
	name := recordName(runA, 1)
	// An envelope under another master key altogether.
	stranger := testKeyring(t, 2)
	stored := v1Envelope(t, stranger, kindRecord, name, runA, v1Document)
	if _, _, err := OpenV1IfAllowed(keys, kindRecord, name, stored, V1ReadPolicy{}); !errors.Is(err, ErrV1Refused) || errors.Is(err, ErrWrongKey) {
		t.Errorf("with no allowance: %v, want ErrV1Refused and not ErrWrongKey", err)
	}
	if _, _, err := OpenV1IfAllowed(keys, kindRecord, name, stored, V1ReadPolicy{LegacyRun: runA}); !errors.Is(err, ErrWrongKey) || errors.Is(err, ErrV1Refused) {
		t.Errorf("with an allowance: %v, want ErrWrongKey and not ErrV1Refused", err)
	}
	// What is not a v1 envelope is not refused by policy: it is said
	// for what it is.
	for name, c := range map[string]struct {
		stored []byte
		not    []error
	}{
		"garbage":         {[]byte(`hello`), []error{ErrV1Refused}},
		"no version":      {[]byte(`{"owner":"x"}`), []error{ErrV1Refused}},
		"v written twice": {[]byte(`{"v":1,"v":1,"owner":"x"}`), []error{ErrV1Refused}},
	} {
		_, _, err := OpenV1IfAllowed(keys, kindRecord, recordName(runA, 1), c.stored, V1ReadPolicy{})
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v, want ErrCorrupt", name, err)
		}
		for _, not := range c.not {
			if errors.Is(err, not) {
				t.Errorf("%s: %v is also %v", name, err, not)
			}
		}
	}
	// No keyring is a caller's error, and no v1 reader at all.
	if _, _, err := OpenV1IfAllowed(nil, kindRecord, recordName(runA, 1), stored, V1ReadPolicy{LegacyRun: runA}); err == nil {
		t.Fatal("opened without a keyring")
	}
}

func TestAV1BaseIsReadOnlyAsABase(t *testing.T) {
	keys := testKeyring(t, 1)
	own := v1Envelope(t, keys, kindManifest, baseSeven, baseSeven, v1Document)
	// The same base-owned envelope, sealed for somewhere else.
	underSnapshot := v1Envelope(t, keys, kindManifest, snapA, baseSeven, v1Document)
	asRecord := v1Envelope(t, keys, kindRecord, recordName(runA, 1), baseSeven, v1Document)
	// A base image's own manifest is read under the fleet key with no
	// allowance at all, said or not.
	for name, policy := range map[string]V1ReadPolicy{
		"a base's policy":     {IsBase: true, BaseID: baseSeven},
		"nothing said":        {},
		"beside an allowance": {LegacyRun: runA},
	} {
		if document, key, err := OpenV1IfAllowed(keys, kindManifest, baseSeven, own, policy); err != nil || string(document) != v1Document || key.Owner != baseSeven {
			t.Errorf("%s: %q, %v", name, document, err)
		}
	}
	// Forged: owned by anything else but the base's own ID, under any
	// policy.
	for _, owner := range []string{runA, "daemon-1", "", "base-8", baseSeven + "0", "x" + baseSeven, "BASE-7", "base-", baseSeven[:len(baseSeven)-1]} {
		stored := v1Envelope(t, keys, kindManifest, baseSeven, owner, v1Document)
		for name, policy := range map[string]V1ReadPolicy{
			"a base's policy":           {IsBase: true, BaseID: baseSeven},
			"nothing said":              {},
			"legacy read":               {AllowLegacyRead: true},
			"a legacy run":              {LegacyRun: runA},
			"a policy for another base": {IsBase: true, BaseID: "base-8"},
		} {
			if _, _, err := OpenV1IfAllowed(keys, kindManifest, baseSeven, stored, policy); !errors.Is(err, ErrV1Refused) {
				t.Errorf("the manifest of %s owned by %q, %s: %v, want ErrV1Refused", baseSeven, owner, name, err)
			}
		}
	}
	// A base image's envelope anywhere but under its own ID: as a
	// record, under a snapshot's ID, or with a policy for another base.
	for name, c := range map[string]struct {
		kind, object string
		stored       []byte
		policy       V1ReadPolicy
	}{
		"under a snapshot's ID, with a policy for the base":          {kindManifest, snapA, underSnapshot, V1ReadPolicy{IsBase: true, BaseID: baseSeven}},
		"under a snapshot's ID, legacy read":                         {kindManifest, snapA, underSnapshot, V1ReadPolicy{AllowLegacyRead: true}},
		"under a snapshot's ID, a legacy run":                        {kindManifest, snapA, underSnapshot, V1ReadPolicy{LegacyRun: runA}},
		"under a snapshot's ID, with a policy for that ID":           {kindManifest, snapA, underSnapshot, V1ReadPolicy{IsBase: true, BaseID: snapA, AllowLegacyRead: true}},
		"as a record, with a policy for the base":                    {kindRecord, recordName(runA, 1), asRecord, V1ReadPolicy{IsBase: true, BaseID: baseSeven}},
		"as a record, legacy read":                                   {kindRecord, recordName(runA, 1), asRecord, V1ReadPolicy{AllowLegacyRead: true}},
		"as a record, a legacy run":                                  {kindRecord, recordName(runA, 1), asRecord, V1ReadPolicy{LegacyRun: runA}},
		"under its own ID, with a policy for a base that is not one": {kindManifest, baseSeven, own, V1ReadPolicy{IsBase: true, BaseID: "base-xyz"}},
		"under its own ID, with a policy for another base":           {kindManifest, baseSeven, own, V1ReadPolicy{IsBase: true, BaseID: "base-8"}},
		"under its own ID, with a base's policy with no ID":          {kindManifest, baseSeven, own, V1ReadPolicy{IsBase: true}},
	} {
		if _, _, err := OpenV1IfAllowed(keys, c.kind, c.object, c.stored, c.policy); !errors.Is(err, ErrV1Refused) {
			t.Errorf("%s: %v, want ErrV1Refused", name, err)
		}
	}
	// A run's snapshot with a base's policy is refused too: the policy
	// is held to what the object is.
	runSnapshot := v1Envelope(t, keys, kindManifest, snapA, runA, v1Document)
	if _, _, err := OpenV1IfAllowed(keys, kindManifest, snapA, runSnapshot, V1ReadPolicy{IsBase: true, BaseID: snapA}); !errors.Is(err, ErrV1Refused) {
		t.Errorf("a run's snapshot with a base's policy for its ID: %v, want ErrV1Refused", err)
	}
	// The v1 reader alone knows nothing of any of this: it opens the
	// forged envelope. The refusal lives here, and a v2 daemon reads v1
	// through here and nowhere else.
	forged := v1Envelope(t, keys, kindManifest, baseSeven, runA, v1Document)
	if _, _, err := keys.open(kindManifest, baseSeven, forged); err != nil {
		t.Fatalf("the v1 reader: %v", err)
	}
}

func TestTheV1ReaderRefusesV2(t *testing.T) {
	cloud := newKMS(t)
	fmk := testKeyring(t, 1)
	key := cloud.hold(t, tenantOne, runA)
	v2 := map[string][]byte{
		kindManifest: must2(sealManifest(fmk, stopManifest(snapA, tenantOne, runA, key.KID), &key, ManifestSealedV2{StreamSHA256: hashCD})),
		kindRecord:   must2(sealRecord(fmk, liveRecord(tenantOne, runA, key.KID, RecordStopped, 1), &key, recordPayload)),
	}
	names := map[string]string{kindManifest: snapA, kindRecord: recordName(runA, 1)}
	// A v1-only daemon stops on a v2 object and says why.
	for what, stored := range v2 {
		_, _, err := fmk.open(kindManifest, names[what], stored)
		if err == nil || errors.Is(err, ErrCorrupt) || errors.Is(err, ErrWrongKey) || !strings.Contains(err.Error(), "version 2") {
			t.Errorf("the v1 reader on the v2 envelope of %s: %v, want it to say the envelope has version 2", what, err)
		}
	}
	// With a policy and every allowance, a v2 envelope is still not a
	// v1 one: not refused by policy, not corrupt.
	for what, stored := range v2 {
		_, _, err := OpenV1IfAllowed(fmk, kindManifest, names[what], stored, V1ReadPolicy{LegacyRun: runA, AllowLegacyRead: true})
		if err == nil || errors.Is(err, ErrV1Refused) || errors.Is(err, ErrCorrupt) {
			t.Errorf("the v1 path with every allowance on the v2 envelope of %s: %v", what, err)
		}
	}
	// And the other way round.
	v1 := v1Envelope(t, fmk, kindManifest, snapA, runA, v1Document)
	if _, err := OpenPublicV2(fmk, kindManifest, snapA, v1); err == nil || errors.Is(err, ErrCorrupt) {
		t.Errorf("the v2 reader on a v1 envelope: %v, want a plain error", err)
	}
	if v, err := InspectEnvelopeVersion(v1); err != nil || v != 1 {
		t.Fatalf("InspectEnvelopeVersion of a v1 envelope = %d, %v", v, err)
	}
	if v, err := InspectEnvelopeVersion(v2[kindManifest]); err != nil || v != 2 {
		t.Fatalf("InspectEnvelopeVersion of a v2 envelope = %d, %v", v, err)
	}
	// A v1 wrapped key and a v2 blob are told apart by their first
	// component, and neither opens as the other.
	if IsBaseID(snapA) || !IsBaseID(baseSeven) || LegacyKID != "v1" || ValidKID(LegacyKID) {
		t.Fatal("a constant changed")
	}
}
