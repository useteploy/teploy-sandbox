package offhost

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
)

// The two key sources: a fleet without Cloud as its own KMS, and a host
// served from what Cloud pushed.

func ciphertextOf(t *testing.T, blob string) string {
	t.Helper()
	if _, err := ParseWrappedHoldKey(blob); err != nil {
		t.Fatal(err)
	}
	return strings.Split(blob, ".")[4]
}

func TestALocalKeySourceMintsUnwrapsAndRewraps(t *testing.T) {
	root := randomBytes(t, KeySize)
	source, err := NewLocalKeySource(root)
	if err != nil {
		t.Fatal(err)
	}
	if source.Version() != 1 {
		t.Fatalf("a new source is at version %d", source.Version())
	}
	one, err := source.Mint(tenantOne, runA)
	if err != nil {
		t.Fatal(err)
	}
	two, err := source.Mint(tenantOne, runA)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidKID(one.KID) || one.KID == two.KID || bytes.Equal(rawOf(one), rawOf(two)) || one.Wrapped == two.Wrapped {
		t.Fatal("two mints made one key")
	}
	if one.Tenant != tenantOne || one.Run != runA {
		t.Fatalf("minted %s", one)
	}
	parsed, err := ParseWrappedHoldKey(one.Wrapped)
	if err != nil || parsed.TKVersion != 1 || parsed.KID != one.KID || parsed.Tenant != tenantOne {
		t.Fatalf("the blob of a minted key: %+v, %v", parsed, err)
	}
	// Unwrap is the key, and its own copy of it.
	opened, err := source.Unwrap(tenantOne, runA, one.Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	assertKey(t, opened, one)
	if _, err := source.Unwrap(tenantOne, runB, one.Wrapped); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a blob for another run: %v, want ErrCorrupt", err)
	}
	if _, err := source.Unwrap(tenantTwo, runA, one.Wrapped); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a blob for another tenant: %v, want ErrCorrupt", err)
	}
	// Anyone with the root file unwraps the same blob to the same key:
	// the KMS's derivation and the source's are one.
	tk, err := TenantKey(root, tenantOne)
	if err != nil {
		t.Fatal(err)
	}
	fromKMS, err := UnwrapHoldKey(tk, runA, one.Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	assertKey(t, fromKMS, one)

	// What was sealed under the key before a re-wrap opens after it.
	fmk := testKeyring(t, 1)
	stored := okv(sealManifest(fmk, stopManifest(snapA, tenantOne, runA, one.KID), &one, ManifestSealedV2{StreamSHA256: hashCD}))
	if _, err := openBoth(t, fmk, kindManifest, snapA, stored, opened); err != nil {
		t.Fatal(err)
	}

	// Under the version it is already at, there is nothing to re-wrap,
	// though the blob is still verified for tenant and run.
	if again, err := source.Rewrap(tenantOne, runA, one.Wrapped); err != nil || again != one.Wrapped {
		t.Fatalf("Rewrap under the current version = %q, %v", again, err)
	}
	if _, err := source.Rewrap(tenantOne, runB, one.Wrapped); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Rewrap under the current version for another run: %v, want ErrCorrupt", err)
	}
	if _, err := source.Rewrap(tenantTwo, runA, one.Wrapped); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Rewrap under the current version for another tenant: %v, want ErrCorrupt", err)
	}

	// The root file is rotated: the next version, with the one before
	// kept to open.
	next := randomBytes(t, KeySize)
	rotated, err := NewLocalKeySourceWithVersion(2, next)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotated.AddPrevious(1, root); err != nil {
		t.Fatal(err)
	}
	fresh, err := rotated.Mint(tenantOne, runB)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, _ := ParseWrappedHoldKey(fresh.Wrapped); parsed.TKVersion != 2 {
		t.Fatalf("a minted blob is under version %d, want 2", parsed.TKVersion)
	}
	kept, err := rotated.Unwrap(tenantOne, runA, one.Wrapped)
	if err != nil {
		t.Fatalf("a blob of the previous version: %v", err)
	}
	assertKey(t, kept, one)
	moved, err := rotated.Rewrap(tenantOne, runA, one.Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = ParseWrappedHoldKey(moved)
	if err != nil || parsed.TKVersion != 2 || parsed.KID != one.KID || moved == one.Wrapped {
		t.Fatalf("the re-wrapped blob: %+v, %v", parsed, err)
	}
	after, err := rotated.Unwrap(tenantOne, runA, moved)
	if err != nil {
		t.Fatalf("the re-wrapped blob does not open: %v", err)
	}
	// The blob is another; the key is the same one, byte for byte.
	if after.Tenant != one.Tenant || after.Run != one.Run || after.KID != one.KID || after.Wrapped != moved || !bytes.Equal(rawOf(after), rawOf(one)) {
		t.Fatalf("the re-wrapped key is %s, want the key %s under the blob it was moved to", after, one)
	}
	// What was sealed before the move opens after it with either the
	// old-blob key or the re-wrapped key (the sealed section's AAD does
	// not bind the wrapping spelling).
	if _, err := openBoth(t, fmk, kindManifest, snapA, stored, kept); err != nil {
		t.Fatalf("what was sealed before the re-wrap does not open with the key under the old blob: %v", err)
	}
	if _, err := openBoth(t, fmk, kindManifest, snapA, stored, after); err != nil {
		t.Fatalf("what was sealed before the re-wrap does not open with the re-wrapped key: %v", err)
	}
	// The re-wrap pass: the envelope is rewritten with the new blob, its
	// sections as they are (the blob is in neither AAD), and opens under
	// the re-wrapped key as well as the old-blob copy of the same key.
	rewritten := withEnvelope(t, stored, func(e *EnvelopeV2) { e.Key = moved })
	if _, err := openBoth(t, fmk, kindManifest, snapA, rewritten, after); err != nil {
		t.Fatalf("the rewritten envelope does not open under the re-wrapped key: %v", err)
	}
	if _, err := openBoth(t, fmk, kindManifest, snapA, rewritten, kept); err != nil {
		t.Fatalf("the rewritten envelope does not open under the same key's old blob: %v", err)
	}
	if again, err := rotated.Rewrap(tenantOne, runA, moved); err != nil || again != moved {
		t.Fatalf("Rewrap of a current blob = %q, %v", again, err)
	}
	// The daemon still on the old file opens the old blob, and the new
	// one only as a version it has not.
	old, err := NewLocalKeySource(root)
	if err != nil {
		t.Fatal(err)
	}
	if kept, err := old.Unwrap(tenantOne, runA, one.Wrapped); err != nil {
		t.Fatal(err)
	} else {
		assertKey(t, kept, one)
	}
	for _, unknown := range []string{moved, blobOf(tenantOne, 3, one.KID, ciphertextOf(t, one.Wrapped))} {
		if _, err := old.Unwrap(tenantOne, runA, unknown); !errors.Is(err, ErrWrongKey) {
			t.Errorf("a blob of another version: %v, want ErrWrongKey", err)
		}
		if _, err := old.Rewrap(tenantOne, runA, unknown); !errors.Is(err, ErrWrongKey) {
			t.Errorf("Rewrap of a blob of another version: %v, want ErrWrongKey", err)
		}
	}
	// A blob of a version nobody has heard of.
	if _, err := rotated.Unwrap(tenantOne, runA, blobOf(tenantOne, 3, one.KID, ciphertextOf(t, one.Wrapped))); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a blob of version 3: %v, want ErrWrongKey", err)
	}
	// Re-wrapped for another run: not opened, so not re-wrapped.
	if _, err := rotated.Rewrap(tenantOne, runB, one.Wrapped); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Rewrap for another run: %v, want ErrCorrupt", err)
	}
	if _, err := rotated.Rewrap(tenantOne, runA, "garbage"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Rewrap of garbage: %v, want ErrCorrupt", err)
	}

	// In a fleet without Cloud the tenant is a label, and Unwrap still
	// enforces that the blob matches the requested tenant.
	other, err := source.Mint(tenantTwo, runA)
	if err != nil {
		t.Fatal(err)
	}
	fromTwo, err := source.Unwrap(tenantTwo, runA, other.Wrapped)
	if err != nil || fromTwo.Tenant != tenantTwo || bytes.Equal(rawOf(fromTwo), rawOf(one)) {
		t.Fatalf("a key of another tenant: %s, %v", fromTwo, err)
	}
	if _, err := source.Unwrap(tenantOne, runA, other.Wrapped); !errors.Is(err, ErrCorrupt) {
		t.Errorf("other tenant's blob asked for as tenantOne: %v, want ErrCorrupt", err)
	}
	if err := (leaks(root, next, rawOf(one)))(everyVerb(source)); err != nil {
		t.Fatal(err)
	}
}

func TestALocalKeySourceSelectsTheVersionTheBlobNames(t *testing.T) {
	root1, root2 := randomBytes(t, KeySize), randomBytes(t, KeySize)
	source, err := NewLocalKeySourceWithVersion(2, root2)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.AddPrevious(1, root1); err != nil {
		t.Fatal(err)
	}
	raw := randomBytes(t, KeySize)
	kid := hex.EncodeToString(randomBytes(t, kidBytes))
	blob := func(version int) string {
		tk, err := TenantKey(map[int][]byte{1: root1, 2: root2}[version], tenantOne)
		if err != nil {
			t.Fatal(err)
		}
		return okv(WrapHoldKey(tk, raw, tenantOne, runA, kid, version))
	}
	v1, v2 := blob(1), blob(2)
	for _, good := range []string{v1, v2} {
		if key, err := source.Unwrap(tenantOne, runA, good); err != nil || !bytes.Equal(rawOf(key), raw) {
			t.Fatalf("a blob of its own version: %v", err)
		}
	}
	// A blob with its version changed to one the source has is not
	// opened under that one's key: it is corrupt, not merely unknown.
	for name, bad := range map[string]string{
		"a version-1 blob said to be version 2": blobOf(tenantOne, 2, kid, ciphertextOf(t, v1)),
		"a version-2 blob said to be version 1": blobOf(tenantOne, 1, kid, ciphertextOf(t, v2)),
	} {
		if _, err := source.Unwrap(tenantOne, runA, bad); !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrWrongKey) {
			t.Errorf("%s: %v, want ErrCorrupt and not ErrWrongKey", name, err)
		}
	}
	// Said to be a version the source has not, it is that, and the
	// source does not try the two it does have.
	for _, version := range []int{3, 9} {
		if _, err := source.Unwrap(tenantOne, runA, blobOf(tenantOne, version, kid, ciphertextOf(t, v1))); !errors.Is(err, ErrWrongKey) {
			t.Errorf("a blob said to be version %d: %v, want ErrWrongKey", version, err)
		}
	}
}

func TestALocalKeySourceRefusesWhatIsNotARoot(t *testing.T) {
	root1, root2, root3 := randomBytes(t, KeySize), randomBytes(t, KeySize), randomBytes(t, KeySize)
	if _, err := NewLocalKeySource(root1[:31]); err == nil {
		t.Fatal("a source was made on a short root key")
	}
	if _, err := NewLocalKeySourceWithVersion(0, root1); err == nil {
		t.Fatal("a source was made on version 0")
	}
	source, err := NewLocalKeySourceWithVersion(3, root3)
	if err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"the current version again": func() error { return source.AddPrevious(3, root1) }(),
		"a later version":           func() error { return source.AddPrevious(4, root1) }(),
		"version 0":                 func() error { return source.AddPrevious(0, root1) }(),
		"a negative version":        func() error { return source.AddPrevious(-1, root1) }(),
		"a short root key":          func() error { return source.AddPrevious(2, root1[:31]) }(),
		"the current key":           func() error { return source.AddPrevious(2, root3) }(),
	} {
		if err == nil {
			t.Errorf("%s: AddPrevious accepted it", name)
		}
	}
	if err := source.AddPrevious(2, root2); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"a version already known":        func() error { return source.AddPrevious(2, randomBytes(t, KeySize)) }(),
		"a version already known, again": func() error { return source.AddPrevious(2, root2) }(),
		"another version's key":          func() error { return source.AddPrevious(1, root2) }(),
		"the current key, again":         func() error { return source.AddPrevious(1, root3) }(),
	} {
		if err == nil {
			t.Errorf("%s: AddPrevious accepted it", name)
		}
	}
	if err := source.AddPrevious(1, root1); err != nil {
		t.Fatal(err)
	}
	if source.Version() != 3 {
		t.Fatalf("the source is at version %d, want 3", source.Version())
	}
	for version, root := range map[int][]byte{1: root1, 2: root2, 3: root3} {
		key := okv(WrapHoldKey(okv(TenantKey(root, tenantOne)), randomBytes(t, KeySize), tenantOne, runA, hex.EncodeToString(randomBytes(t, kidBytes)), version))
		if _, err := source.Unwrap(tenantOne, runA, key); err != nil {
			t.Fatalf("a blob of version %d: %v", version, err)
		}
	}
	// A zero source is no source.
	var empty LocalKeySource
	if _, err := empty.Mint(tenantOne, runA); err == nil {
		t.Fatal("a zero source minted a key")
	}
	if _, err := empty.Unwrap(tenantOne, runA, blobOf(tenantOne, 1, strings.Repeat("ab", 16), strings.Repeat("A", 80))); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a zero source: %v, want ErrWrongKey", err)
	}
	if err := empty.AddPrevious(1, root1); err == nil {
		t.Fatal("a zero source took a previous root key")
	}
	// What is not a tenant or a run is refused here too.
	for _, tenant := range badTenants() {
		if _, err := source.Mint(tenant, runA); !errors.Is(err, ErrCorrupt) {
			t.Errorf("Mint for the tenant %q: %v, want ErrCorrupt", tenant, err)
		}
	}
	for _, run := range []string{"", "a/b", "a b", strings.Repeat("a", 129)} {
		if _, err := source.Mint(tenantOne, run); !errors.Is(err, ErrCorrupt) {
			t.Errorf("Mint for the run %q: %v, want ErrCorrupt", run, err)
		}
	}
	// Its name says what it is and nothing of a key.
	if s := source.String(); !strings.Contains(s, "version 3") || !strings.Contains(s, "2 previous") {
		t.Errorf("String = %q", s)
	}
	if check := leaks(root1, root2, root3); check(everyVerb(source)) != nil || check(source.GoString()) != nil {
		t.Fatal(check(everyVerb(source)))
	}
}

// okv is a value that must have come without an error.
func okv[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// errOf is the error of a call that is only to fail.
func errOf[T any](_ T, err error) error { return err }

func TestAPushedKeySourceAnswersByKIDOnly(t *testing.T) {
	cloud := newKMS(t)
	one := cloud.hold(t, tenantOne, runA)
	pushed := NewPushedKeySource()
	// Nothing was pushed: the blob is asked for, and named.
	_, err := pushed.Unwrap(tenantOne, runA, one.Wrapped)
	if !errors.Is(err, ErrNeedKey) {
		t.Fatalf("with nothing pushed: %v, want ErrNeedKey", err)
	}
	var need *NeedKeyError
	if !errors.As(err, &need) || len(need.Missing) != 1 {
		t.Fatalf("not a NeedKeyError naming one key: %v", err)
	}
	if want := (KeyNeed{Tenant: tenantOne, Run: runA, KID: one.KID, Wrapped: one.Wrapped}); need.Missing[0] != want {
		t.Errorf("the need is %+v, want %+v", need.Missing[0], want)
	}
	if msg := err.Error(); !strings.Contains(msg, runA) || !strings.Contains(msg, one.KID) || !strings.Contains(msg, tenantOne) || len(msg) > 400 {
		t.Errorf("the error is %q", msg)
	}
	if check := leaks(rawOf(one)); check(need.Error()) != nil {
		t.Fatal("the error shows the key")
	}
	if errors.Is(err, ErrCorrupt) {
		t.Fatal("a missing key is reported as corruption")
	}
	// A host in pushed mode mints nothing and re-wraps nothing.
	for name, err := range map[string]error{
		"Mint":   errOf(pushed.Mint(tenantOne, runA)),
		"Rewrap": errOf(pushed.Rewrap(tenantOne, runA, one.Wrapped)),
	} {
		if err == nil || errors.Is(err, ErrNeedKey) || errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v, want a plain error", name, err)
		}
	}
	if err := pushed.Supply(one); err != nil {
		t.Fatal(err)
	}
	// The key comes back as its own copy.
	got, err := pushed.Unwrap(tenantOne, runA, one.Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	assertKey(t, got, one)

	// Re-wrapped blob of the same held kid/tenant/run still unwraps to the held key.
	rewrapped := okv(WrapHoldKey(cloud.tk(t, tenantOne), rawOf(one), tenantOne, runA, one.KID, 2))
	if gotRewrapped, err := pushed.Unwrap(tenantOne, runA, rewrapped); err != nil {
		t.Errorf("the same kid re-wrapped: %v, want held key", err)
	} else {
		assertKey(t, gotRewrapped, one)
	}

	two := cloud.hold(t, tenantOne, runA)
	otherTenant := cloud.holdAs(t, tenantTwo, runA, one.KID, rawOf(one))
	for name, c := range map[string]struct{ tenant, run, blob string }{
		"another run":              {tenantOne, runB, one.Wrapped},
		"no run":                   {tenantOne, "", one.Wrapped},
		"a run with a slash":       {tenantOne, "run/x", one.Wrapped},
		"another tenant requested": {tenantTwo, runA, one.Wrapped},
		"the same kid and bytes as another tenant's": {tenantTwo, runA, otherTenant.Wrapped},
		"a kid that was not pushed":                  {tenantOne, runA, two.Wrapped},
		"a blob that is not one":                     {tenantOne, runA, "garbage"},
	} {
		_, err := pushed.Unwrap(c.tenant, c.run, c.blob)
		switch {
		case name == "a kid that was not pushed":
			if !errors.Is(err, ErrNeedKey) {
				t.Errorf("%s: %v, want ErrNeedKey", name, err)
			}
		case name == "a blob that is not one":
			if !errors.Is(err, ErrCorrupt) {
				t.Errorf("%s: %v, want ErrCorrupt", name, err)
			}
		default:
			if !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrNeedKey) {
				t.Errorf("%s: %v, want ErrCorrupt and not ErrNeedKey", name, err)
			}
		}
	}
	// The need names the run asked for, and what the blob says.
	_, err = pushed.Unwrap(tenantOne, runB, two.Wrapped)
	if !errors.As(err, &need) || need.Missing[0].Run != runB || need.Missing[0].KID != two.KID || need.Missing[0].Wrapped != two.Wrapped {
		t.Errorf("the need for another run's key: %v", err)
	}
	if s := pushed.String(); !strings.Contains(s, "1 hold key") {
		t.Errorf("String = %q", s)
	}
	if check := leaks(rawOf(one)); check(everyVerb(pushed)) != nil {
		t.Fatal(check(everyVerb(pushed)))
	}
}

func TestSupplyIsAllOrNothing(t *testing.T) {
	cloud := newKMS(t)
	one := cloud.hold(t, tenantOne, runA)
	two := cloud.hold(t, tenantTwo, runB)
	pushed := NewPushedKeySource()
	if err := pushed.Supply(); err != nil {
		t.Fatal(err)
	}
	// One key that is not one refuses the lot.
	changed := two
	changed.Run = runA
	for name, batch := range map[string][]HoldKey{
		"a zero hold key":            {one, {}, two},
		"a key with a changed field": {one, changed},
		"only a zero hold key":       {HoldKey{}},
	} {
		if err := pushed.Supply(batch...); err == nil {
			t.Errorf("%s: Supply accepted the batch", name)
		}
		if _, err := pushed.Unwrap(tenantOne, runA, one.Wrapped); !errors.Is(err, ErrNeedKey) {
			t.Errorf("%s: something of the batch was stored: %v", name, err)
		}
	}
	if err := pushed.Supply(one); err != nil {
		t.Fatal(err)
	}
	// The same kid with other bytes, or for another run, is refused, and
	// the key held is unchanged.
	for name, again := range map[string]HoldKey{
		"other bytes":     cloud.holdAs(t, tenantOne, runA, one.KID, randomBytes(t, KeySize)),
		"another run":     cloud.holdAs(t, tenantOne, runB, one.KID, rawOf(one)),
		"another tenant":  cloud.holdAs(t, tenantTwo, runA, one.KID, rawOf(one)),
		"other bytes too": cloud.holdAs(t, tenantTwo, runB, one.KID, randomBytes(t, KeySize)),
	} {
		if err := pushed.Supply(two, again); err == nil {
			t.Errorf("%s: Supply accepted the key", name)
		}
		if _, err := pushed.Unwrap(tenantTwo, runB, two.Wrapped); !errors.Is(err, ErrNeedKey) {
			t.Errorf("%s: a key of the refused batch was stored: %v", name, err)
		}
		got, err := pushed.Unwrap(tenantOne, runA, one.Wrapped)
		if err != nil {
			t.Fatal(err)
		}
		assertKey(t, got, one)
	}
	// The same kid, the same bytes, the same run: the same key, pushed
	// twice in one batch or again, with its blob moved to another
	// version: accepted, and the new blob is the one held while the old
	// blob still opens with the held key.
	copy, err := one.clone()
	if err != nil {
		t.Fatal(err)
	}
	if err := pushed.Supply(copy, copy); err != nil {
		t.Fatalf("one key pushed twice in one batch: %v", err)
	}
	// A re-wrap keeps the bytes: the key comes from the KMS with its
	// new blob.
	moved := okv(WrapHoldKey(cloud.tk(t, tenantOne), rawOf(one), tenantOne, runA, one.KID, 2))
	again, err := NewHoldKey(tenantOne, runA, one.KID, moved, rawOf(one))
	if err != nil {
		t.Fatal(err)
	}
	if err := pushed.Supply(again); err != nil {
		t.Fatalf("a re-wrapped key pushed again: %v", err)
	}
	if got, err := pushed.Unwrap(tenantOne, runA, again.Wrapped); err != nil {
		t.Fatal(err)
	} else {
		assertKey(t, got, again)
	}
	if gotOld, err := pushed.Unwrap(tenantOne, runA, one.Wrapped); err != nil {
		t.Errorf("the old blob of a re-wrapped key: %v, want held key", err)
	} else {
		assertKey(t, gotOld, again)
	}
	// Supplying a key the source handed out (a copy) is fine.
	if err := pushed.Supply(got0(t, pushed, tenantOne, runA, again.Wrapped)); err != nil {
		t.Fatal(err)
	}
	// The need, and the errors, say no key.
	var need *NeedKeyError
	if _, err := pushed.Unwrap(tenantTwo, runB, two.Wrapped); !errors.As(err, &need) || len(need.Missing) != 1 {
		t.Fatal("unreachable")
	}
	many := &NeedKeyError{Missing: []KeyNeed{{Tenant: tenantOne, Run: runA, KID: one.KID}, {Tenant: tenantTwo, Run: runB, KID: two.KID}}}
	if !strings.HasPrefix(many.Error(), "need the hold keys of run ") || !errors.Is(many, ErrNeedKey) {
		t.Errorf("two needs: %q", many.Error())
	}
}

func got0(t *testing.T, pushed *PushedKeySource, tenant, run, blob string) HoldKey {
	t.Helper()
	key, err := pushed.Unwrap(tenant, run, blob)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestForgetWipesTheKeyWhereItLies(t *testing.T) {
	cloud := newKMS(t)
	one := cloud.hold(t, tenantOne, runA)
	two := cloud.hold(t, tenantTwo, runB)
	pushed := NewPushedKeySource()
	if err := pushed.Supply(one, two); err != nil {
		t.Fatal(err)
	}
	pushed.mu.Lock()
	where := pushed.keys[one.KID].raw
	pushed.mu.Unlock()
	if bytes.Equal(where.key.bytes[:], make([]byte, KeySize)) {
		t.Fatal("the fixture key is zeros")
	}
	handed, err := pushed.Unwrap(tenantOne, runA, one.Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	pushed.Forget(one.KID)
	if !where.key.wiped || !bytes.Equal(where.key.bytes[:], make([]byte, KeySize)) {
		t.Fatal("Forget did not wipe the key's bytes where they lie")
	}
	if _, err := pushed.Unwrap(tenantOne, runA, one.Wrapped); !errors.Is(err, ErrNeedKey) {
		t.Errorf("after Forget: %v, want ErrNeedKey", err)
	}
	// A key handed out before is its holder's: still whole, still its own.
	assertKey(t, handed, one)
	if got, err := pushed.Unwrap(tenantTwo, runB, two.Wrapped); err != nil {
		t.Fatal(err)
	} else {
		assertKey(t, got, two)
	}
	pushed.Forget(one.KID) // again
	pushed.Forget("not-a-kid")
	if s := pushed.String(); !strings.Contains(s, "1 hold key") {
		t.Errorf("String = %q", s)
	}
	// A zero source holds nothing, and says so.
	var empty PushedKeySource
	if _, err := empty.Unwrap(tenantOne, runA, one.Wrapped); !errors.Is(err, ErrNeedKey) {
		t.Errorf("a zero source: %v, want ErrNeedKey", err)
	}
	empty.Forget(one.KID)
}

func TestKeySourcesAreSafeForConcurrentUse(t *testing.T) {
	cloud := newKMS(t)
	pushed := NewPushedKeySource()
	root1, root2 := randomBytes(t, KeySize), randomBytes(t, KeySize)
	local, err := NewLocalKeySourceWithVersion(2, root2)
	if err != nil {
		t.Fatal(err)
	}
	const held = 12
	keys := make([]HoldKey, held)
	for i := range keys {
		keys[i] = cloud.hold(t, tenantOne, runA)
	}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				key := keys[(worker+i)%held]
				switch i % 6 {
				case 0:
					_ = pushed.Supply(key)
				case 1:
					_, err := pushed.Unwrap(tenantOne, runA, key.Wrapped)
					if err != nil && !errors.Is(err, ErrNeedKey) && !errors.Is(err, ErrCorrupt) {
						t.Errorf("Unwrap: %v", err)
					}
				case 2:
					pushed.Forget(key.KID)
				case 3:
					_, _ = pushed.Unwrap(tenantOne, runB, key.Wrapped)
				case 4:
					if minted, err := local.Mint(tenantOne, runA); err == nil {
						if _, err := local.Unwrap(tenantOne, runA, minted.Wrapped); err != nil {
							t.Errorf("Unwrap of a minted key: %v", err)
						}
					}
				case 5:
					_ = local.Version()
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = local.AddPrevious(1, root1)
	}()
	wg.Wait()
	// Every key is either held, and opens, or not held, and is asked for.
	for _, key := range keys {
		got, err := pushed.Unwrap(tenantOne, runA, key.Wrapped)
		switch {
		case err == nil:
			assertKey(t, got, key)
		case errors.Is(err, ErrNeedKey):
		default:
			t.Errorf("after the run: %v", err)
		}
	}
}
