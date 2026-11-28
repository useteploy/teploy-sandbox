package offhosttest

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/s3"
)

var bg = context.Background()

// Key custody K0. Every object has an ETag of its bytes, the same from a
// read, a HEAD and a listing, and another for other bytes: what a write
// conditional on one needs to tell two versions apart.
func TestEveryObjectHasAnETagOfItsBytes(t *testing.T) {
	bucket := NewMemory()
	if err := bucket.Put(bg, "k", []byte("v"), s3.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	body, etag, err := bucket.GetWithETag(bg, "k", 16)
	if err != nil || string(body) != "v" || !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) || len(etag) < 4 {
		t.Fatalf("GetWithETag = %q, ETag %q, %v; want the bytes and a quoted ETag", body, etag, err)
	}
	if got, _ := bucket.Get(bg, "k", 16); string(got) != "v" {
		t.Fatalf("Get = %q", got)
	}
	if info, err := bucket.Head(bg, "k"); err != nil || info.ETag != etag {
		t.Fatalf("Head = %+v, %v; want ETag %q", info, err, etag)
	}
	if listed, err := bucket.ListAll(bg, ""); err != nil || len(listed) != 1 || listed[0].ETag != etag {
		t.Fatalf("ListAll = %+v, %v; want ETag %q", listed, err, etag)
	}
	if _, again, _ := bucket.GetWithETag(bg, "k", 16); again != etag {
		t.Fatalf("the ETag of the same bytes is %q, then %q", etag, again)
	}
	// Tampering is other bytes.
	bucket.SetRaw("k", []byte("tampered"))
	if _, now, _ := bucket.GetWithETag(bg, "k", 16); now == etag {
		t.Fatal("rewritten bytes kept the ETag of the old ones")
	}
	// Nothing there: no ETag, and not found.
	if _, etag, err := bucket.GetWithETag(bg, "missing", 16); !errors.Is(err, s3.ErrNotFound) || etag != "" {
		t.Fatalf("GetWithETag of a missing object = ETag %q, %v", etag, err)
	}
}

func TestAPutConditionalOnAnETag(t *testing.T) {
	bucket := NewMemory()
	// No object: no match.
	if err := bucket.Put(bg, "k", []byte("v"), s3.PutOptions{IfMatch: `"none"`}); !errors.Is(err, s3.ErrPreconditionFailed) {
		t.Fatalf("a write conditional on an ETag of a missing object = %v, want ErrPreconditionFailed", err)
	}
	if err := bucket.Put(bg, "k", []byte("v"), s3.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	_, etag, _ := bucket.GetWithETag(bg, "k", 16)
	if err := bucket.Put(bg, "k", []byte("other"), s3.PutOptions{IfMatch: `"none"`}); !errors.Is(err, s3.ErrPreconditionFailed) {
		t.Fatalf("a write naming another ETag = %v, want ErrPreconditionFailed", err)
	}
	if got, _ := bucket.Get(bg, "k", 16); string(got) != "v" {
		t.Fatalf("the refused write landed: %q", got)
	}
	if err := bucket.Put(bg, "k", []byte("next"), s3.PutOptions{IfMatch: etag}); err != nil {
		t.Fatalf("a write naming the object's ETag: %v", err)
	}
	// Both conditions at once is no write at all: refused before any
	// condition is judged, as the client refuses it before sending. On an
	// object that is not there, judging them is all that would stop it.
	if err := bucket.Put(bg, "elsewhere", []byte("both"), s3.PutOptions{IfAbsent: true, IfMatch: etag}); err == nil || errors.Is(err, s3.ErrPreconditionFailed) {
		t.Fatalf("a write conditional on the object being absent and on its ETag = %v; want it refused as no write, not as a failed condition", err)
	}
	if bucket.Raw("elsewhere") != nil {
		t.Fatal("the write landed")
	}
	if got, _ := bucket.Get(bg, "k", 16); string(got) != "next" {
		t.Fatalf("the refused write landed: %q", got)
	}
	// A service without the condition writes over whatever is there.
	bucket.NoIfMatchPut = true
	if err := bucket.Put(bg, "k", []byte("any"), s3.PutOptions{IfMatch: `"none"`}); err != nil {
		t.Fatalf("a service that ignores If-Match refused the write: %v", err)
	}
	if got, _ := bucket.Get(bg, "k", 16); string(got) != "any" {
		t.Fatalf("the write that ignores If-Match did not land: %q", got)
	}
}

func TestADeleteConditionalOnAnETag(t *testing.T) {
	bucket := NewMemory()
	if err := bucket.Put(bg, "k", []byte("v"), s3.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	_, etag, _ := bucket.GetWithETag(bg, "k", 16)
	// No ETag is no condition: the delete would be unconditional. It is
	// refused before anything else, where nothing else would stop it: on
	// a service that ignores If-Match, judging the condition cannot.
	bucket.NoIfMatchDelete = true
	if err := bucket.DeleteIfMatch(bg, "k", ""); err == nil {
		t.Fatal("a delete conditional on no ETag was accepted")
	}
	if got, _ := bucket.Get(bg, "k", 16); string(got) != "v" {
		t.Fatalf("a delete conditional on no ETag removed the object: %q", got)
	}
	bucket.NoIfMatchDelete = false
	if err := bucket.DeleteIfMatch(bg, "missing", `"none"`); !errors.Is(err, s3.ErrNotFound) {
		t.Fatalf("a conditional delete of a missing object = %v, want ErrNotFound", err)
	}
	if err := bucket.DeleteIfMatch(bg, "k", `"none"`); !errors.Is(err, s3.ErrPreconditionFailed) {
		t.Fatalf("a delete naming another ETag = %v, want ErrPreconditionFailed", err)
	}
	if got, _ := bucket.Get(bg, "k", 16); string(got) != "v" {
		t.Fatalf("the refused delete removed the object: %q", got)
	}
	// The bucket's own failure is the caller's, and removes nothing.
	bucket.SetFail(func(op, _ string) error {
		if op == "delete" {
			return errors.New("the service is down")
		}
		return nil
	})
	if err := bucket.DeleteIfMatch(bg, "k", etag); err == nil || err.Error() != "the service is down" {
		t.Fatalf("a delete the service failed = %v", err)
	}
	if got, _ := bucket.Get(bg, "k", 16); string(got) != "v" {
		t.Fatal("a delete the service failed removed the object")
	}
	bucket.SetFail(nil)
	if err := bucket.DeleteIfMatch(bg, "k", etag); err != nil {
		t.Fatalf("a delete naming the object's ETag: %v", err)
	}
	if _, _, err := bucket.GetWithETag(bg, "k", 16); !errors.Is(err, s3.ErrNotFound) {
		t.Fatalf("after the delete: %v, want ErrNotFound", err)
	}
	// A service without the condition deletes whatever is named, and
	// succeeds on what is not there, like an unconditional delete.
	bucket.NoIfMatchDelete = true
	if err := bucket.Put(bg, "k", []byte("v"), s3.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := bucket.DeleteIfMatch(bg, "k", `"none"`); err != nil {
		t.Fatalf("a service that ignores If-Match refused the delete: %v", err)
	}
	if err := bucket.DeleteIfMatch(bg, "k", `"none"`); err != nil {
		t.Fatalf("a service that ignores If-Match did not succeed on a missing object: %v", err)
	}
}

// The read and delete hooks of a Faulty bucket cover the conditional
// calls too: a race is ordered by hand at a conditional request as at any
// other.
func TestFaultyHooksCoverTheConditionalCalls(t *testing.T) {
	memory := NewMemory()
	bucket := NewFaulty(memory)
	if err := bucket.Put(bg, "k", []byte("v"), s3.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	var order []string
	hooked := func(f *Faulty) {
		f.GetErr = func(key string) error { order = append(order, "getErr "+key); return nil }
		f.AfterGet = func(key string) { order = append(order, "afterGet "+key) }
		f.BeforeDelete = func(key string) { order = append(order, "beforeDelete "+key) }
		f.AfterDelete = func(key string) { order = append(order, "afterDelete "+key) }
	}
	bucket.Set(hooked)
	_, etag, err := bucket.GetWithETag(bg, "k", 16)
	if err != nil || etag == "" {
		t.Fatalf("GetWithETag through the hooks = ETag %q, %v", etag, err)
	}
	// A read the hook fails answers its error, as Get does (that hook
	// records nothing).
	bucket.Set(func(f *Faulty) {
		hooked(f)
		f.GetErr = func(string) error { return &s3.Error{Status: 404, Code: "NoSuchKey"} }
	})
	if _, _, err := bucket.GetWithETag(bg, "k", 16); !errors.Is(err, s3.ErrNotFound) {
		t.Fatalf("a read failed by the hook = %v, want ErrNotFound", err)
	}
	bucket.Set(hooked)
	// A delete that is refused reached the bucket, so BeforeDelete ran;
	// AfterDelete is for one that deleted.
	if err := bucket.DeleteIfMatch(bg, "k", `"none"`); !errors.Is(err, s3.ErrPreconditionFailed) {
		t.Fatalf("a delete naming another ETag = %v, want ErrPreconditionFailed", err)
	}
	if err := bucket.DeleteIfMatch(bg, "k", etag); err != nil {
		t.Fatal(err)
	}
	want := []string{"getErr k", "afterGet k", "beforeDelete k", "beforeDelete k", "afterDelete k"}
	if !slices.Equal(order, want) {
		t.Fatalf("the hooks ran %v, want %v", order, want)
	}
	if left := memory.Keys(""); len(left) != 0 {
		t.Fatalf("the object is still there: %v", left)
	}
}
