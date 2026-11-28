//go:build s3integration

package s3

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// The live suite runs the client against a real S3-compatible service:
//
//	SBX_S3_TEST_ENDPOINT=http://127.0.0.1:7070 SBX_S3_TEST_BUCKET=sbx-test \
//	SBX_S3_TEST_ACCESS_KEY=... SBX_S3_TEST_SECRET_KEY=... \
//	go test -tags s3integration ./internal/s3
//
// SBX_S3_TEST_VIRTUAL_HOST=1 addresses the bucket as a host label.
func liveClient(t *testing.T) *Client {
	t.Helper()
	endpoint := os.Getenv("SBX_S3_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("SBX_S3_TEST_ENDPOINT is not set")
	}
	client, err := New(Config{
		Endpoint: endpoint,
		// The suite's service is wherever the operator put it.
		AllowInsecure: true,
		Region:        os.Getenv("SBX_S3_TEST_REGION"),
		Bucket:        os.Getenv("SBX_S3_TEST_BUCKET"),
		PathStyle:     os.Getenv("SBX_S3_TEST_VIRTUAL_HOST") == "",
		Credentials:   Credentials{AccessKey: os.Getenv("SBX_S3_TEST_ACCESS_KEY"), SecretKey: os.Getenv("SBX_S3_TEST_SECRET_KEY")},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.CreateBucket(ctx); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	return client
}

func TestLiveObjects(t *testing.T) {
	client := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	prefix := fmt.Sprintf("live-%d/", time.Now().UnixNano())
	key := prefix + "a key+with (odd) chars~.bin"
	body := make([]byte, 300<<10)
	_, _ = rand.Read(body)

	if _, err := client.Head(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Head of a missing object = %v, want ErrNotFound", err)
	}
	if err := client.Put(ctx, key, body, PutOptions{ContentType: "application/octet-stream"}); err != nil {
		t.Fatal(err)
	}
	got, err := client.Get(ctx, key, int64(len(body)))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("Get: %d bytes, %v", len(got), err)
	}
	info, err := client.Head(ctx, key)
	if err != nil || info.Size != int64(len(body)) {
		t.Fatalf("Head = %+v, %v", info, err)
	}
	for i := 0; i < 5; i++ {
		if err := client.Put(ctx, fmt.Sprintf("%slist/%d", prefix, i), []byte{byte(i)}, PutOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	listed, err := client.ListAll(ctx, prefix+"list/")
	if err != nil || len(listed) != 5 || listed[4].Key != prefix+"list/4" || listed[0].LastModified.IsZero() {
		t.Fatalf("ListAll = %+v, %v", listed, err)
	}
	page, err := client.List(ctx, prefix, "/", "")
	if err != nil || len(page.Prefixes) != 1 || page.Prefixes[0] != prefix+"list/" || len(page.Objects) != 1 {
		t.Fatalf("List with a delimiter = %+v, %v", page, err)
	}
	all, err := client.ListAll(ctx, prefix)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range all {
		if err := client.Delete(ctx, object.Key); err != nil {
			t.Fatal(err)
		}
	}
	if left, err := client.ListAll(ctx, prefix); err != nil || len(left) != 0 {
		t.Fatalf("after deleting everything: %+v, %v", left, err)
	}
	if err := client.Delete(ctx, key); err != nil {
		t.Fatalf("deleting a missing object: %v", err)
	}
}

func TestLiveConditionalPut(t *testing.T) {
	client := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	key := fmt.Sprintf("live-%d/lease", time.Now().UnixNano())
	defer client.Delete(context.Background(), key)

	const writers = 16
	var wg sync.WaitGroup
	results := make([]error, writers)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = client.Put(ctx, key, []byte(fmt.Sprintf("writer-%d", i)), PutOptions{IfAbsent: true})
		}()
	}
	wg.Wait()
	won, lost := 0, 0
	winner := ""
	for i, err := range results {
		switch {
		case err == nil:
			won++
			winner = fmt.Sprintf("writer-%d", i)
		case errors.Is(err, ErrPreconditionFailed):
			lost++
		default:
			t.Errorf("writer %d: %v", i, err)
		}
	}
	t.Logf("conditional put: %d won, %d refused", won, lost)
	if won != 1 || lost != writers-1 {
		t.Fatalf("this service does not honour If-None-Match: %d writers won", won)
	}
	if got, err := client.Get(ctx, key, 64); err != nil || string(got) != winner {
		t.Fatalf("the object is %q (%v), want the winner's %q", got, err, winner)
	}
}

// W2 (key custody K0): `If-Match` on PUT, which re-keying a snapshot
// needs. A write conditional on the ETag of the bytes read lands only
// while those are still the object; one that lost a race to another
// write is refused and changes nothing.
func TestLiveConditionalPutIfMatch(t *testing.T) {
	client := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	key := fmt.Sprintf("live-%d/cas", time.Now().UnixNano())
	defer client.Delete(context.Background(), key)

	if err := client.Put(ctx, key, []byte("v1"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	_, etag, err := client.GetWithETag(ctx, key, 64)
	if err != nil || etag == "" {
		t.Fatalf("GetWithETag = ETag %q, %v: a service that answers no ETag has no write conditional on one", etag, err)
	}
	// The probe and the store make their conditions of what a GET
	// answers; a HEAD that answers another is worth knowing.
	if info, err := client.Head(ctx, key); err != nil || info.ETag != etag {
		t.Logf("HEAD answers ETag %q (%v) where GET answers %q", info.ETag, err, etag)
	}
	// Another ETag: refused, and the object is as it was.
	if err := client.Put(ctx, key, []byte("lost"), PutOptions{IfMatch: `"no-such-etag"`}); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("a write with If-Match naming another ETag = %v, want ErrPreconditionFailed: this service does not honour If-Match on PUT", err)
	}
	if got, err := client.Get(ctx, key, 64); err != nil || string(got) != "v1" {
		t.Fatalf("after the refused write the object is %q (%v): the service answered 412 and wrote anyway", got, err)
	}
	// The ETag read with the bytes: the write lands, and moves it on.
	if err := client.Put(ctx, key, []byte("v2"), PutOptions{IfMatch: etag}); err != nil {
		t.Fatalf("a write with If-Match naming the object's ETag = %v", err)
	}
	got, next, err := client.GetWithETag(ctx, key, 64)
	if err != nil || string(got) != "v2" || next == "" || next == etag {
		t.Fatalf("after the write: %q, ETag %q (was %q), %v: an ETag that does not move with the bytes tells no version from another", got, next, etag, err)
	}
	// An object that is not there matches nothing: refused, 404 on some
	// services and 412 on others, and not created.
	if err := client.Put(ctx, key+"-missing", []byte("x"), PutOptions{IfMatch: next}); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("a write with If-Match on a missing object = %v, want ErrNotFound or ErrPreconditionFailed", err)
	}
	if _, err := client.Head(ctx, key+"-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a write with If-Match on a missing object created it: %v", err)
	}

	// The race compare-and-swap is for: every writer read the same ETag,
	// and exactly one lands.
	const writers = 16
	var wg sync.WaitGroup
	results := make([]error, writers)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = client.Put(ctx, key, []byte(fmt.Sprintf("writer-%d", i)), PutOptions{IfMatch: next})
		}()
	}
	wg.Wait()
	won, lost := 0, 0
	winner := ""
	for i, err := range results {
		switch {
		case err == nil:
			won++
			winner = fmt.Sprintf("writer-%d", i)
		case errors.Is(err, ErrPreconditionFailed):
			lost++
		default:
			t.Errorf("writer %d: %v", i, err)
		}
	}
	t.Logf("conditional put with If-Match: %d won, %d refused", won, lost)
	if won != 1 || lost != writers-1 {
		t.Fatalf("%d of %d writers landed on one ETag, %d refused; want exactly 1: this service does not honour If-Match on PUT", won, writers, lost)
	}
	if got, err := client.Get(ctx, key, 64); err != nil || string(got) != winner {
		t.Fatalf("the object is %q (%v), want the winner's %q", got, err, winner)
	}
}

// W2 (key custody K0): `If-Match` on DELETE, which the collector's
// conditional delete needs. A delete naming the ETag of the bytes that
// were copied removes the object only while those are still it.
func TestLiveConditionalDeleteIfMatch(t *testing.T) {
	client := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	key := fmt.Sprintf("live-%d/conditional-delete", time.Now().UnixNano())

	if err := client.Put(ctx, key, []byte("v"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	_, etag, err := client.GetWithETag(ctx, key, 64)
	if err != nil || etag == "" {
		t.Fatalf("GetWithETag = ETag %q, %v", etag, err)
	}
	// Another ETag: refused, and the object is as it was.
	if err := client.DeleteIfMatch(ctx, key, `"no-such-etag"`); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("a delete with If-Match naming another ETag = %v, want ErrPreconditionFailed: this service does not honour If-Match on DELETE", err)
	}
	if got, err := client.Get(ctx, key, 64); err != nil || string(got) != "v" {
		t.Fatalf("after the refused delete the object is %q (%v): the service answered 412 and deleted anyway", got, err)
	}
	// The object's ETag: gone.
	if err := client.DeleteIfMatch(ctx, key, etag); err != nil {
		t.Fatalf("a delete with If-Match naming the object's ETag = %v", err)
	}
	if _, err := client.Get(ctx, key, 64); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after the delete: %v, want ErrNotFound: the service answered success and removed nothing", err)
	}
	// What is gone is reported, where an unconditional delete succeeds.
	if err := client.DeleteIfMatch(ctx, key, etag); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a conditional delete of a missing object = %v, want ErrNotFound", err)
	}
}
