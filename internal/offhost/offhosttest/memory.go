// Package offhosttest has an in-memory object store for tests of
// everything built on internal/offhost.
package offhosttest

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// Memory is a bucket in memory, with the semantics the daemon relies on:
// a conditional write that exactly one of many writers wins, listings in
// key order that show every write, and modification times.
type Memory struct {
	mu      sync.Mutex
	objects map[string]memoryObject
	// Unconditional makes the bucket ignore `If-None-Match`, like a
	// service that does not know it: every write succeeds.
	Unconditional bool
	// Now is the bucket's clock.
	Now func() time.Time
	// Fail, when set, is asked before every call (op is "put", "get",
	// "head", "delete" or "list") and its error returned instead.
	Fail func(op, key string) error
	// Puts counts the bytes written, per key prefix a test cares about.
	PutBytes int64
}

type memoryObject struct {
	data     []byte
	modified time.Time
}

// NewMemory is an empty bucket.
func NewMemory() *Memory {
	return &Memory{objects: map[string]memoryObject{}, Now: time.Now}
}

func (m *Memory) fail(op, key string) error {
	m.mu.Lock()
	fail := m.Fail
	m.mu.Unlock()
	if fail == nil {
		return nil
	}
	return fail(op, key)
}

// SetFail replaces Fail under the bucket's lock.
func (m *Memory) SetFail(fail func(op, key string) error) {
	m.mu.Lock()
	m.Fail = fail
	m.mu.Unlock()
}

func (m *Memory) Put(_ context.Context, key string, body []byte, opts s3.PutOptions) error {
	if err := m.fail("put", key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.objects[key]; exists && opts.IfAbsent && !m.Unconditional {
		return &s3.Error{Status: 412, Code: "PreconditionFailed"}
	}
	m.objects[key] = memoryObject{data: bytes.Clone(body), modified: m.Now()}
	m.PutBytes += int64(len(body))
	return nil
}

func (m *Memory) Get(_ context.Context, key string, limit int64) ([]byte, error) {
	if err := m.fail("get", key); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	object, ok := m.objects[key]
	if !ok {
		return nil, &s3.Error{Status: 404, Code: "NoSuchKey"}
	}
	if int64(len(object.data)) > limit {
		return nil, &s3.Error{Status: 200, Code: "ResponseTooLarge"}
	}
	return bytes.Clone(object.data), nil
}

func (m *Memory) Head(_ context.Context, key string) (s3.Object, error) {
	if err := m.fail("head", key); err != nil {
		return s3.Object{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	object, ok := m.objects[key]
	if !ok {
		return s3.Object{}, &s3.Error{Status: 404, Code: "NoSuchKey"}
	}
	return s3.Object{Key: key, Size: int64(len(object.data)), LastModified: object.modified}, nil
}

func (m *Memory) Delete(_ context.Context, key string) error {
	if err := m.fail("delete", key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	return nil
}

// ListAll lists every object under prefix, in key order.
func (m *Memory) ListAll(_ context.Context, prefix string) ([]s3.Object, error) {
	if err := m.fail("list", prefix); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var listed []s3.Object
	for key, object := range m.objects {
		if strings.HasPrefix(key, prefix) {
			listed = append(listed, s3.Object{Key: key, Size: int64(len(object.data)), LastModified: object.modified})
		}
	}
	sort.Slice(listed, func(i, j int) bool { return listed[i].Key < listed[j].Key })
	return listed, nil
}

// Walk hands every object under prefix to each, in key order: the
// listing as it was when the walk began.
func (m *Memory) Walk(ctx context.Context, prefix string, each func(s3.Object) error) error {
	listed, err := m.ListAll(ctx, prefix)
	if err != nil {
		return err
	}
	for _, object := range listed {
		if err := each(object); err != nil {
			return err
		}
	}
	return nil
}

// Keys lists the keys under prefix, sorted.
func (m *Memory) Keys(prefix string) []string {
	listed, _ := m.ListAll(context.Background(), prefix)
	keys := make([]string, len(listed))
	for i, object := range listed {
		keys[i] = object.Key
	}
	return keys
}

// Raw returns an object's stored bytes, nil when there is none.
func (m *Memory) Raw(key string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	object, ok := m.objects[key]
	if !ok {
		return nil
	}
	return bytes.Clone(object.data)
}

// SetRaw replaces an object's bytes without touching its time: tampering.
func (m *Memory) SetRaw(key string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	object := m.objects[key]
	object.data = bytes.Clone(data)
	m.objects[key] = object
}

// Remove deletes an object behind the store's back.
func (m *Memory) Remove(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
}

// Size is the total bytes stored under prefix.
func (m *Memory) Size(prefix string) int64 {
	listed, _ := m.ListAll(context.Background(), prefix)
	var total int64
	for _, object := range listed {
		total += object.Size
	}
	return total
}

// Faulty is a bucket that misbehaves on request: a test sets the hook it
// needs and the rest pass through to the Memory underneath. It is how
// the answers a real service can give wrongly, late or not at all are
// provoked at one exact call.
type Faulty struct {
	*Memory
	mu sync.Mutex
	// BeforePut runs before a write reaches the bucket.
	BeforePut func(key string)
	// AfterPut runs after a write has landed; its error is the answer
	// the caller gets (a write whose answer was lost).
	AfterPut func(key string) error
	// GetErr, when it returns an error, is the answer to a read (a 404
	// for an object that is there).
	GetErr func(key string) error
	// AfterGet runs after a read that succeeded.
	AfterGet func(key string)
	// Listed rewrites a listing before the caller sees it: stale, cut
	// short, without times, or ignoring the prefix.
	Listed func(prefix string, listed []s3.Object) []s3.Object
	// BeforeDelete and AfterDelete run around a delete reaching the
	// bucket: a race ordered by hand at one exact request.
	BeforeDelete func(key string)
	AfterDelete  func(key string)
	// Headed rewrites the answer to a HEAD (a service that reports a
	// size other than what was written).
	Headed func(object s3.Object) s3.Object
}

func (f *Faulty) Head(ctx context.Context, key string) (s3.Object, error) {
	object, err := f.Memory.Head(ctx, key)
	f.mu.Lock()
	rewrite := f.Headed
	f.mu.Unlock()
	if err == nil && rewrite != nil {
		object = rewrite(object)
	}
	return object, err
}

func (f *Faulty) Delete(ctx context.Context, key string) error {
	f.mu.Lock()
	before, after := f.BeforeDelete, f.AfterDelete
	f.mu.Unlock()
	if before != nil {
		before(key)
	}
	if err := f.Memory.Delete(ctx, key); err != nil {
		return err
	}
	if after != nil {
		after(key)
	}
	return nil
}

// Frozen is the bucket as it is now, for a listing that is behind:
// Listing answers every later listing from this moment's contents (a
// replica that has not caught up), whatever was written or deleted
// since.
type Frozen struct{ objects []s3.Object }

// Freeze takes the bucket as it is now.
func (m *Memory) Freeze() *Frozen {
	listed, _ := m.ListAll(context.Background(), "")
	return &Frozen{objects: listed}
}

// Listing is the frozen bucket's listing of prefix, for Faulty.Listed.
func (f *Frozen) Listing(prefix string, _ []s3.Object) []s3.Object {
	var out []s3.Object
	for _, object := range f.objects {
		if strings.HasPrefix(object.Key, prefix) {
			out = append(out, object)
		}
	}
	return out
}

// NewFaulty wraps a bucket.
func NewFaulty(memory *Memory) *Faulty { return &Faulty{Memory: memory} }

// Set changes hooks under the wrapper's lock.
func (f *Faulty) Set(change func(*Faulty)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *Faulty) Put(ctx context.Context, key string, body []byte, opts s3.PutOptions) error {
	f.mu.Lock()
	before, after := f.BeforePut, f.AfterPut
	f.mu.Unlock()
	if before != nil {
		before(key)
	}
	if err := f.Memory.Put(ctx, key, body, opts); err != nil {
		return err
	}
	if after != nil {
		return after(key)
	}
	return nil
}

func (f *Faulty) Get(ctx context.Context, key string, limit int64) ([]byte, error) {
	f.mu.Lock()
	getErr, after := f.GetErr, f.AfterGet
	f.mu.Unlock()
	if getErr != nil {
		if err := getErr(key); err != nil {
			return nil, err
		}
	}
	data, err := f.Memory.Get(ctx, key, limit)
	if err == nil && after != nil {
		after(key)
	}
	return data, err
}

func (f *Faulty) Walk(ctx context.Context, prefix string, each func(s3.Object) error) error {
	listed, err := f.Memory.ListAll(ctx, prefix)
	if err != nil {
		return err
	}
	f.mu.Lock()
	rewrite := f.Listed
	f.mu.Unlock()
	if rewrite != nil {
		listed = rewrite(prefix, listed)
	}
	for _, object := range listed {
		if err := each(object); err != nil {
			return err
		}
	}
	return nil
}
