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
