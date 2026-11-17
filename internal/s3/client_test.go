package s3

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeService is a small in-memory S3: enough of the protocol to exercise
// the client, with every request's signature checked the way a real
// service checks it (recomputed from the request as received).
type fakeService struct {
	t           *testing.T
	credentials Credentials
	bucket      string
	virtualHost bool

	mu       sync.Mutex
	objects  map[string][]byte
	uploads  map[string]map[int][]byte
	nextID   int
	requests []string
	// fail answers the next requests with these statuses, one each.
	fail []int
	// pageSize is the listing page size.
	pageSize int
}

func newFakeService(t *testing.T) (*fakeService, *httptest.Server) {
	service := &fakeService{
		t:           t,
		credentials: Credentials{AccessKey: "AKIDEXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
		bucket:      "bucket",
		objects:     map[string][]byte{},
		uploads:     map[string]map[int][]byte{},
		pageSize:    1000,
	}
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	return service, server
}

func (f *fakeService) client(t *testing.T, endpoint string) *Client {
	t.Helper()
	client, err := New(Config{Endpoint: endpoint, Bucket: f.bucket, PathStyle: !f.virtualHost, Credentials: f.credentials})
	if err != nil {
		t.Fatal(err)
	}
	client.sleep = func(context.Context, time.Duration) error { return nil }
	return client
}

func fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", code, code)
}

func (f *fakeService) verify(r *http.Request, body []byte) error {
	header := r.Header.Get("Authorization")
	_, list, ok := strings.Cut(header, "SignedHeaders=")
	if !ok {
		return errors.New("no SignedHeaders")
	}
	list, _, _ = strings.Cut(list, ",")
	headers := map[string]string{}
	for _, name := range strings.Split(list, ";") {
		if name == "host" {
			headers[name] = r.Host
		} else {
			headers[name] = r.Header.Get(name)
		}
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != r.Header.Get("x-amz-content-sha256") {
		return errors.New("payload hash does not match the body")
	}
	at, err := time.Parse(timeFormat, r.Header.Get("x-amz-date"))
	if err != nil {
		return err
	}
	// EscapedPath is what was on the wire; the signature covers its
	// decoded form encoded once.
	want := f.credentials.authorization(signRequest{method: r.Method, path: r.URL.Path, query: r.URL.Query(), headers: headers,
		payloadHash: r.Header.Get("x-amz-content-sha256")}, at, "us-east-1", "s3")
	if want != header {
		return fmt.Errorf("signature mismatch:\n got %s\nwant %s", header, want)
	}
	return nil
}

func (f *fakeService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	if len(f.fail) > 0 {
		status := f.fail[0]
		f.fail = f.fail[1:]
		code := "InternalError"
		if status == http.StatusForbidden {
			code = "AccessDenied"
		}
		fail(w, status, code)
		return
	}
	if err := f.verify(r, body); err != nil {
		f.t.Errorf("%s %s: %v", r.Method, r.URL, err)
		fail(w, http.StatusForbidden, "SignatureDoesNotMatch")
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/")
	if f.virtualHost {
		if !strings.HasPrefix(r.Host, f.bucket+".") {
			fail(w, http.StatusNotFound, "NoSuchBucket")
			return
		}
	} else {
		bucket, rest, _ := strings.Cut(key, "/")
		if bucket != f.bucket {
			fail(w, http.StatusNotFound, "NoSuchBucket")
			return
		}
		key = rest
	}
	query := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && key == "":
		f.list(w, query.Get("prefix"), query.Get("continuation-token"))
	case r.Method == http.MethodPost && query.Has("uploads"):
		f.nextID++
		id := "upload-" + strconv.Itoa(f.nextID)
		f.uploads[id] = map[int][]byte{}
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>", id)
	case r.Method == http.MethodPut && query.Has("uploadId"):
		parts, ok := f.uploads[query.Get("uploadId")]
		if !ok {
			fail(w, http.StatusNotFound, "NoSuchUpload")
			return
		}
		number, _ := strconv.Atoi(query.Get("partNumber"))
		parts[number] = body
		w.Header().Set("ETag", fmt.Sprintf("\"part-%d\"", number))
	case r.Method == http.MethodPost && query.Has("uploadId"):
		parts, ok := f.uploads[query.Get("uploadId")]
		if !ok {
			fail(w, http.StatusNotFound, "NoSuchUpload")
			return
		}
		var document struct {
			Parts []struct {
				PartNumber int
				ETag       string
			} `xml:"Part"`
		}
		if err := xml.Unmarshal(body, &document); err != nil {
			fail(w, http.StatusBadRequest, "MalformedXML")
			return
		}
		var object []byte
		for _, part := range document.Parts {
			if part.ETag != fmt.Sprintf("\"part-%d\"", part.PartNumber) {
				fail(w, http.StatusBadRequest, "InvalidPart")
				return
			}
			object = append(object, parts[part.PartNumber]...)
		}
		delete(f.uploads, query.Get("uploadId"))
		f.objects[key] = object
		fmt.Fprint(w, "<CompleteMultipartUploadResult></CompleteMultipartUploadResult>")
	case r.Method == http.MethodDelete && query.Has("uploadId"):
		delete(f.uploads, query.Get("uploadId"))
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPut:
		if _, exists := f.objects[key]; exists && r.Header.Get("If-None-Match") == "*" {
			fail(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		f.objects[key] = body
	case r.Method == http.MethodGet, r.Method == http.MethodHead:
		object, ok := f.objects[key]
		if !ok {
			fail(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(object)))
		w.Header().Set("Last-Modified", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Format(http.TimeFormat))
		if r.Method == http.MethodGet {
			_, _ = w.Write(object)
		}
	case r.Method == http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		fail(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

func (f *fakeService) list(w http.ResponseWriter, prefix, token string) {
	var keys []string
	for key := range f.objects {
		if strings.HasPrefix(key, prefix) && key > token {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	truncated := len(keys) > f.pageSize
	if truncated {
		keys = keys[:f.pageSize]
	}
	fmt.Fprintf(w, "<ListBucketResult><IsTruncated>%t</IsTruncated>", truncated)
	if truncated {
		fmt.Fprintf(w, "<NextContinuationToken>%s</NextContinuationToken>", keys[len(keys)-1])
	}
	for _, key := range keys {
		fmt.Fprintf(w, "<Contents><Key>%s</Key><Size>%d</Size><LastModified>2026-01-02T03:04:05.000Z</LastModified><ETag>\"e\"</ETag></Contents>", key, len(f.objects[key]))
	}
	fmt.Fprint(w, "</ListBucketResult>")
}

func TestClientObjectRoundTrip(t *testing.T) {
	service, server := newFakeService(t)
	client := service.client(t, server.URL)
	ctx := context.Background()

	key := "dir/a key+with (odd) chars~.bin"
	if err := client.Put(ctx, key, []byte("hello"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := client.Get(ctx, key, 1<<20)
	if err != nil || string(got) != "hello" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	info, err := client.Head(ctx, key)
	if err != nil || info.Size != 5 || info.LastModified.IsZero() {
		t.Fatalf("Head = %+v, %v", info, err)
	}
	if _, err := client.Get(ctx, key, 3); err == nil {
		t.Fatal("an object larger than the limit was returned")
	}
	if err := client.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(ctx, key, 1<<20); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete = %v, want ErrNotFound", err)
	}
	if _, err := client.Head(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Head after delete = %v, want ErrNotFound", err)
	}
	if err := client.Delete(ctx, key); err != nil {
		t.Fatalf("deleting a missing object: %v", err)
	}
}

func TestClientConditionalPut(t *testing.T) {
	service, server := newFakeService(t)
	client := service.client(t, server.URL)
	ctx := context.Background()
	if err := client.Put(ctx, "lease", []byte("one"), PutOptions{IfAbsent: true}); err != nil {
		t.Fatal(err)
	}
	err := client.Put(ctx, "lease", []byte("two"), PutOptions{IfAbsent: true})
	if !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("second conditional put = %v, want ErrPreconditionFailed", err)
	}
	if got, _ := client.Get(ctx, "lease", 16); string(got) != "one" {
		t.Fatalf("the object was overwritten: %q", got)
	}
	// A precondition failure is an answer, not a fault: one request.
	service.mu.Lock()
	defer service.mu.Unlock()
	if count := len(service.requests); count != 3 {
		t.Fatalf("%d requests, want 3: %v", count, service.requests)
	}
}

func TestClientRetries(t *testing.T) {
	service, server := newFakeService(t)
	client := service.client(t, server.URL)
	ctx := context.Background()

	service.fail = []int{500, 503, 429}
	if err := client.Put(ctx, "k", []byte("v"), PutOptions{}); err != nil {
		t.Fatalf("put through three retryable failures: %v", err)
	}
	if got, err := client.Get(ctx, "k", 8); err != nil || string(got) != "v" {
		t.Fatalf("Get = %q, %v", got, err)
	}

	service.mu.Lock()
	service.requests = nil
	service.fail = []int{403}
	service.mu.Unlock()
	var failure *Error
	if err := client.Put(ctx, "k", []byte("v"), PutOptions{}); !errors.As(err, &failure) || failure.Status != 403 {
		t.Fatalf("put = %v, want the 403", err)
	}
	service.mu.Lock()
	if len(service.requests) != 1 {
		t.Fatalf("a 403 was retried: %v", service.requests)
	}
	service.fail = []int{500, 500, 500, 500, 500, 500, 500}
	service.mu.Unlock()
	if err := client.Put(ctx, "k", []byte("v"), PutOptions{}); err == nil || !strings.Contains(err.Error(), "giving up after 6 attempts") {
		t.Fatalf("put = %v, want it to give up", err)
	}
}

func TestClientRetryStopsWithContext(t *testing.T) {
	service, server := newFakeService(t)
	client := service.client(t, server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	client.sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	service.fail = []int{500, 500}
	if err := client.Put(ctx, "k", []byte("v"), PutOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("put = %v, want context.Canceled", err)
	}
}

func TestClientListPages(t *testing.T) {
	service, server := newFakeService(t)
	service.pageSize = 3
	client := service.client(t, server.URL)
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		if err := client.Put(ctx, fmt.Sprintf("p/%02d", i), []byte{byte(i)}, PutOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	_ = client.Put(ctx, "q/other", nil, PutOptions{})
	objects, err := client.ListAll(ctx, "p/")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 8 || objects[0].Key != "p/00" || objects[7].Key != "p/07" || objects[3].Size != 1 || objects[0].LastModified.IsZero() {
		t.Fatalf("ListAll = %+v", objects)
	}
}

func TestClientVirtualHostAddressing(t *testing.T) {
	service, server := newFakeService(t)
	service.virtualHost = true
	// The bucket is a host label: resolve every name to the test server.
	client, err := New(Config{Endpoint: "http://s3.test", Bucket: service.bucket, Credentials: service.credentials,
		HTTPClient: &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: dialTo(server.Listener.Addr().String())}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := client.Put(ctx, "a/b", []byte("x"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, err := client.Get(ctx, "a/b", 8); err != nil || string(got) != "x" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.requests[0] != "PUT /a/b" {
		t.Fatalf("request = %q, want the key alone in the path", service.requests[0])
	}
}

func TestClientPutStream(t *testing.T) {
	service, server := newFakeService(t)
	client := service.client(t, server.URL)
	ctx := context.Background()

	data := make([]byte, 2*MinPartSize+12345)
	_, _ = rand.Read(data)
	size, err := client.PutStream(ctx, "big", iotestOneByteAtATimeAfter(data), MinPartSize, PutOptions{})
	if err != nil || size != int64(len(data)) {
		t.Fatalf("PutStream = %d, %v", size, err)
	}
	got, err := client.Get(ctx, "big", int64(len(data)))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("multipart object differs (%d bytes, %v)", len(got), err)
	}

	// Exactly two full parts: no empty third part.
	exact := data[:2*MinPartSize]
	if _, err := client.PutStream(ctx, "exact", bytes.NewReader(exact), MinPartSize, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := client.Get(ctx, "exact", int64(len(exact))); !bytes.Equal(got, exact) {
		t.Fatal("exact-multiple object differs")
	}

	// A small stream is one plain put.
	service.mu.Lock()
	service.requests = nil
	service.mu.Unlock()
	if _, err := client.PutStream(ctx, "small", strings.NewReader("tiny"), MinPartSize, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	service.mu.Lock()
	if len(service.requests) != 1 || service.requests[0] != "PUT /bucket/small" {
		t.Fatalf("small stream requests = %v", service.requests)
	}
	service.mu.Unlock()

	// A failing reader aborts the upload: nothing is left behind.
	broken := io.MultiReader(bytes.NewReader(data[:MinPartSize+10]), failingReader{})
	if _, err := client.PutStream(ctx, "broken", broken, MinPartSize, PutOptions{}); err == nil {
		t.Fatal("PutStream of a failing reader succeeded")
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.uploads) != 0 {
		t.Fatalf("%d multipart uploads left open", len(service.uploads))
	}
	if _, exists := service.objects["broken"]; exists {
		t.Fatal("a failed upload left an object")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("the source failed") }

// iotestOneByteAtATimeAfter returns short reads, which a stream from a
// pipe gives too.
func iotestOneByteAtATimeAfter(data []byte) io.Reader {
	return &shortReader{data: data}
}

type shortReader struct{ data []byte }

func (s *shortReader) Read(p []byte) (int, error) {
	if len(s.data) == 0 {
		return 0, io.EOF
	}
	n := 70000
	if n > len(p) {
		n = len(p)
	}
	if n > len(s.data) {
		n = len(s.data)
	}
	copy(p, s.data[:n])
	s.data = s.data[n:]
	return n, nil
}

func TestNewRejectsBadConfig(t *testing.T) {
	good := Config{Endpoint: "https://s3.example.com", Bucket: "b", Credentials: Credentials{AccessKey: "a", SecretKey: "s"}}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"no scheme":      func(c *Config) { c.Endpoint = "s3.example.com" },
		"path":           func(c *Config) { c.Endpoint = "https://s3.example.com/x" },
		"no bucket":      func(c *Config) { c.Bucket = "" },
		"slash bucket":   func(c *Config) { c.Bucket = "a/b" },
		"no credentials": func(c *Config) { c.Credentials = Credentials{} },
	} {
		cfg := good
		mutate(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
