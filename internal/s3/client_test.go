package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	requests []string
	// fail answers the next requests with these statuses, one each.
	fail []int
	// pageSize is the listing page size.
	pageSize int
	// quiet keeps a signature mismatch out of the test's own failures:
	// for a test that provokes one.
	quiet bool
}

func newFakeService(t *testing.T) (*fakeService, *httptest.Server) {
	service := &fakeService{
		t:           t,
		credentials: Credentials{AccessKey: "AKIDEXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
		bucket:      "bucket",
		objects:     map[string][]byte{},
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
		if !f.quiet {
			f.t.Errorf("%s %s: %v", r.Method, r.URL, err)
		}
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
	client, err := New(Config{Endpoint: "http://s3.test", AllowInsecure: true, Bucket: service.bucket, Credentials: service.credentials,
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
		// Plain http to another host: object names in the clear, and
		// answers anyone on the path can forge.
		"http elsewhere": func(c *Config) { c.Endpoint = "http://s3.example.com" },
	} {
		cfg := good
		mutate(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A redirect in front of the bucket must fail the write: followed, it
// turns the PUT into a GET of the target that reports success.
func TestPutDoesNotFollowARedirect(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPut {
			w.Header().Set("Location", "/bucket/elsewhere")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	client, err := New(Config{Endpoint: server.URL, Bucket: "bucket", PathStyle: true,
		Credentials: Credentials{AccessKey: "AKIDEXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Put(context.Background(), "some/key", []byte("data"), PutOptions{}); err == nil {
		t.Fatal("a redirect must fail the write")
	} else if !strings.Contains(err.Error(), "302") {
		t.Fatalf("the failure must name the redirect: %v", err)
	}
	if len(requests) != 1 || requests[0] != "PUT /bucket/some/key" {
		t.Fatalf("only the PUT may be made: %v", requests)
	}
}

// A service that repeats its continuation token must end the listing,
// not feed the same page to the caller forever while its slice grows.
func TestAListingThatRepeatsItsTokenEnds(t *testing.T) {
	pages := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list-type") != "2" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		pages++
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>stuck</NextContinuationToken>
<Contents><Key>page-%d</Key></Contents></ListBucketResult>`, pages)
	}))
	t.Cleanup(server.Close)
	client, err := New(Config{Endpoint: server.URL, Bucket: "bucket", PathStyle: true,
		Credentials: Credentials{AccessKey: "AKIDEXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListAll(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "continuation") {
		t.Fatalf("a repeated continuation token: %v", err)
	}
	if pages != 2 {
		t.Fatalf("two pages are enough to see the repeat, got %d", pages)
	}
}

// Review A8: the condition of a conditional write is part of what is
// signed. Unsigned, anything between the daemon and the service could
// remove it and the request would still verify: "create only" would
// become "overwrite".
func TestConditionalHeadersAreSigned(t *testing.T) {
	var authorization, condition string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization, condition = r.Header.Get("Authorization"), r.Header.Get("If-None-Match")
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	t.Cleanup(server.Close)
	client, err := New(Config{Endpoint: server.URL, Bucket: "b", PathStyle: true, Credentials: Credentials{AccessKey: "a", SecretKey: "s"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Put(context.Background(), "v1/run/x/00000000000000000002", []byte("record"), PutOptions{IfAbsent: true, ContentType: "application/json"}); err != nil {
		t.Fatal(err)
	}
	if condition != "*" {
		t.Fatalf("If-None-Match = %q", condition)
	}
	_, list, _ := strings.Cut(authorization, "SignedHeaders=")
	list, _, _ = strings.Cut(list, ",")
	for _, want := range []string{"if-none-match", "content-type", "host", "x-amz-content-sha256", "x-amz-date"} {
		if !strings.Contains(";"+list+";", ";"+want+";") {
			t.Errorf("%s is not among the signed headers: %s", want, list)
		}
	}
}

// And the fake service, which recomputes every signature from the
// request as received, refuses a conditional write whose condition was
// removed on the way.
func TestAStrippedConditionBreaksTheSignature(t *testing.T) {
	service, server := newFakeService(t)
	stripped := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		forward, _ := http.NewRequest(r.Method, server.URL+r.URL.RequestURI(), bytes.NewReader(body))
		forward.Header = r.Header.Clone()
		forward.Host = r.Host
		if forward.Header.Get("If-None-Match") != "" {
			forward.Header.Del("If-None-Match")
			stripped++
		}
		recorder := httptest.NewRecorder()
		service.quiet = true
		service.ServeHTTP(recorder, forward)
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	}))
	t.Cleanup(proxy.Close)
	client := service.client(t, proxy.URL)
	err := client.Put(context.Background(), "k", []byte("x"), PutOptions{IfAbsent: true})
	if err == nil || stripped == 0 {
		t.Fatalf("a write whose condition was stripped on the way was accepted (stripped %d): %v", stripped, err)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if _, written := service.objects["k"]; written {
		t.Fatal("the unconditional form of a conditional write reached the bucket")
	}
}

// Review A10: SigV4 sorts the query by name, then value — not the
// joined "name=value" strings.
func TestCanonicalQuerySortsByName(t *testing.T) {
	if got := canonicalQuery(url.Values{"a": {"1"}, "a-b": {"2"}}); got != "a=1&a-b=2" {
		t.Fatalf("canonical query = %s, want a=1&a-b=2", got)
	}
	if got := canonicalQuery(url.Values{"k": {"b", "a"}, "j": {"z"}}); got != "j=z&k=a&k=b" {
		t.Fatalf("canonical query = %s", got)
	}
}

// Review A6: a listing is what a collector deletes by. A service that
// ignores the prefix must be an error, not a list of someone else's
// objects.
func TestAListingOutsideItsPrefixIsRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<ListBucketResult><IsTruncated>false</IsTruncated>
<Contents><Key>fleet/v1/snap/a/manifest</Key><Size>1</Size><LastModified>2026-01-02T03:04:05.000Z</LastModified></Contents>
<Contents><Key>backups/database.dump</Key><Size>1</Size><LastModified>2026-01-02T03:04:05.000Z</LastModified></Contents>
</ListBucketResult>`)
	}))
	t.Cleanup(server.Close)
	client, err := New(Config{Endpoint: server.URL, Bucket: "bucket", PathStyle: true, Credentials: Credentials{AccessKey: "a", SecretKey: "s"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListAll(context.Background(), "fleet/v1/"); err == nil || !strings.Contains(err.Error(), "backups/database.dump") {
		t.Fatalf("a listing with a key outside its prefix: %v", err)
	}
}

// Review A10: a listing has as many pages as it has; S3 sets no bound,
// and a fixed one fails every pass over a large bucket for good.
func TestAListingOfManyPagesIsWalked(t *testing.T) {
	service, server := newFakeService(t)
	service.pageSize = 1
	client := service.client(t, server.URL)
	service.mu.Lock()
	for i := 0; i < 1500; i++ {
		service.objects[fmt.Sprintf("p/%05d", i)] = []byte{1}
	}
	service.mu.Unlock()
	count := 0
	if err := client.Walk(context.Background(), "p/", func(Object) error { count++; return nil }); err != nil {
		t.Fatal(err)
	}
	if count != 1500 {
		t.Fatalf("walked %d of 1500 objects", count)
	}
	// And a walk stops where its caller says.
	stop := errors.New("enough")
	if err := client.Walk(context.Background(), "p/", func(Object) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("Walk = %v", err)
	}
}

// Review A10: "no such bucket" is not "no such object". Daemons act on
// the second (a run with no record, a snapshot with no manifest).
func TestNoSuchBucketIsNotNotFound(t *testing.T) {
	service, server := newFakeService(t)
	client, err := New(Config{Endpoint: server.URL, Bucket: "another", PathStyle: true, Credentials: service.credentials})
	if err != nil {
		t.Fatal(err)
	}
	client.sleep = func(context.Context, time.Duration) error { return nil }
	_, err = client.Get(context.Background(), "k", 8)
	if errors.Is(err, ErrNotFound) || !errors.Is(err, ErrNoBucket) {
		t.Fatalf("Get from a bucket that does not exist = %v", err)
	}
	if _, err := service.client(t, server.URL).Get(context.Background(), "k", 8); !errors.Is(err, ErrNotFound) || errors.Is(err, ErrNoBucket) {
		t.Fatalf("Get of a missing object = %v", err)
	}
}

// Review A2: a modification time that cannot be read stays the zero
// time; it is the caller's to treat as unknown.
func TestAnUnreadableListingTimeIsZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<ListBucketResult><IsTruncated>false</IsTruncated>
<Contents><Key>a</Key><Size>1</Size><LastModified>yesterday</LastModified></Contents></ListBucketResult>`)
	}))
	t.Cleanup(server.Close)
	client, err := New(Config{Endpoint: server.URL, Bucket: "bucket", PathStyle: true, Credentials: Credentials{AccessKey: "a", SecretKey: "s"}})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListAll(context.Background(), "")
	if err != nil || len(listed) != 1 || !listed[0].LastModified.IsZero() {
		t.Fatalf("ListAll = %+v, %v", listed, err)
	}
}
