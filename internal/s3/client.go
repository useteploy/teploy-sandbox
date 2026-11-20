package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config is where a bucket is and how to sign for it.
type Config struct {
	// Endpoint is the service's base URL, scheme included
	// (https://s3.example.com, http://127.0.0.1:7070).
	Endpoint string
	// Region is the signing region; services that have none usually
	// accept "us-east-1".
	Region string
	Bucket string
	// PathStyle addresses the bucket as the first path segment
	// (endpoint/bucket/key) instead of as a host label
	// (bucket.endpoint/key).
	PathStyle   bool
	Credentials Credentials
	// HTTPClient is used when set; the default has sane timeouts.
	HTTPClient *http.Client
	// MaxAttempts bounds tries of one request (default 6).
	MaxAttempts int
	// UserAgent is sent when set.
	UserAgent string
	// AllowInsecure admits an http:// endpoint that is not this host.
	// Without TLS anything on the path reads every object name and can
	// replay, drop or answer for the service; the signature only covers
	// what the request says, never what the answer does.
	AllowInsecure bool
}

// Client talks to one bucket.
type Client struct {
	cfg      Config
	endpoint *url.URL
	http     *http.Client
	now      func() time.Time
	// sleep waits between attempts; tests replace it.
	sleep func(ctx context.Context, d time.Duration) error
}

var (
	// ErrNotFound: the object does not exist. A bucket that does not
	// exist is ErrNoBucket, never this: "the object is not there" is an
	// answer daemons act on, and a mistyped bucket must not give it.
	ErrNotFound = errors.New("s3: not found")
	// ErrNoBucket: the service says the bucket itself does not exist.
	ErrNoBucket = errors.New("s3: no such bucket")
	// ErrPreconditionFailed: a conditional write found the object already
	// there.
	ErrPreconditionFailed = errors.New("s3: precondition failed")
)

// Error is an error response from the service.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("s3: HTTP %d", e.Status)
	}
	return fmt.Sprintf("s3: %s (HTTP %d): %s", e.Code, e.Status, e.Message)
}

// Is maps the service's answers onto the two sentinel errors.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.Status == http.StatusNotFound && e.Code != "NoSuchBucket"
	case ErrNoBucket:
		return e.Code == "NoSuchBucket"
	case ErrPreconditionFailed:
		return e.Status == http.StatusPreconditionFailed
	}
	return false
}

// New validates cfg and returns a client for its bucket.
func New(cfg Config) (*Client, error) {
	endpoint, err := url.Parse(cfg.Endpoint)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" {
		return nil, fmt.Errorf("s3: endpoint %q must be an http or https URL", cfg.Endpoint)
	}
	if endpoint.Scheme == "http" && !cfg.AllowInsecure && !loopbackHost(endpoint.Hostname()) {
		return nil, fmt.Errorf("s3: endpoint %q is plain http to another host; use https, or say explicitly that the path to the service is trusted", cfg.Endpoint)
	}
	if strings.Trim(endpoint.Path, "/") != "" || endpoint.RawQuery != "" {
		return nil, fmt.Errorf("s3: endpoint %q must not have a path or query", cfg.Endpoint)
	}
	if cfg.Bucket == "" || strings.ContainsAny(cfg.Bucket, "/ ") {
		return nil, fmt.Errorf("s3: bucket %q is not a bucket name", cfg.Bucket)
	}
	if cfg.Credentials.AccessKey == "" || cfg.Credentials.SecretKey == "" {
		return nil, errors.New("s3: an access key and a secret key are required")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 6
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 2 * time.Minute,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
		}}
	}
	// An S3 service does not redirect legitimately, and a followed one
	// turns a PUT into a GET of the target that reports success: never
	// follow, whatever client was handed in. A 3xx then arrives as a
	// response of its own and fails as an error.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{cfg: cfg, endpoint: endpoint, http: client, now: time.Now, sleep: sleepContext}, nil
}

// loopbackHost reports whether host is this machine: a loopback address
// or the name every resolver gives one.
func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// target is the host and path of a key ("" is the bucket itself).
func (c *Client) target(key string) (host, path string) {
	if c.cfg.PathStyle {
		return c.endpoint.Host, "/" + c.cfg.Bucket + "/" + key
	}
	return c.cfg.Bucket + "." + c.endpoint.Host, "/" + key
}

// request is one call, replayable: the body is bytes.
type request struct {
	method  string
	key     string
	query   url.Values
	headers map[string]string
	body    []byte
	// limit bounds how much of a response body is read; 0 reads none
	// beyond an error document.
	limit int64
}

type response struct {
	status  int
	headers http.Header
	body    []byte
}

const maxErrorBody = 64 << 10

// attemptTimeout bounds one attempt: generous for the body it carries in
// either direction, never unbounded.
func attemptTimeout(bytes int64) time.Duration {
	return 60*time.Second + time.Duration(bytes/(128<<10))*time.Second
}

func (c *Client) attempt(ctx context.Context, r request) (*response, error) {
	size := int64(len(r.body))
	if r.limit > size {
		size = r.limit
	}
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout(size))
	defer cancel()

	host, path := c.target(r.key)
	digest := sha256.Sum256(r.body)
	payloadHash := hex.EncodeToString(digest[:])
	now := c.now().UTC()
	signed := map[string]string{
		"host":                 host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date":           now.Format(timeFormat),
	}
	if c.cfg.Credentials.SessionToken != "" {
		signed["x-amz-security-token"] = c.cfg.Credentials.SessionToken
	}
	// Every header that changes what the request means is signed: a
	// condition (If-None-Match, If-Match) that something on the path
	// could strip would turn "create only" into "overwrite" with a
	// signature that still verifies.
	for name, value := range r.headers {
		signed[strings.ToLower(name)] = value
	}
	sign := signRequest{method: r.method, path: path, query: r.query, headers: signed, payloadHash: payloadHash}

	target := url.URL{Scheme: c.endpoint.Scheme, Host: host, Path: path, RawPath: uriEncode(path, true), RawQuery: canonicalQuery(r.query)}
	req, err := http.NewRequestWithContext(ctx, r.method, target.String(), bytes.NewReader(r.body))
	if err != nil {
		return nil, err
	}
	req.ContentLength = int64(len(r.body))
	for name, value := range signed {
		if name != "host" {
			req.Header.Set(name, value)
		}
	}
	if c.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", c.cfg.UserAgent)
	}
	req.Header.Set("Authorization", c.cfg.Credentials.authorization(sign, now, c.cfg.Region, "s3"))

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := &response{status: resp.StatusCode, headers: resp.Header}
	limit := r.limit
	if resp.StatusCode >= 300 || limit == 0 {
		limit = maxErrorBody
	}
	// One byte more than allowed, so an oversized body is seen as one.
	out.body, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("s3: reading the response: %w", err)
	}
	if resp.StatusCode < 300 && int64(len(out.body)) > limit {
		if r.limit == 0 {
			out.body = out.body[:0]
		} else {
			return nil, &Error{Status: resp.StatusCode, Code: "ResponseTooLarge", Message: fmt.Sprintf("the body is larger than the %d bytes expected", r.limit)}
		}
	}
	if resp.StatusCode < 300 && resp.ContentLength >= 0 && r.method != http.MethodHead && int64(len(out.body)) != resp.ContentLength {
		return nil, fmt.Errorf("s3: short response: %d of %d bytes", len(out.body), resp.ContentLength)
	}
	return out, nil
}

// serviceError turns a non-2xx response into an *Error.
func serviceError(resp *response) *Error {
	failure := &Error{Status: resp.status}
	var document struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if xml.Unmarshal(resp.body, &document) == nil {
		failure.Code, failure.Message = document.Code, document.Message
	}
	if failure.Code == "RequestTimeTooSkewed" {
		// Name the real cause: an operator reading "AccessDenied" looks
		// at credentials, not at the clock. The service's own Date says
		// by how much the two disagree.
		if date, err := http.ParseTime(resp.headers.Get("Date")); err == nil {
			failure.Message += fmt.Sprintf(" (this daemon's clock and the service's differ by about %s; synchronize the clock)", respSkew(date))
		} else {
			failure.Message += " (synchronize this daemon's clock with the service's)"
		}
	}
	return failure
}

// respSkew formats a clock difference without its sign mattering.
func respSkew(date time.Time) string {
	d := time.Since(date)
	if d < 0 {
		d = -d
	}
	return d.Round(time.Second).String()
}

// retryable reports whether another attempt can help.
func retryable(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var failure *Error
	if !errors.As(err, &failure) {
		// The network, a timeout, a body cut short.
		return true
	}
	switch failure.Status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	case http.StatusConflict:
		// Two conditional writes at once: the service asks for a retry.
		return failure.Code == "ConditionalRequestConflict" || failure.Code == "OperationAborted"
	}
	switch failure.Code {
	case "RequestTimeout", "SlowDown", "InternalError", "ServiceUnavailable", "Throttling":
		return true
	}
	return false
}

const (
	backoffBase = 200 * time.Millisecond
	backoffMax  = 10 * time.Second
)

// do runs r until it succeeds, fails for good or runs out of attempts.
func (c *Client) do(ctx context.Context, r request) (*response, error) {
	var last error
	for attempt := 0; attempt < c.cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			delay := backoffBase << (attempt - 1)
			if delay > backoffMax {
				delay = backoffMax
			}
			// Full jitter: callers that failed together do not retry together.
			delay = time.Duration(rand.Int64N(int64(delay)) + int64(delay)/2)
			if err := c.sleep(ctx, delay); err != nil {
				return nil, errors.Join(last, err)
			}
		}
		resp, err := c.attempt(ctx, r)
		if err == nil && resp.status >= 300 {
			err = serviceError(resp)
		}
		if err == nil {
			return resp, nil
		}
		last = err
		if ctx.Err() != nil || !retryable(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("s3: giving up after %d attempts: %w", c.cfg.MaxAttempts, last)
}

// PutOptions are the optional parts of a write.
type PutOptions struct {
	// IfAbsent makes the write conditional (`If-None-Match: *`): it
	// succeeds only when no object has the key, and is
	// ErrPreconditionFailed otherwise. Not every service honours it; see
	// Store.Conditional in internal/offhost for how that is found out.
	// The header is signed, so nothing between the daemon and the
	// service can remove the condition without breaking the request.
	IfAbsent    bool
	ContentType string
}

func (o PutOptions) headers() map[string]string {
	headers := map[string]string{}
	if o.IfAbsent {
		headers["If-None-Match"] = "*"
	}
	if o.ContentType != "" {
		headers["Content-Type"] = o.ContentType
	}
	return headers
}

// Put writes an object in one request. A retried conditional write can
// answer ErrPreconditionFailed for an object this very call created (the
// first attempt reached the service and its answer was lost): a caller
// for whom that matters reads the object back.
func (c *Client) Put(ctx context.Context, key string, body []byte, opts PutOptions) error {
	_, err := c.do(ctx, request{method: http.MethodPut, key: key, body: body, headers: opts.headers()})
	return err
}

// Get reads an object of at most limit bytes into memory.
func (c *Client) Get(ctx context.Context, key string, limit int64) ([]byte, error) {
	resp, err := c.do(ctx, request{method: http.MethodGet, key: key, limit: limit})
	if err != nil {
		return nil, err
	}
	return resp.body, nil
}

// Object is one listed or inspected object.
type Object struct {
	Key          string
	Size         int64
	LastModified time.Time
	ETag         string
}

// Head describes an object without reading it.
func (c *Client) Head(ctx context.Context, key string) (Object, error) {
	resp, err := c.do(ctx, request{method: http.MethodHead, key: key})
	if err != nil {
		return Object{}, err
	}
	object := Object{Key: key, ETag: resp.headers.Get("ETag")}
	object.Size, _ = strconv.ParseInt(resp.headers.Get("Content-Length"), 10, 64)
	object.LastModified, _ = http.ParseTime(resp.headers.Get("Last-Modified"))
	return object, nil
}

// Delete removes an object. Deleting what is not there succeeds.
func (c *Client) Delete(ctx context.Context, key string) error {
	_, err := c.do(ctx, request{method: http.MethodDelete, key: key})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// Page is one page of a listing.
type Page struct {
	Objects []Object
	// Prefixes are the common prefixes when a delimiter was given.
	Prefixes []string
	// Next continues the listing; "" on the last page.
	Next string
}

const maxListBody = 16 << 20

// List returns one page of the keys under prefix (ListObjectsV2), in key
// order. token is "" for the first page.
//
// A key that does not begin with prefix is an error, not a result: every
// caller deletes by what a listing says, and a service (or something in
// front of one) that ignores the prefix would otherwise have a daemon
// delete what was never its own. A modification time that cannot be read
// is the zero time; callers that age objects must not take it for old.
func (c *Client) List(ctx context.Context, prefix, delimiter, token string) (Page, error) {
	query := url.Values{"list-type": {"2"}}
	if prefix != "" {
		query.Set("prefix", prefix)
	}
	if delimiter != "" {
		query.Set("delimiter", delimiter)
	}
	if token != "" {
		query.Set("continuation-token", token)
	}
	resp, err := c.do(ctx, request{method: http.MethodGet, query: query, limit: maxListBody})
	if err != nil {
		return Page{}, err
	}
	var result struct {
		IsTruncated           bool   `xml:"IsTruncated"`
		NextContinuationToken string `xml:"NextContinuationToken"`
		Contents              []struct {
			Key          string `xml:"Key"`
			Size         int64  `xml:"Size"`
			LastModified string `xml:"LastModified"`
			ETag         string `xml:"ETag"`
		} `xml:"Contents"`
		CommonPrefixes []struct {
			Prefix string `xml:"Prefix"`
		} `xml:"CommonPrefixes"`
	}
	if err := xml.Unmarshal(resp.body, &result); err != nil {
		return Page{}, fmt.Errorf("s3: list response: %w", err)
	}
	page := Page{}
	for _, entry := range result.Contents {
		if !strings.HasPrefix(entry.Key, prefix) {
			return Page{}, fmt.Errorf("s3: the listing of %q holds %q, which is not under it; the service does not honour the prefix", prefix, entry.Key)
		}
		object := Object{Key: entry.Key, Size: entry.Size, ETag: entry.ETag}
		object.LastModified, _ = time.Parse(time.RFC3339Nano, entry.LastModified)
		page.Objects = append(page.Objects, object)
	}
	for _, entry := range result.CommonPrefixes {
		if !strings.HasPrefix(entry.Prefix, prefix) {
			return Page{}, fmt.Errorf("s3: the listing of %q holds the prefix %q, which is not under it", prefix, entry.Prefix)
		}
		page.Prefixes = append(page.Prefixes, entry.Prefix)
	}
	if result.IsTruncated {
		if result.NextContinuationToken == "" {
			return Page{}, errors.New("s3: a truncated listing without a continuation token")
		}
		page.Next = result.NextContinuationToken
	}
	return page, nil
}

// Walk calls each for every object under prefix, a page at a time: what
// is held at once is one page, however large the bucket. An error from
// each ends the walk and is returned.
//
// There is no bound on the number of pages (S3 has none, and a bound
// makes every pass over a large bucket fail for good). What is refused
// is a listing that cannot end: a continuation token the service has
// already given.
func (c *Client) Walk(ctx context.Context, prefix string, each func(Object) error) error {
	token := ""
	// One digest per page: a million pages (a billion keys) is 8 MB.
	seen := map[[8]byte]struct{}{}
	for {
		page, err := c.List(ctx, prefix, "", token)
		if err != nil {
			return err
		}
		for _, object := range page.Objects {
			if err := each(object); err != nil {
				return err
			}
		}
		if page.Next == "" {
			return nil
		}
		digest := sha256.Sum256([]byte(page.Next))
		mark := [8]byte(digest[:8])
		if _, repeated := seen[mark]; repeated {
			return fmt.Errorf("s3: the service repeats the continuation token of %q", prefix)
		}
		seen[mark] = struct{}{}
		token = page.Next
	}
}

// ListAll lists every key under prefix into memory: for a prefix known
// to be small (one run's records, a test's objects). Passes over a whole
// bucket use Walk.
func (c *Client) ListAll(ctx context.Context, prefix string) ([]Object, error) {
	var objects []Object
	err := c.Walk(ctx, prefix, func(object Object) error {
		objects = append(objects, object)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return objects, nil
}

// CreateBucket creates the client's bucket. A bucket this account already
// has is not an error.
func (c *Client) CreateBucket(ctx context.Context) error {
	_, err := c.do(ctx, request{method: http.MethodPut})
	var failure *Error
	if errors.As(err, &failure) && (failure.Code == "BucketAlreadyOwnedByYou" || failure.Code == "BucketAlreadyExists") {
		return nil
	}
	return err
}
