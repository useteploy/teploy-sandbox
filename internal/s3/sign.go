// Package s3 is a small client for S3-compatible object storage, written
// against the standard library only: Signature Version 4, the handful of
// object calls the daemon needs, and retries.
//
// It deliberately speaks plain S3 and nothing a single provider adds. The
// one feature beyond the 2006 API is the conditional write
// (`If-None-Match: *`), and a caller can ask whether the service honours
// it (see Client.Put and ErrPreconditionFailed).
package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Credentials sign requests. SessionToken is optional (temporary
// credentials).
type Credentials struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
}

const (
	algorithm     = "AWS4-HMAC-SHA256"
	timeFormat    = "20060102T150405Z"
	dateFormat    = "20060102"
	emptyBodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// signRequest is one request as Signature Version 4 sees it.
type signRequest struct {
	method string
	// path is the request path as the bytes the caller means, not yet
	// percent-encoded.
	path  string
	query url.Values
	// headers are the headers to sign, by any-case name. "host" must be
	// among them.
	headers map[string]string
	// payloadHash is the hex SHA-256 of the body.
	payloadHash string
}

// uriEncode percent-encodes everything but the RFC 3986 unreserved
// characters, and "/" too unless keepSlash.
func uriEncode(value string, keepSlash bool) string {
	const upperHex = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			out.WriteByte(c)
		case c == '/' && keepSlash:
			out.WriteByte(c)
		default:
			out.WriteByte('%')
			out.WriteByte(upperHex[c>>4])
			out.WriteByte(upperHex[c&15])
		}
	}
	return out.String()
}

// canonicalQuery is the query string sorted by encoded name, and by
// encoded value among equal names. Sorting the joined "name=value"
// strings is not that: a name that is a prefix of another ("a", "a-b")
// would follow it whenever the next byte sorts below '='.
func canonicalQuery(query url.Values) string {
	type pair struct{ name, value string }
	var pairs []pair
	for name, values := range query {
		for _, value := range values {
			pairs = append(pairs, pair{uriEncode(name, false), uriEncode(value, false)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].name != pairs[j].name {
			return pairs[i].name < pairs[j].name
		}
		return pairs[i].value < pairs[j].value
	})
	joined := make([]string, len(pairs))
	for i, p := range pairs {
		joined[i] = p.name + "=" + p.value
	}
	return strings.Join(joined, "&")
}

// canonicalHeaderValue trims a value and folds runs of spaces to one.
func canonicalHeaderValue(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

// canonical returns the canonical request and its signed-headers list.
func (r signRequest) canonical() (request, signedHeaders string) {
	names := make([]string, 0, len(r.headers))
	lower := make(map[string]string, len(r.headers))
	for name, value := range r.headers {
		key := strings.ToLower(name)
		names = append(names, key)
		lower[key] = canonicalHeaderValue(value)
	}
	sort.Strings(names)
	var headers strings.Builder
	for _, name := range names {
		headers.WriteString(name + ":" + lower[name] + "\n")
	}
	signedHeaders = strings.Join(names, ";")
	path := uriEncode(r.path, true)
	if path == "" {
		path = "/"
	}
	request = strings.Join([]string{
		r.method,
		path,
		canonicalQuery(r.query),
		headers.String(),
		signedHeaders,
		r.payloadHash,
	}, "\n")
	return request, signedHeaders
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// signingKey derives the key a day's requests to one service in one
// region are signed with.
func signingKey(secret, date, region, service string) []byte {
	key := hmacSHA256([]byte("AWS4"+secret), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	return hmacSHA256(key, "aws4_request")
}

// authorization returns the Authorization header value for r at now.
func (c Credentials) authorization(r signRequest, now time.Time, region, service string) string {
	now = now.UTC()
	date := now.Format(dateFormat)
	scope := date + "/" + region + "/" + service + "/aws4_request"
	request, signedHeaders := r.canonical()
	digest := sha256.Sum256([]byte(request))
	toSign := strings.Join([]string{algorithm, now.Format(timeFormat), scope, hex.EncodeToString(digest[:])}, "\n")
	signature := hex.EncodeToString(hmacSHA256(signingKey(c.SecretKey, date, region, service), toSign))
	return algorithm + " Credential=" + c.AccessKey + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}
