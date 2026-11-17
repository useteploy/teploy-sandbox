package s3

import (
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The vectors below are AWS's published Signature Version 4 test suite
// (the "aws-sig-v4-test-suite" files: request, canonical request,
// signature), with its example credentials, which are not real ones.
var suiteCredentials = Credentials{AccessKey: "AKIDEXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}

const suiteHash = emptyBodyHash

func suiteHeaders(extra map[string]string) map[string]string {
	headers := map[string]string{"Host": "example.amazonaws.com", "X-Amz-Date": "20150830T123600Z"}
	for name, value := range extra {
		headers[name] = value
	}
	return headers
}

func TestSigV4PublishedSuite(t *testing.T) {
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	unreserved := "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	cases := []struct {
		name      string
		request   signRequest
		canonical string
		signature string
	}{
		{
			name:      "get-vanilla",
			request:   signRequest{method: "GET", path: "/", headers: suiteHeaders(nil), payloadHash: suiteHash},
			canonical: "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n" + suiteHash,
			signature: "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
		},
		{
			name:      "post-vanilla",
			request:   signRequest{method: "POST", path: "/", headers: suiteHeaders(nil), payloadHash: suiteHash},
			signature: "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
		},
		{
			name:      "get-utf8",
			request:   signRequest{method: "GET", path: "/ሴ", headers: suiteHeaders(nil), payloadHash: suiteHash},
			canonical: "GET\n/%E1%88%B4\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n" + suiteHash,
			signature: "8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85",
		},
		{
			name:      "get-space-normalized",
			request:   signRequest{method: "GET", path: "/example space/", headers: suiteHeaders(nil), payloadHash: suiteHash},
			signature: "652487583200325589f1fba4c7e578f72c47cb61beeca81406b39ddec1366741",
		},
		{
			name:      "get-unreserved",
			request:   signRequest{method: "GET", path: "/" + unreserved, headers: suiteHeaders(nil), payloadHash: suiteHash},
			signature: "07ef7494c76fa4850883e2b006601f940f8a34d404d0cfa977f52a65bbf5f24f",
		},
		{
			name: "get-vanilla-query-order-key-case",
			request: signRequest{method: "GET", path: "/", query: url.Values{"Param2": {"value2"}, "Param1": {"value1"}},
				headers: suiteHeaders(nil), payloadHash: suiteHash},
			canonical: "GET\n/\nParam1=value1&Param2=value2\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n" + suiteHash,
			signature: "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
		},
		{
			name: "get-vanilla-empty-query-key",
			request: signRequest{method: "GET", path: "/", query: url.Values{"Param1": {"value1"}},
				headers: suiteHeaders(nil), payloadHash: suiteHash},
			signature: "a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb",
		},
		{
			name: "get-vanilla-query-unreserved",
			request: signRequest{method: "GET", path: "/", query: url.Values{unreserved: {unreserved}},
				headers: suiteHeaders(nil), payloadHash: suiteHash},
			signature: "9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197",
		},
		{
			name: "post-vanilla-query",
			request: signRequest{method: "POST", path: "/", query: url.Values{"Param1": {"value1"}},
				headers: suiteHeaders(nil), payloadHash: suiteHash},
			signature: "28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11",
		},
		{
			name: "get-header-value-trim",
			request: signRequest{method: "GET", path: "/",
				headers: suiteHeaders(map[string]string{"My-Header1": " value1", "My-Header2": " \"a   b   c\""}), payloadHash: suiteHash},
			canonical: "GET\n/\n\nhost:example.amazonaws.com\nmy-header1:value1\nmy-header2:\"a b c\"\nx-amz-date:20150830T123600Z\n\nhost;my-header1;my-header2;x-amz-date\n" + suiteHash,
			signature: "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
		},
		{
			name: "post-x-www-form-urlencoded",
			request: signRequest{method: "POST", path: "/",
				headers: suiteHeaders(map[string]string{
					"Content-Type":         "application/x-www-form-urlencoded",
					"Content-Length":       "13",
					"X-Amz-Content-Sha256": "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
				}), payloadHash: "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e"},
			signature: "d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.canonical != "" {
				if got, _ := tc.request.canonical(); got != tc.canonical {
					t.Fatalf("canonical request:\n%s\nwant:\n%s", got, tc.canonical)
				}
			}
			header := suiteCredentials.authorization(tc.request, at, "us-east-1", "service")
			if !strings.HasSuffix(header, "Signature="+tc.signature) {
				t.Fatalf("authorization = %s, want signature %s", header, tc.signature)
			}
			if !strings.HasPrefix(header, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=") {
				t.Fatalf("authorization = %s", header)
			}
		})
	}
}

// The signing key example from the AWS documentation ("Examples of how to
// derive a signing key for Signature Version 4").
func TestSigV4SigningKey(t *testing.T) {
	key := signingKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")
	if got, want := hex.EncodeToString(key), "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"; got != want {
		t.Fatalf("signing key = %s, want %s", got, want)
	}
}

// The worked examples in the Amazon S3 API reference ("Signature
// Calculations for the Authorization Header: Transferring Payload in a
// Single Chunk"), with the documentation's example credentials.
func TestSigV4S3DocumentationExamples(t *testing.T) {
	credentials := Credentials{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	at := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	const host = "examplebucket.s3.amazonaws.com"
	cases := []struct {
		name      string
		request   signRequest
		signature string
	}{
		{
			name: "get object with a range",
			request: signRequest{method: "GET", path: "/test.txt", headers: map[string]string{
				"Host": host, "Range": "bytes=0-9", "x-amz-content-sha256": emptyBodyHash, "x-amz-date": "20130524T000000Z",
			}, payloadHash: emptyBodyHash},
			signature: "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		},
		{
			name: "put object",
			request: signRequest{method: "PUT", path: "/test$file.text", headers: map[string]string{
				"Host": host, "Date": "Fri, 24 May 2013 00:00:00 GMT", "x-amz-date": "20130524T000000Z", "x-amz-storage-class": "REDUCED_REDUNDANCY",
				"x-amz-content-sha256": "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			}, payloadHash: "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"},
			signature: "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		},
		{
			name: "get bucket lifecycle",
			request: signRequest{method: "GET", path: "/", query: url.Values{"lifecycle": {""}}, headers: map[string]string{
				"Host": host, "x-amz-content-sha256": emptyBodyHash, "x-amz-date": "20130524T000000Z",
			}, payloadHash: emptyBodyHash},
			signature: "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		},
		{
			name: "list objects",
			request: signRequest{method: "GET", path: "/", query: url.Values{"max-keys": {"2"}, "prefix": {"J"}}, headers: map[string]string{
				"Host": host, "x-amz-content-sha256": emptyBodyHash, "x-amz-date": "20130524T000000Z",
			}, payloadHash: emptyBodyHash},
			signature: "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := credentials.authorization(tc.request, at, "us-east-1", "s3")
			if !strings.HasSuffix(header, "Signature="+tc.signature) {
				t.Fatalf("authorization = %s, want signature %s", header, tc.signature)
			}
		})
	}
}
