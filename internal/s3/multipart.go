package s3

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// MinPartSize is the smallest part S3 accepts for any part but the last.
const MinPartSize = 5 << 20

// maxParts is the most parts one upload may have.
const maxParts = 10000

// PutStream writes an object of unknown length from r as a multipart
// upload, holding one part of partSize bytes in memory at a time. A
// stream that fits in one part is written with a single Put. On failure
// the upload is aborted, so no parts are left to be billed for.
func (c *Client) PutStream(ctx context.Context, key string, r io.Reader, partSize int, opts PutOptions) (size int64, err error) {
	if partSize < MinPartSize {
		return 0, fmt.Errorf("s3: part size %d is below the %d byte minimum", partSize, MinPartSize)
	}
	buffer := make([]byte, partSize)
	filled, readErr := io.ReadFull(r, buffer)
	if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
		return int64(filled), c.Put(ctx, key, buffer[:filled], opts)
	}
	if readErr != nil {
		return 0, readErr
	}

	initHeaders := map[string]string{}
	if opts.ContentType != "" {
		initHeaders["Content-Type"] = opts.ContentType
	}
	resp, err := c.do(ctx, request{method: http.MethodPost, key: key, query: url.Values{"uploads": {""}}, headers: initHeaders, limit: maxErrorBody})
	if err != nil {
		return 0, err
	}
	var initiated struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(resp.body, &initiated); err != nil || initiated.UploadID == "" {
		return 0, fmt.Errorf("s3: multipart upload of %s did not return an upload id", key)
	}
	uploadID := initiated.UploadID
	defer func() {
		if err != nil {
			// Under its own deadline: the caller's may be what ended it.
			abortCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if _, abortErr := c.do(abortCtx, request{method: http.MethodDelete, key: key, query: url.Values{"uploadId": {uploadID}}}); abortErr != nil && !errors.Is(abortErr, ErrNotFound) {
				err = errors.Join(err, fmt.Errorf("s3: abort of multipart upload %s: %w", uploadID, abortErr))
			}
		}
	}()

	type part struct {
		XMLName    xml.Name `xml:"Part"`
		PartNumber int
		ETag       string
	}
	var parts []part
	for number := 1; ; number++ {
		if number > maxParts {
			return size, fmt.Errorf("s3: %s needs more than %d parts of %d bytes", key, maxParts, partSize)
		}
		resp, err := c.do(ctx, request{method: http.MethodPut, key: key, body: buffer[:filled],
			query: url.Values{"partNumber": {strconv.Itoa(number)}, "uploadId": {uploadID}}})
		if err != nil {
			return size, err
		}
		etag := resp.headers.Get("ETag")
		if etag == "" {
			return size, fmt.Errorf("s3: part %d of %s was accepted without an ETag", number, key)
		}
		parts = append(parts, part{PartNumber: number, ETag: etag})
		size += int64(filled)
		if readErr != nil {
			break
		}
		filled, readErr = io.ReadFull(r, buffer)
		if readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return size, readErr
		}
	}

	var document bytes.Buffer
	document.WriteString("<CompleteMultipartUpload>")
	for _, done := range parts {
		encoded, _ := xml.Marshal(done)
		document.Write(encoded)
	}
	document.WriteString("</CompleteMultipartUpload>")
	headers := map[string]string{}
	if opts.IfAbsent {
		headers["If-None-Match"] = "*"
	}
	resp, err = c.do(ctx, request{method: http.MethodPost, key: key, body: document.Bytes(), headers: headers,
		query: url.Values{"uploadId": {uploadID}}, limit: maxErrorBody})
	if err != nil {
		return size, err
	}
	// A completion can fail after the 200 was sent: the error is then in
	// the body.
	var failure struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}
	if xml.Unmarshal(resp.body, &failure) == nil && failure.Code != "" {
		return size, &Error{Status: http.StatusOK, Code: failure.Code, Message: failure.Message}
	}
	return size, nil
}
