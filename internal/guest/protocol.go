// Package guest is the protocol between the sandbox daemon and the agent
// inside a run's VM (cmd/teploy-guestd), with both ends of it: Server is
// what the agent runs, Client is what the VM driver calls.
//
// The protocol is a stream of frames over any reliable byte stream: a
// vsock connection in production, a unix socket or net.Pipe in tests.
// One connection carries one request.
//
//	frame   = type(1 byte) length(4 bytes, big endian) payload
//	request = 'Q' JSON(Request)
//	          then, for op "write" only: 'D' chunks ... 'E'
//	reply   = for op "exec": 'O' (stdout) and 'R' (stderr) chunks, any order
//	          for op "read": 'D' chunks
//	          then always one 'X' JSON(Result), and the server closes
//
// Request.V names the protocol version. A server that does not speak it
// answers with CodeUnsupportedVersion and its own version, so either side
// can be upgraded first.
package guest

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ProtocolVersion is the version this package speaks.
const ProtocolVersion = 1

// Port is the vsock port the agent listens on inside the guest.
const Port = 7440

// MaxFileBytes bounds a file in either direction, the same 64 MiB the
// Docker driver and the HTTP upload path enforce.
const MaxFileBytes = 64 << 20

// DefaultWorkDir is where the files API is confined and where an exec
// with no cwd runs. It matches run.WorkDir.
const DefaultWorkDir = "/work"

const (
	frameRequest = 'Q'
	frameData    = 'D'
	frameEnd     = 'E'
	frameStdout  = 'O'
	frameStderr  = 'R'
	frameResult  = 'X'

	// maxFrame bounds one frame's payload. The request frame carries the
	// command and its env (the daemon caps env at 64 KiB); data frames are
	// sent in chunkSize pieces.
	maxFrame  = 1 << 20
	chunkSize = 32 << 10
)

const (
	OpPing  = "ping"
	OpExec  = "exec"
	OpWrite = "write"
	OpRead  = "read"
	OpSync  = "sync"
)

// Request is the first frame of every connection.
type Request struct {
	V  int    `json:"v"`
	Op string `json:"op"`

	// exec
	Cmd string            `json:"cmd,omitempty"`
	Cwd string            `json:"cwd,omitempty"`
	Env map[string]string `json:"env,omitempty"`
	// TimeoutMs bounds the command; 0 is unbounded.
	TimeoutMs int64 `json:"timeoutMs,omitempty"`

	// write, read: an absolute path under the agent's workdir.
	Path string `json:"path,omitempty"`
}

// Error codes carried in Result.Code.
const (
	CodeBadRequest         = "bad_request"
	CodeNotFound           = "not_found"
	CodeTooLarge           = "too_large"
	CodeUnsupportedVersion = "unsupported_version"
	CodeInternal           = "internal"
)

// Result is the last frame of every connection.
type Result struct {
	// Code and Error are set when the request failed; both empty is success.
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`

	// V is the server's protocol version, on every result.
	V int `json:"v"`

	// exec
	ExitCode int  `json:"exitCode"`
	TimedOut bool `json:"timedOut,omitempty"`

	// ping
	Agent string `json:"agent,omitempty"`
}

// Error is a failure the agent reported (as opposed to a broken stream).
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return "guest agent: " + e.Message }

// IsCode reports whether err is an agent error with the given code.
func IsCode(err error, code string) bool {
	var agentErr *Error
	return errors.As(err, &agentErr) && agentErr.Code == code
}

func writeFrame(w io.Writer, kind byte, payload []byte) error {
	if len(payload) > maxFrame {
		return fmt.Errorf("frame of %d bytes exceeds the %d byte limit", len(payload), maxFrame)
	}
	// One Write per frame: frames from concurrent writers (stdout and
	// stderr) must not interleave, and the callers serialize on that.
	buf := make([]byte, 5+len(payload))
	buf[0] = kind
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err
}

func writeJSONFrame(w io.Writer, kind byte, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeFrame(w, kind, payload)
}

func readFrame(r io.Reader) (kind byte, payload []byte, err error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[1:5])
	if size > maxFrame {
		return 0, nil, fmt.Errorf("frame of %d bytes exceeds the %d byte limit", size, maxFrame)
	}
	payload = make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}
