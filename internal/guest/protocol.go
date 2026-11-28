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
// Version 2 adds op "connect" (Request.V must be 2): the agent dials
// 127.0.0.1:<port>, then [::1]:<port>, inside the guest, answers one 'X'
// JSON(Result) — success, or CodeRefused — and on success the connection
// is from then on a raw byte stream to that socket, in both directions,
// with no more frames. A half-close travels across where both ends can
// make one. The client reads that result with MaxV2Frame as its limit,
// allocating only what has arrived, under ConnectResultTimeout.
//
// Version 3 adds op "restored" (Request.V must be 3), for a VM the daemon
// has just restored from a memory image: the agent sets the guest's wall
// clock to Request.NowNs, mixes Request.Entropy into the kernel's random
// pool and reseeds its generator, and answers one 'X' JSON(Result) whose
// Restored says what it did: whether the guest kernel has the VM
// Generation ID device (which reseeds the generator on every restore),
// whether the agent's own reseed worked, and the guest's clock just after
// it was set, so the daemon can check the step took.
//
// Version 4 extends "restored" for a VM that is a fork of a running one:
// Request.Fork and Request.KillSessions, which only a version 4 request
// may carry (an agent of version 3 or older refuses the request for its
// version, rather than ignore fields it does not know and leave the
// fork's inherited sessions running). On a version 4 "restored" the agent
// also, after the clock and the entropy: ends every exec session it had
// when the request came (KillSessions), which in a fork are the
// parent's, inherited with its memory; writes the restore's generation
// to GenerationFile (/run/teploy/generation); and runs the executables
// of HooksDir (/etc/teploy/on-restore.d) in name order, each with
// TEPLOY_GENERATION and TEPLOY_FORK in its environment, so that daemons
// that seeded a generator of their own before the fork can be restarted
// there. Restored then says how many sessions it ended, the generation,
// and which hooks ran and failed.
//
// Request.V names the protocol version. A server answers a version it
// does not speak with CodeUnsupportedVersion and its own version, so
// either side can be upgraded first. A version 3 server still answers
// every version 1 and 2 request as before; an older server refuses
// "restored" (as a version 3 request) and "connect" (as a version 2
// request) the same way, which the daemon reports as a guest agent too
// old for what it asked.
package guest

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// ProtocolVersion is the newest version this package speaks. Requests of
// version 1 are still sent for, and answered for, every op version 1 had,
// so a daemon with this package drives an agent built before version 2.
const ProtocolVersion = 4

// requestVersion is the version a request for op is sent as: the oldest
// version that has the op.
func requestVersion(op string) int {
	switch op {
	case opRestoredFork:
		return 4
	case OpConnect:
		return 2
	case OpRestored:
		return 3
	}
	return 1
}

// MaxV2Frame bounds a frame of a version 2 op; ConnectResultTimeout is how
// long the agent has to answer a connect.
const (
	MaxV2Frame           = 64 << 10
	ConnectResultTimeout = 5 * time.Second
)

// RestoredEntropyBytes is how much entropy a "restored" request carries:
// 64 bytes of the host's randomness, more than the kernel's generator
// needs for a reseed.
const RestoredEntropyBytes = 64

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
	// OpConnect is version 2.
	OpConnect = "connect"
	// OpRestored is version 3; with Fork or KillSessions, version 4.
	OpRestored = "restored"

	// opRestoredFork is not an op on the wire: it is how a "restored"
	// request with the fields of version 4 is versioned (versionOf).
	opRestoredFork = "restored+fork"
)

// versionOf is the version req is sent as: the oldest that has its op
// and every field it carries.
func versionOf(req Request) int {
	if req.Op == OpRestored && (req.Fork || req.KillSessions) {
		return requestVersion(opRestoredFork)
	}
	return requestVersion(req.Op)
}

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

	// connect: the guest TCP port, 1-65535.
	Port int `json:"port,omitempty"`

	// restored: the host's wall clock, in nanoseconds since the epoch, and
	// RestoredEntropyBytes of the host's randomness (JSON carries it as
	// base64).
	NowNs   int64  `json:"nowNs,omitempty"`
	Entropy []byte `json:"entropy,omitempty"`
	// restored, version 4: the VM is a fork of a running one (Fork), and
	// the exec sessions the agent had when the request came are the
	// parent's and are ended (KillSessions).
	Fork         bool `json:"fork,omitempty"`
	KillSessions bool `json:"killSessions,omitempty"`
}

// Error codes carried in Result.Code.
const (
	CodeBadRequest         = "bad_request"
	CodeNotFound           = "not_found"
	CodeTooLarge           = "too_large"
	CodeUnsupportedVersion = "unsupported_version"
	CodeInternal           = "internal"
	// CodeRefused: nothing accepted the connection on the guest port.
	CodeRefused = "refused"
	// CodeBusy: the agent has as many connects open as it allows.
	CodeBusy = "busy"
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

	// restored
	Restored *RestoredResult `json:"restored,omitempty"`
}

// RestoredResult is what the agent did for a "restored" request.
type RestoredResult struct {
	// VMGenIDSeen: the guest kernel has a driver bound to the VM
	// Generation ID device. The hypervisor changes the ID and notifies
	// the device before a restored VM runs again, and the driver
	// reseeds the generator on that, so /dev/urandom never continues the
	// stream the saved memory held. This is the reseed the daemon
	// requires.
	VMGenIDSeen bool `json:"vmgenidSeen"`
	// Reseeded: the agent's own reseed request (RNDRESEEDCRNG) was
	// honoured. In addition to the kernel's, and no evidence of one: it
	// comes only once the guest has been running again for as long as
	// its first answer took.
	Reseeded bool `json:"reseeded"`
	// ClockNs is the guest's wall clock just after it was set.
	ClockNs int64 `json:"clockNs"`

	// Version 4 only. SessionsKilled is how many exec sessions the agent
	// ended for KillSessions. Generation is what it wrote to its
	// generation file: one more than the file held. Hooks are the
	// on-restore executables it ran, by name, and HooksFailed those of
	// them that failed or ran out of time.
	SessionsKilled int      `json:"sessionsKilled,omitempty"`
	Generation     uint64   `json:"generation,omitempty"`
	Hooks          []string `json:"hooks,omitempty"`
	HooksFailed    []string `json:"hooksFailed,omitempty"`
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

// readFrameBounded is readFrame for version 2 ops: at most limit bytes of
// payload, and memory only for what has arrived, so a peer that sends a
// header and nothing else holds no more than the header. It never reads
// past the frame.
func readFrameBounded(r io.Reader, limit int) (kind byte, payload []byte, err error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[1:5])
	if size > uint32(limit) {
		return 0, nil, fmt.Errorf("frame of %d bytes exceeds the %d byte limit", size, limit)
	}
	const step = 4 << 10
	payload = make([]byte, 0, min(int(size), step))
	for len(payload) < int(size) {
		want := min(int(size)-len(payload), step)
		if cap(payload)-len(payload) < want {
			grown := make([]byte, len(payload), min(int(size), 2*cap(payload)+want))
			copy(grown, payload)
			payload = grown
		}
		n, err := io.ReadFull(r, payload[len(payload):len(payload)+want])
		payload = payload[:len(payload)+n]
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, nil, err
		}
	}
	return header[0], payload, nil
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
