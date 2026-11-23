package guest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// killAfter is how long a timed-out command gets between TERM and KILL,
	// the same five seconds the Docker driver's `timeout --kill-after` gives.
	killAfter = 5 * time.Second
	// pipeGrace is how long a finished command's output pipes may stay open
	// (a background child inherited them) before the exec answers anyway.
	pipeGrace = 2 * time.Second

	// Exit codes for a command the deadline ended, as coreutils timeout
	// reports them: the Docker driver classifies the same two.
	exitTimedOut = 124
	exitKilled   = 137
)

// Server answers agent requests. The zero value serves DefaultWorkDir with
// /bin/sh and the process's own environment.
type Server struct {
	// WorkDir confines the files API and is the default exec directory.
	WorkDir string
	// Shell runs exec commands as `Shell -c cmd`.
	Shell string
	// Env is the base environment of every exec ("NAME=value"); nil means
	// the agent's own. A request's env is laid over it.
	Env []string
	// Agent is the version string ping reports.
	Agent string
	// Sync flushes filesystems; nil means the platform's sync(2).
	Sync func() error
	// Logf, when set, receives one line per failed request.
	Logf func(format string, args ...any)

	// MaxConnects bounds the connect streams open at once (version 2);
	// zero is DefaultMaxConnects.
	MaxConnects int
	// DialTCP opens a connect's socket; nil dials TCP with a
	// ConnectResultTimeout bound. Tests substitute it.
	DialTCP func(address string) (net.Conn, error)

	// killAfter and maxFile override the TERM-to-KILL grace and the file
	// size limit in tests.
	killAfter time.Duration
	maxFile   int64
	// linger overrides pipeLinger in tests.
	linger time.Duration

	connectsMu sync.Mutex
	connects   int
}

// DefaultMaxConnects is how many connect streams the agent keeps open at
// once: twice the daemon's own per-run cap.
const DefaultMaxConnects = 128

func (s *Server) fileLimit() int64 {
	if s.maxFile > 0 {
		return s.maxFile
	}
	return MaxFileBytes
}

// limitText names the file size limit in an error.
func (s *Server) limitText() string {
	if limit := s.fileLimit(); limit < 1<<20 {
		return fmt.Sprintf("%d byte", limit)
	}
	return fmt.Sprintf("%d MiB", s.fileLimit()>>20)
}

func (s *Server) workDir() string {
	if s.WorkDir != "" {
		return filepath.Clean(s.WorkDir)
	}
	return DefaultWorkDir
}

func (s *Server) shell() string {
	if s.Shell != "" {
		return s.Shell
	}
	return "/bin/sh"
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// frameWriter serializes frames from the exec's two output streams and the
// handler onto one connection.
type frameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (f *frameWriter) frame(kind byte, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return writeFrame(f.w, kind, payload)
}

// stream is an io.Writer that sends what it is given as frames of one kind.
type stream struct {
	out  *frameWriter
	kind byte
}

func (s stream) Write(p []byte) (int, error) {
	for sent := 0; sent < len(p); {
		end := min(sent+chunkSize, len(p))
		if err := s.out.frame(s.kind, p[sent:end]); err != nil {
			return sent, err
		}
		sent = end
	}
	return len(p), nil
}

// ServeConn handles the one request a connection carries, then closes it.
func (s *Server) ServeConn(conn io.ReadWriteCloser) {
	defer conn.Close()
	out := &frameWriter{w: conn}
	result, stream := s.handle(conn, out)
	if stream != nil {
		// A connect that reached its port: the result says so, and the
		// connection becomes the stream.
		defer stream.Close()
		payload, err := json.Marshal(Result{V: ProtocolVersion})
		if err != nil || out.frame(frameResult, payload) != nil {
			return
		}
		s.pipe(conn, stream)
		return
	}
	result.V = ProtocolVersion
	if result.Code != "" {
		s.logf("request failed: %s: %s", result.Code, result.Error)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return
	}
	_ = out.frame(frameResult, payload)
}

func failure(code, format string, args ...any) Result {
	return Result{Code: code, Error: fmt.Sprintf(format, args...), ExitCode: -1}
}

// handle serves one request. A connect that reached its port returns the
// guest socket instead of a result: the caller answers and pipes.
func (s *Server) handle(conn io.Reader, out *frameWriter) (Result, net.Conn) {
	kind, payload, err := readFrame(conn)
	if err != nil {
		return failure(CodeBadRequest, "read request: %v", err), nil
	}
	if kind != frameRequest {
		return failure(CodeBadRequest, "first frame must be a request, got %q", kind), nil
	}
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		return failure(CodeBadRequest, "request is not JSON: %v", err), nil
	}
	if req.V < 1 || req.V > ProtocolVersion {
		return failure(CodeUnsupportedVersion, "protocol version %d is not supported; this agent speaks 1 to %d", req.V, ProtocolVersion), nil
	}
	if req.V < requestVersion(req.Op) {
		return failure(CodeUnsupportedVersion, "op %q needs protocol version %d", req.Op, requestVersion(req.Op)), nil
	}
	switch req.Op {
	case OpPing:
		return Result{Agent: s.Agent}, nil
	case OpSync:
		if err := s.sync(); err != nil {
			return failure(CodeInternal, "sync: %v", err), nil
		}
		return Result{}, nil
	case OpExec:
		return s.exec(conn, out, req), nil
	case OpWrite:
		return s.write(conn, req), nil
	case OpRead:
		return s.read(out, req), nil
	case OpConnect:
		return s.connect(req)
	default:
		return failure(CodeBadRequest, "unknown op %q", req.Op), nil
	}
}

// connect dials the guest port: 127.0.0.1 first (where dev servers bind),
// then ::1. The stream it returns holds one of MaxConnects until closed.
func (s *Server) connect(req Request) (Result, net.Conn) {
	if req.Port < 1 || req.Port > 65535 {
		return failure(CodeBadRequest, "connect needs a port 1-65535, got %d", req.Port), nil
	}
	limit := s.MaxConnects
	if limit <= 0 {
		limit = DefaultMaxConnects
	}
	s.connectsMu.Lock()
	if s.connects >= limit {
		s.connectsMu.Unlock()
		return failure(CodeBusy, "the agent has %d connects open, its limit", limit), nil
	}
	s.connects++
	s.connectsMu.Unlock()
	release := func() {
		s.connectsMu.Lock()
		s.connects--
		s.connectsMu.Unlock()
	}
	dial := s.DialTCP
	if dial == nil {
		dial = func(address string) (net.Conn, error) {
			return net.DialTimeout("tcp", address, ConnectResultTimeout/2)
		}
	}
	port := strconv.Itoa(req.Port)
	var errs []error
	for _, host := range []string{"127.0.0.1", "::1"} {
		socket, err := dial(net.JoinHostPort(host, port))
		if err == nil {
			return Result{}, &countedConn{Conn: socket, release: release}
		}
		errs = append(errs, err)
	}
	release()
	return failure(CodeRefused, "nothing accepted a connection on guest port %d: %v", req.Port, errors.Join(errs...)), nil
}

// countedConn gives its connect slot back when closed.
type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (c *countedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}

// pipeLinger is how long the direction still open after the other ended
// may go without moving a byte before the stream is closed: the peer it
// reads from may never close it (a server that keeps a socket after its
// client half-closed), and the connect slot must come back.
const pipeLinger = 2 * time.Minute

func (s *Server) lingerTime() time.Duration {
	if s.linger > 0 {
		return s.linger
	}
	return pipeLinger
}

type readDeadliner interface{ SetReadDeadline(time.Time) error }

// pipe copies between the daemon's connection and the guest socket until
// both directions end. An end of one direction is passed on as a
// half-close where the other side can take one, and as a close where it
// cannot; the direction left open then has pipeLinger between bytes.
func (s *Server) pipe(conn io.ReadWriteCloser, socket net.Conn) {
	var ended atomic.Bool
	linger := s.lingerTime()
	done := make(chan struct{}, 2)
	halfClose := func(w any, closer io.Closer) {
		if half, ok := w.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
			return
		}
		_ = closer.Close()
	}
	direction := func(dst io.Writer, src io.Reader, other io.Reader, finish func()) {
		buf := make([]byte, chunkSize)
		for {
			if ended.Load() {
				if d, ok := src.(readDeadliner); ok {
					_ = d.SetReadDeadline(time.Now().Add(linger))
				}
			}
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		finish()
		if !ended.Swap(true) {
			if d, ok := other.(readDeadliner); ok {
				_ = d.SetReadDeadline(time.Now().Add(linger))
			}
		} else {
			// Both directions are over.
			_ = conn.Close()
			_ = socket.Close()
		}
		done <- struct{}{}
	}
	go direction(socket, conn, socket, func() { halfClose(socket, socket) })
	go direction(conn, socket, conn, func() { halfClose(conn, conn) })
	<-done
	<-done
}

func (s *Server) sync() error {
	if s.Sync != nil {
		return s.Sync()
	}
	return platformSync()
}

// safePath checks a files-API path: absolute, already clean (so no "..",
// no empty or "." segments) and strictly inside the workdir. The daemon
// applies the same rules before it calls; the agent does not trust that.
func (s *Server) safePath(path string) (string, error) {
	root := s.workDir()
	switch {
	case path == "" || strings.ContainsRune(path, 0):
		return "", errors.New("path is empty or contains a NUL")
	case !filepath.IsAbs(path):
		return "", errors.New("path must be absolute")
	case filepath.Clean(path) != path:
		return "", errors.New("path must be clean: no \"..\", \".\" or empty segments")
	case !strings.HasPrefix(path, root+string(filepath.Separator)):
		return "", fmt.Errorf("path is outside the workdir %s", root)
	}
	return path, nil
}

func (s *Server) exec(conn io.Reader, out *frameWriter, req Request) Result {
	if strings.TrimSpace(req.Cmd) == "" {
		return failure(CodeBadRequest, "exec needs a command")
	}
	dir := req.Cwd
	if dir == "" {
		dir = s.workDir()
		// The default directory always exists, as it does in a container.
		_ = os.MkdirAll(dir, 0o755)
	}
	if !filepath.IsAbs(dir) {
		return failure(CodeBadRequest, "cwd must be absolute")
	}
	for name, value := range req.Env {
		if name == "" || strings.ContainsAny(name, "=\x00") || strings.ContainsRune(value, 0) {
			return failure(CodeBadRequest, "env name %q or its value cannot be passed to a process", name)
		}
	}

	cmd := exec.Command(s.shell(), "-c", req.Cmd)
	cmd.Dir = dir
	cmd.Env = mergeEnv(s.Env, req.Env)
	cmd.Stdout = stream{out, frameStdout}
	cmd.Stderr = stream{out, frameStderr}
	cmd.WaitDelay = pipeGrace
	ownProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		return failure(CodeBadRequest, "start command: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// The client sends nothing after an exec request, so the only thing
	// this read can see is the connection ending: the caller gave up, and
	// the command must not outlive it.
	gone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		close(gone)
	}()

	var deadline, kill <-chan time.Time
	if req.TimeoutMs > 0 {
		timer := time.NewTimer(time.Duration(req.TimeoutMs) * time.Millisecond)
		defer timer.Stop()
		deadline = timer.C
	}
	grace := s.killAfter
	if grace <= 0 {
		grace = killAfter
	}
	timedOut, killed := false, false
	for {
		select {
		case err := <-done:
			if timedOut {
				code := exitTimedOut
				if killed {
					code = exitKilled
				}
				return Result{ExitCode: code, TimedOut: true}
			}
			if err != nil && cmd.ProcessState == nil {
				return failure(CodeInternal, "wait for command: %v", err)
			}
			return Result{ExitCode: exitCode(cmd.ProcessState)}
		case <-deadline:
			timedOut, deadline = true, nil
			terminateGroup(cmd)
			timer := time.NewTimer(grace)
			defer timer.Stop()
			kill = timer.C
		case <-kill:
			killed, kill = true, nil
			killGroup(cmd)
		case <-gone:
			gone = nil
			killGroup(cmd)
		}
	}
}

// mergeEnv lays overrides over base (nil base: the agent's own
// environment), sorted so a command sees a stable environment.
func mergeEnv(base []string, overrides map[string]string) []string {
	if base == nil {
		base = os.Environ()
	}
	merged := make(map[string]string, len(base)+len(overrides))
	for _, entry := range base {
		if name, value, ok := strings.Cut(entry, "="); ok && name != "" {
			merged[name] = value
		}
	}
	for name, value := range overrides {
		merged[name] = value
	}
	env := make([]string, 0, len(merged))
	for name, value := range merged {
		env = append(env, name+"="+value)
	}
	sort.Strings(env)
	return env
}

// write receives a file body. On any failure it keeps reading to the end
// frame before answering, so a client still sending is never left blocked
// on a peer that stopped listening.
func (s *Server) write(conn io.Reader, req Request) Result {
	var file *os.File
	var failed *Result
	fail := func(result Result) {
		if failed == nil {
			failed = &result
		}
	}
	path, err := s.safePath(req.Path)
	if err != nil {
		fail(failure(CodeBadRequest, "write %q: %v", req.Path, err))
	} else if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fail(failure(CodeInternal, "write %s: %v", path, err))
	} else if file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644); err != nil {
		fail(failure(CodeInternal, "write %s: %v", path, err))
	}
	if file != nil {
		defer file.Close()
	}
	var total int64
	for {
		kind, payload, err := readFrame(conn)
		if err != nil {
			return failure(CodeBadRequest, "write %s: body ended early: %v", req.Path, err)
		}
		if kind == frameEnd {
			break
		}
		if kind != frameData {
			return failure(CodeBadRequest, "write %s: unexpected frame %q in the body", req.Path, kind)
		}
		if failed != nil {
			continue
		}
		total += int64(len(payload))
		if total > s.fileLimit() {
			fail(failure(CodeTooLarge, "write %s: body exceeds the %s files-API limit", req.Path, s.limitText()))
			continue
		}
		if _, err := file.Write(payload); err != nil {
			fail(failure(CodeInternal, "write %s: %v", path, err))
		}
	}
	if failed != nil {
		return *failed
	}
	if err := file.Close(); err != nil {
		return failure(CodeInternal, "write %s: %v", path, err)
	}
	return Result{}
}

func (s *Server) read(out *frameWriter, req Request) Result {
	path, err := s.safePath(req.Path)
	if err != nil {
		return failure(CodeBadRequest, "read %q: %v", req.Path, err)
	}
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return failure(CodeNotFound, "read %s: no such file", path)
	}
	if err != nil {
		return failure(CodeInternal, "read %s: %v", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return failure(CodeInternal, "read %s: %v", path, err)
	}
	if !info.Mode().IsRegular() {
		return failure(CodeBadRequest, "read %s: not a regular file", path)
	}
	limit := s.fileLimit()
	tooLarge := failure(CodeTooLarge, "read %s: file exceeds the %s files-API limit", path, s.limitText())
	if info.Size() > limit {
		return tooLarge
	}
	// One byte past the limit: a file that grew since the stat is still
	// refused rather than cut short.
	limited := io.LimitReader(file, limit+1)
	buf := make([]byte, chunkSize)
	var total int64
	for {
		n, err := limited.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > limit {
				return tooLarge
			}
			if werr := out.frame(frameData, buf[:n]); werr != nil {
				return failure(CodeInternal, "read %s: %v", path, werr)
			}
		}
		if err == io.EOF {
			return Result{}
		}
		if err != nil {
			return failure(CodeInternal, "read %s: %v", path, err)
		}
	}
}
