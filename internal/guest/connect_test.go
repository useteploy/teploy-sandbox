//go:build unix

package guest

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// unixPairClient is pipeClient over a real socket pair, so half-closes
// and deadlines behave as on a vsock.
func unixPairClient(t *testing.T, srv *Server) *Client {
	t.Helper()
	return &Client{Dial: func(context.Context) (net.Conn, error) {
		a, b, err := socketPair()
		if err != nil {
			return nil, err
		}
		go srv.ServeConn(b)
		return a, nil
	}}
}

func socketPair() (net.Conn, net.Conn, error) {
	dir, err := tempSocketDir()
	if err != nil {
		return nil, nil, err
	}
	listener, err := net.Listen("unix", dir+"/s")
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	defer os.RemoveAll(dir)
	a, err := net.Dial("unix", dir+"/s")
	if err != nil {
		return nil, nil, err
	}
	return a, <-accepted, nil
}

// echoServer answers on 127.0.0.1 with what it reads, upper-cased, and
// closes its side once the client has half-closed.
func echoServer(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				data, _ := io.ReadAll(conn)
				_, _ = conn.Write(bytes.ToUpper(data))
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestConnectPipesBytesAndHalfCloses(t *testing.T) {
	port := echoServer(t)
	srv := &Server{WorkDir: t.TempDir()}
	client := unixPairClient(t, srv)
	conn, err := client.Connect(ctxT(t), port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello, guest")); err != nil {
		t.Fatal(err)
	}
	// The echo server answers only after it has seen the end of the
	// request: the half-close has to travel through the agent.
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "HELLO, GUEST" {
		t.Fatalf("got %q", got)
	}
}

func TestConnectRefusedWhenNothingListens(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	srv := &Server{WorkDir: t.TempDir()}
	_, err = pipeClient(srv).Connect(ctxT(t), port)
	if !IsCode(err, CodeRefused) {
		t.Fatalf("want %s, got %v", CodeRefused, err)
	}
}

func TestConnectTriesIPv6Loopback(t *testing.T) {
	var dialed []string
	srv := &Server{WorkDir: t.TempDir(), DialTCP: func(address string) (net.Conn, error) {
		dialed = append(dialed, address)
		if strings.HasPrefix(address, "127.") {
			return nil, errors.New("refused")
		}
		a, b := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, b) }()
		return a, nil
	}}
	conn, err := pipeClient(srv).Connect(ctxT(t), 3000)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if strings.Join(dialed, ",") != "127.0.0.1:3000,[::1]:3000" {
		t.Fatalf("dialed %v", dialed)
	}
}

func TestConnectNeedsVersion2AndOldOpsKeepVersion1(t *testing.T) {
	srv := &Server{WorkDir: t.TempDir(), Agent: "a"}
	ask := func(req Request) Result {
		client, server := net.Pipe()
		go srv.ServeConn(server)
		defer client.Close()
		if err := writeJSONFrame(client, frameRequest, req); err != nil {
			t.Fatal(err)
		}
		_, payload, err := readFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		var result Result
		if err := json.Unmarshal(payload, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if got := ask(Request{V: 1, Op: OpPing}); got.Code != "" || got.Agent != "a" {
		t.Fatalf("a version 1 ping is no longer answered: %+v", got)
	}
	if got := ask(Request{V: 2, Op: OpPing}); got.Code != "" {
		t.Fatalf("a version 2 ping is refused: %+v", got)
	}
	if got := ask(Request{V: 1, Op: OpConnect, Port: 1}); got.Code != CodeUnsupportedVersion {
		t.Fatalf("a version 1 connect is not refused: %+v", got)
	}
	if got := ask(Request{V: 3, Op: OpPing}); got.Code != CodeUnsupportedVersion || got.V != 2 {
		t.Fatalf("version 3 not refused with the agent's version: %+v", got)
	}
	if got := ask(Request{V: 2, Op: OpConnect, Port: 70000}); got.Code != CodeBadRequest {
		t.Fatalf("port 70000 accepted: %+v", got)
	}
}

// A daemon built with this package drives an agent built before version 2:
// every op but connect is sent as version 1, and connect gets a clear
// "unsupported version" from it.
func TestOldAgent(t *testing.T) {
	old := func(conn net.Conn) {
		defer conn.Close()
		_, payload, err := readFrame(conn)
		if err != nil {
			return
		}
		var req Request
		_ = json.Unmarshal(payload, &req)
		result := Result{V: 1, Agent: "old"}
		if req.V != 1 {
			result = Result{V: 1, Code: CodeUnsupportedVersion, Error: "protocol version 2 is not supported; this agent speaks 1"}
		}
		_ = writeJSONFrame(conn, frameResult, result)
	}
	client := &Client{Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go old(b)
		return a, nil
	}}
	if agent, err := client.Ping(ctxT(t)); err != nil || agent != "old" {
		t.Fatalf("ping of an old agent: %q %v", agent, err)
	}
	if _, err := client.Connect(ctxT(t), 3000); !IsCode(err, CodeUnsupportedVersion) {
		t.Fatalf("connect to an old agent: %v", err)
	}
}

func TestConnectResultDeadline(t *testing.T) {
	old := connectResultTimeout
	connectResultTimeout = 200 * time.Millisecond
	t.Cleanup(func() { connectResultTimeout = old })
	silent := &Client{Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, b) }()
		t.Cleanup(func() { b.Close() })
		return a, nil
	}}
	start := time.Now()
	_, err := silent.Connect(context.Background(), 3000)
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("a guest that never answers held the connect for %s: %v", time.Since(start), err)
	}
}

// A guest that sends a frame header promising a large payload and then
// nothing must not make the daemon allocate the promised size.
func TestBoundedFrameAllocatesOnlyWhatArrives(t *testing.T) {
	var header [5]byte
	header[0] = frameResult
	binary.BigEndian.PutUint32(header[1:], MaxV2Frame)
	read := func() {
		if _, _, err := readFrameBounded(bytes.NewReader(header[:]), MaxV2Frame); err == nil {
			t.Fatal("a frame with no payload was read")
		}
	}
	read()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	const rounds = 200
	for range rounds {
		read()
	}
	runtime.ReadMemStats(&after)
	if perRound := (after.TotalAlloc - before.TotalAlloc) / rounds; perRound > 8<<10 {
		t.Fatalf("each headers-only frame allocated %d bytes", perRound)
	}
	binary.BigEndian.PutUint32(header[1:], MaxV2Frame+1)
	if _, _, err := readFrameBounded(bytes.NewReader(header[:]), MaxV2Frame); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("an oversized frame was not refused: %v", err)
	}
	// A whole frame reads back exactly, and nothing after it is consumed.
	payload := bytes.Repeat([]byte("x"), 10000)
	var buf bytes.Buffer
	_ = writeFrame(&buf, frameResult, payload)
	buf.WriteString("raw")
	kind, got, err := readFrameBounded(&buf, MaxV2Frame)
	if err != nil || kind != frameResult || !bytes.Equal(got, payload) || buf.String() != "raw" {
		t.Fatalf("kind %q, %d bytes, err %v, left %q", kind, len(got), err, buf.String())
	}
}

func TestConnectCapAndRelease(t *testing.T) {
	port := echoServer(t)
	srv := &Server{WorkDir: t.TempDir(), MaxConnects: 1}
	client := pipeClient(srv)
	first, err := client.Connect(ctxT(t), port)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Connect(ctxT(t), port); !IsCode(err, CodeBusy) {
		t.Fatalf("second connect over the cap: %v", err)
	}
	first.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := client.Connect(ctxT(t), port)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the slot never came back: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A guest server that keeps its socket after the client half-closed, and
// never writes, gives its connect slot back after pipeLinger.
func TestConnectLingerReleasesTheSlot(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			t.Cleanup(func() { conn.Close() }) // held open, silent
		}
	}()
	srv := &Server{WorkDir: t.TempDir(), MaxConnects: 1, linger: 200 * time.Millisecond}
	client := unixPairClient(t, srv)
	conn, err := client.Connect(ctxT(t), listener.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.(*net.UnixConn).CloseWrite()
	deadline := time.Now().Add(10 * time.Second)
	for {
		srv.connectsMu.Lock()
		open := srv.connects
		srv.connectsMu.Unlock()
		if open == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a lingering stream kept its connect slot")
		}
		time.Sleep(20 * time.Millisecond)
	}
	conn.Close()
}

// tempSocketDir is a short directory for a unix socket (macOS caps socket
// paths at 104 bytes, which t.TempDir() can exceed).
func tempSocketDir() (string, error) {
	return os.MkdirTemp("/tmp", "gsock")
}
