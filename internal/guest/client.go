package guest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Client calls an agent. Every call dials its own connection.
type Client struct {
	// Dial opens a stream to the agent: the hypervisor's vsock socket in
	// production, anything connected to Server.ServeConn in tests.
	Dial func(ctx context.Context) (net.Conn, error)
	// FileTimeout bounds what the guest can make of a file call: a whole
	// ReadFile, and in a WriteFile each frame the guest has to take and
	// the wait for its answer (not the whole write: how fast the body
	// arrives is the caller's business). Zero means DefaultFileTimeout.
	FileTimeout time.Duration
}

// DefaultFileTimeout is generous for 64 MiB over a local socket and short
// against a guest that has stopped cooperating.
const DefaultFileTimeout = 2 * time.Minute

func (c *Client) fileTimeout() time.Duration {
	if c.FileTimeout > 0 {
		return c.FileTimeout
	}
	return DefaultFileTimeout
}

// call is one open request.
type call struct {
	ctx  context.Context
	conn net.Conn
	stop func() bool
}

func (c *Client) open(ctx context.Context, req Request) (*call, error) {
	conn, err := c.Dial(ctx)
	if err != nil {
		return nil, err
	}
	// Closing the connection is how a cancelled call is abandoned: the
	// agent sees it end and kills the command it was running for it.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	opened := &call{ctx: ctx, conn: conn, stop: stop}
	req.V = ProtocolVersion
	if err := writeJSONFrame(conn, frameRequest, req); err != nil {
		opened.close()
		return nil, opened.wrap(err)
	}
	return opened, nil
}

func (c *call) close() {
	c.stop()
	_ = c.conn.Close()
}

// wrap turns a stream error into the context's when the context is what
// ended the stream.
func (c *call) wrap(err error) error {
	if ctxErr := c.ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return fmt.Errorf("guest agent connection: %w", err)
}

// finish reads frames until the result, handing every other frame to on.
func (c *call) finish(on func(kind byte, payload []byte) error) (Result, error) {
	for {
		kind, payload, err := readFrame(c.conn)
		if err != nil {
			return Result{}, c.wrap(err)
		}
		if kind != frameResult {
			if on == nil {
				return Result{}, fmt.Errorf("guest agent sent an unexpected frame %q", kind)
			}
			if err := on(kind, payload); err != nil {
				return Result{}, err
			}
			continue
		}
		var result Result
		if err := json.Unmarshal(payload, &result); err != nil {
			return Result{}, fmt.Errorf("guest agent result is not JSON: %w", err)
		}
		if result.Code != "" {
			return result, &Error{Code: result.Code, Message: result.Error}
		}
		return result, nil
	}
}

func (c *Client) simple(ctx context.Context, req Request) (Result, error) {
	opened, err := c.open(ctx, req)
	if err != nil {
		return Result{}, err
	}
	defer opened.close()
	return opened.finish(nil)
}

// Ping reports the agent's version string once it answers.
func (c *Client) Ping(ctx context.Context) (string, error) {
	result, err := c.simple(ctx, Request{Op: OpPing})
	return result.Agent, err
}

// Sync flushes the guest's filesystems.
func (c *Client) Sync(ctx context.Context) error {
	_, err := c.simple(ctx, Request{Op: OpSync})
	return err
}

// Exec runs cmd through the guest's shell, streaming its output to the
// writers. timeout 0 is unbounded. A command the deadline ended reports
// timedOut with exit code 124 (or 137 when it had to be killed).
func (c *Client) Exec(ctx context.Context, cmd, cwd string, env map[string]string, timeout time.Duration, stdout, stderr io.Writer) (exitCode int, timedOut bool, err error) {
	opened, err := c.open(ctx, Request{Op: OpExec, Cmd: cmd, Cwd: cwd, Env: env, TimeoutMs: timeout.Milliseconds()})
	if err != nil {
		return -1, false, err
	}
	defer opened.close()
	result, err := opened.finish(func(kind byte, payload []byte) error {
		var w io.Writer
		switch kind {
		case frameStdout:
			w = stdout
		case frameStderr:
			w = stderr
		default:
			return fmt.Errorf("guest agent sent an unexpected frame %q during exec", kind)
		}
		if w == nil {
			return nil
		}
		// A writer that fails (the caller's stream is gone) ends the call;
		// closing the connection ends the command.
		_, werr := w.Write(payload)
		return werr
	})
	if err != nil {
		return -1, false, err
	}
	return result.ExitCode, result.TimedOut, nil
}

// WriteFile stores data at path, creating parent directories.
func (c *Client) WriteFile(ctx context.Context, path string, data io.Reader) error {
	opened, err := c.open(ctx, Request{Op: OpWrite, Path: path})
	if err != nil {
		return err
	}
	defer opened.close()
	// A guest that stops reading blocks the write, and one that never
	// answers blocks the read of its result; the request's context does
	// not end either (a server cannot see its client leave while the
	// request body is unread). The deadline moves with every frame.
	stall := c.fileTimeout()
	buf := make([]byte, chunkSize)
	for {
		n, rerr := data.Read(buf)
		if n > 0 {
			_ = opened.conn.SetWriteDeadline(time.Now().Add(stall))
			if err := writeFrame(opened.conn, frameData, buf[:n]); err != nil {
				return opened.wrap(err)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			// The connection closes without an end frame, so the agent
			// knows the body is incomplete.
			return fmt.Errorf("write file: read body: %w", rerr)
		}
	}
	_ = opened.conn.SetDeadline(time.Now().Add(stall))
	if err := writeFrame(opened.conn, frameEnd, nil); err != nil {
		return opened.wrap(err)
	}
	_, err = opened.finish(nil)
	return err
}

// ReadFile returns the file at path, refusing one above MaxFileBytes.
func (c *Client) ReadFile(ctx context.Context, path string) ([]byte, error) {
	// The guest has the file at hand, so the whole read gets one deadline:
	// a per-frame one would let it send a byte at a time for ever.
	ctx, cancel := context.WithTimeout(ctx, c.fileTimeout())
	defer cancel()
	opened, err := c.open(ctx, Request{Op: OpRead, Path: path})
	if err != nil {
		return nil, err
	}
	defer opened.close()
	var data []byte
	_, err = opened.finish(func(kind byte, payload []byte) error {
		if kind != frameData {
			return fmt.Errorf("guest agent sent an unexpected frame %q during read", kind)
		}
		if len(payload) == 0 {
			// The agent never sends one, and an endless run of them would
			// otherwise pass every limit here.
			return errors.New("guest agent sent an empty data frame during read")
		}
		if len(data)+len(payload) > MaxFileBytes {
			return errors.New("guest agent sent more than the files-API limit")
		}
		data = append(data, payload...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if data == nil {
		data = []byte{}
	}
	return data, nil
}
