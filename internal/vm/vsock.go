package vm

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// dialVsock connects to a guest vsock port through the hypervisor's unix
// socket. Cloud Hypervisor (like Firecracker) multiplexes the guest's
// ports over one socket: the host connects, sends "CONNECT <port>\n", and
// after an "OK <n>\n" line the stream is the guest connection.
func dialVsock(ctx context.Context, socketPath string, port uint32) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, err
	}
	// The handshake has no business taking long once the socket accepted;
	// a guest that is not listening yet answers by closing the stream.
	deadline := time.Now().Add(5 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vsock handshake: %w", err)
	}
	// Byte at a time: nothing past the newline may be consumed, it already
	// belongs to the guest stream.
	var line []byte
	one := make([]byte, 1)
	for {
		if _, err := conn.Read(one); err != nil {
			conn.Close()
			return nil, fmt.Errorf("vsock handshake: guest port %d not reachable: %w", port, err)
		}
		if one[0] == '\n' {
			break
		}
		if line = append(line, one[0]); len(line) > 64 {
			conn.Close()
			return nil, fmt.Errorf("vsock handshake: unexpected reply %q", line)
		}
	}
	if !strings.HasPrefix(string(line), "OK ") {
		conn.Close()
		return nil, fmt.Errorf("vsock handshake: unexpected reply %q", line)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
