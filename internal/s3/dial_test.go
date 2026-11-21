package s3

import (
	"context"
	"net"
)

// dialTo sends every connection to one address, whatever host was asked
// for: a test's stand-in for DNS.
func dialTo(address string) func(ctx context.Context, network, _ string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, address)
	}
}
