package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// HostFirewall blocks every host service reachable from the isolated bridge.
// Docker's internal bridge and disabled ICC cover routed/peer traffic; INPUT
// is the remaining host boundary. Only the proxy's gateway listeners pass.
// Bridge/chain names are daemon-owned, so other host traffic is unaffected.
type HostFirewall struct {
	lock *os.File

	Bridge, Gateway, Chain string
	Bin                    string
}

func (f HostFirewall) command(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bin := f.Bin
	if bin == "" {
		bin = "iptables"
	}
	out, err := exec.CommandContext(ctx, bin, append([]string{"-w", "3"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sandbox firewall: %s: %w", out, err)
	}
	return nil
}
func (f HostFirewall) ensure(args ...string) error {
	check := append([]string{"-C"}, args...)
	if f.command(check...) == nil {
		return nil
	}
	return f.command(append([]string{"-I"}, args...)...)
}
func (f *HostFirewall) Start() error {
	lock, err := os.OpenFile("/var/run/teploy-sandbox-egress.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return fmt.Errorf("egress bridge already owned: %w", err)
	}
	f.lock = lock
	if net.ParseIP(f.Gateway) == nil {
		return fmt.Errorf("invalid proxy gateway")
	}
	// Singleton bridge ownership permits clearing stale proxy-port grants.
	if err := f.command("-n", "-L", f.Chain); err != nil {
		if err := f.command("-N", f.Chain); err != nil {
			return err
		}
	}
	// Keep a deny rule in place while retiring stale port grants. Flushing
	// a chain already attached to INPUT would briefly expose host services.
	if err := f.command("-I", f.Chain, "-j", "DROP"); err != nil {
		return err
	}
	for n := 0; n < 65536; n++ {
		if err := f.command("-D", f.Chain, "2"); err != nil {
			break
		}
	}
	return f.ensure("INPUT", "-i", f.Bridge, "-j", f.Chain)
}
func (f HostFirewall) PermitPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid proxy port")
	}
	return f.ensure(f.Chain, "-d", f.Gateway, "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT")
}

func (f HostFirewall) RevokePort(port int) error {
	err := f.command("-D", f.Chain, "-d", f.Gateway, "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT")
	if err != nil {
		return errors.Join(err, f.command("-I", f.Chain, "-j", "DROP"))
	}
	return nil
}
func (f *HostFirewall) Close() {
	if f.lock != nil {
		f.lock.Close()
		f.lock = nil
	}
}
