//go:build vmintegration

// Live checks of guest networking: what a guest that controls its own
// kernel can and cannot reach on each tier, from inside real VMs.
//
// The suite builds its own "rest of the network" so that every refusal
// has a control beside it: a network namespace on the host (the peer)
// that answers on private, shared, link-local and benchmarking addresses,
// and a listener on the host itself (the canary) bound to every address.
// A guest failing to reach something only counts when the same thing was
// reached from somewhere that is allowed to.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/vm"
)

const (
	peerNS       = "tsbxpeer"
	peerHostLink = "tsbxpeer0"
	// peerHostAddr is the host's own address on the link to the peer: a
	// private address that is the host itself.
	peerHostAddr = "172.30.77.1"
	peerAddr     = "172.30.77.2"
	peerHTTP     = 8080
	peerUDP      = 9100
)

// peerAddrs is where the peer answers: one address in each kind of range
// that is not the public internet.
var peerAddrs = map[string]string{
	"private (172.16/12)":      peerAddr,
	"private (10/8)":           "10.77.0.1",
	"private (192.168/16)":     "192.168.77.1",
	"shared (100.64/10)":       "100.64.77.1",
	"link-local and metadata":  "169.254.169.254",
	"benchmarking (198.18/15)": "198.18.77.1",
}

// listenPy logs every TCP connection and UDP datagram it gets.
const listenPy = `import socket, sys, threading
log, ports = sys.argv[1], [int(p) for p in sys.argv[2:]]
lock = threading.Lock()
def note(line):
    with lock:
        with open(log, "a") as f:
            f.write(line + "\n")
def tcp(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(64)
    while True:
        c, peer = s.accept(); note("tcp %d from %s" % (port, peer[0]))
        try: c.sendall(b"hello\n")
        except OSError: pass
        c.close()
def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", port))
    while True:
        data, peer = s.recvfrom(2048); note("udp %d from %s %s" % (port, peer[0], data.decode(errors="replace").strip()))
for p in ports:
    threading.Thread(target=tcp, args=(p,), daemon=True).start()
    threading.Thread(target=udp, args=(p,), daemon=True).start()
note("ready")
threading.Event().wait()
`

// framePy sends one hand-made frame from a guest: whatever source MAC and
// address the caller says, which is the point.
const framePy = `import socket, struct, sys
def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff
def mac(s): return bytes.fromhex(s.replace(":", ""))
kind, dev = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((dev, 0))
if kind == "udp":
    smac, dmac, sip, dip, dport, payload = sys.argv[3:9]
    data = payload.encode()
    udp = struct.pack("!HHHH", 40000, int(dport), 8 + len(data), 0) + data
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, socket.inet_aton(sip), socket.inet_aton(dip))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    s.send(mac(dmac) + mac(smac) + b"\x08\x00" + ip + udp)
elif kind == "arp":
    smac, dmac, op, sha, spa, tha, tpa = sys.argv[3:10]
    s.send(mac(dmac) + mac(smac) + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, int(op)) + mac(sha) + socket.inet_aton(spa) + mac(tha) + socket.inet_aton(tpa))
`

func hostTry(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func hostRun(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := hostTry(name, args...)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

// netPeer is the suite's stand-in for the networks around the host.
type netPeer struct {
	dir string
	log string
}

func (p *netPeer) received() string {
	raw, _ := os.ReadFile(p.log)
	return string(raw)
}

// startPeer makes the peer namespace: a neighbour of the host that serves
// HTTP on 8080 (with a 1 GiB file for throughput), accepts TCP on 25 and
// logs UDP on 9100, on every address in peerAddrs.
func startPeer(t *testing.T) *netPeer {
	t.Helper()
	_, _ = hostTry("ip", "netns", "del", peerNS)
	_, _ = hostTry("ip", "link", "del", peerHostLink)
	hostRun(t, "ip", "netns", "add", peerNS)
	peer := &netPeer{dir: t.TempDir()}
	peer.log = filepath.Join(peer.dir, "received.log")
	var processes []*exec.Cmd
	t.Cleanup(func() {
		for _, process := range processes {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
		_, _ = hostTry("ip", "netns", "del", peerNS)
		_, _ = hostTry("ip", "link", "del", peerHostLink)
	})
	inPeer := func(args ...string) { hostRun(t, "ip", append([]string{"netns", "exec", peerNS}, args...)...) }
	hostRun(t, "ip", "link", "add", peerHostLink, "type", "veth", "peer", "name", "peer0", "netns", peerNS)
	hostRun(t, "ip", "addr", "add", peerHostAddr+"/30", "dev", peerHostLink)
	hostRun(t, "ip", "link", "set", peerHostLink, "up")
	inPeer("ip", "link", "set", "lo", "up")
	inPeer("ip", "addr", "add", peerAddr+"/30", "dev", "peer0")
	inPeer("ip", "link", "set", "peer0", "up")
	inPeer("ip", "route", "add", "default", "via", peerHostAddr)
	for _, addr := range peerAddrs {
		if addr != peerAddr {
			inPeer("ip", "addr", "add", addr+"/32", "dev", "lo")
			hostRun(t, "ip", "route", "add", addr+"/32", "via", peerAddr)
		}
	}
	web := filepath.Join(peer.dir, "web")
	if err := os.Mkdir(web, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(web, "hello.txt"), []byte("peer-ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Sparse: a gigabyte to send that takes no disk.
	if err := os.Truncate(createFile(t, filepath.Join(web, "blob")), 1<<30); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(peer.dir, "listen.py")
	if err := os.WriteFile(script, []byte(listenPy), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"python3", "-m", "http.server", strconv.Itoa(peerHTTP), "--bind", "0.0.0.0", "--directory", web},
		{"python3", script, peer.log, "25", strconv.Itoa(peerUDP)},
	} {
		process := exec.Command("ip", append([]string{"netns", "exec", peerNS}, args...)...)
		if err := process.Start(); err != nil {
			t.Fatal(err)
		}
		processes = append(processes, process)
	}
	// The control for every "a guest cannot reach it": the host can.
	deadline := time.Now().Add(20 * time.Second)
	for name, addr := range peerAddrs {
		for {
			out, err := hostTry("curl", "-s", "--max-time", "2", fmt.Sprintf("http://%s:%d/hello.txt", addr, peerHTTP))
			if err == nil && out == "peer-ok" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the peer does not answer on its %s address %s: %v %s", name, addr, err, out)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	if conn, err := net.DialTimeout("tcp", peerAddr+":25", 5*time.Second); err != nil {
		t.Fatalf("the peer does not accept on port 25: %v", err)
	} else {
		conn.Close()
	}
	return peer
}

func createFile(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	return path
}

// canary is a service on the host itself, bound to every address, TCP and
// UDP on one port: what the daemon's API or an SSH daemon is to a guest.
type canary struct {
	port     int
	tcp, udp atomic.Int64
}

func startCanary(t *testing.T) *canary {
	t.Helper()
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &canary{port: listener.Addr().(*net.TCPAddr).Port}
	packets, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", c.port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close(); packets.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			c.tcp.Add(1)
			conn.Close()
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := packets.ReadFrom(buf); err != nil {
				return
			}
			c.udp.Add(1)
		}
	}()
	// The control: a neighbour that is not a guest reaches it, on the
	// host's address facing that neighbour.
	hostRun(t, "ip", "netns", "exec", peerNS, "python3", "-c", fmt.Sprintf(
		`import socket; socket.create_connection(("%[1]s", %[2]d), 5).close(); socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("%[1]s", %[2]d))`, peerHostAddr, c.port))
	deadline := time.Now().Add(5 * time.Second)
	for c.tcp.Load() != 1 || c.udp.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("the canary was not reached by its control: tcp %d udp %d", c.tcp.Load(), c.udp.Load())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return c
}

// untouched fails the test if anything reached the canary since its
// control did.
func (c *canary) untouched(t *testing.T, when string) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	if c.tcp.Load() != 1 || c.udp.Load() != 1 {
		t.Fatalf("%s: a guest reached a service on the host itself (tcp connections %d, udp datagrams %d; want only the control's 1 and 1)", when, c.tcp.Load(), c.udp.Load())
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// netNames is what the driver names things for this suite's identity:
// each run's network namespace, the tap inside it, the host's end of an
// open run's link, and the host's table.
type netNames struct{ nsPrefix, tapPrefix, linkPrefix, table string }

func namesFor(config vm.Config) netNames {
	return netNames{nsPrefix: "tvn" + config.Owner[:6] + "-", tapPrefix: "tv" + config.Owner[:6] + "-",
		linkPrefix: "tvh" + config.Owner[:6] + "-", table: "teploy_sbx_vm_" + config.Owner[:8]}
}

// runTable is the name of the tables inside a run's namespace.
const runTable = "guest"

// links lists the host's interfaces that are this suite's: the host's
// ends of open runs' links, and any tap, which no longer belongs on the
// host at all.
func (n netNames) links(t *testing.T) []string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, each := range interfaces {
		if strings.HasPrefix(each.Name, n.linkPrefix) || strings.HasPrefix(each.Name, n.tapPrefix) {
			names = append(names, each.Name)
		}
	}
	slices.Sort(names)
	return names
}

// namespaces lists this suite's run namespaces.
func (n netNames) namespaces(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("/run/netns")
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), n.nsPrefix) {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	return names
}

// inNS runs a command in a network namespace.
func inNS(t *testing.T, ns string, args ...string) string {
	t.Helper()
	return hostRun(t, "ip", append([]string{"netns", "exec", ns}, args...)...)
}

func tryNS(ns string, args ...string) (string, error) {
	return hostTry("ip", append([]string{"netns", "exec", ns}, args...)...)
}

// guestNIC is a guest's network device as the guest sees it, and where
// the host keeps its other end: the run's namespace, the tap in it, and
// for an open run the host's end of the link out of it.
type guestNIC struct {
	dev, addr, mac, gateway, gatewayMAC string
	ns, tap, link                       string
}

func sh(t *testing.T, manager *run.Manager, id, cmd string) vmExec {
	t.Helper()
	return vmRun(t, manager, id, cmd, "", nil, 120*time.Second)
}

func inspectNIC(t *testing.T, manager *run.Manager, id string) guestNIC {
	t.Helper()
	out := sh(t, manager, id, `dev=$(ip -4 -o addr show scope global | awk '{print $2; exit}')
echo "$dev $(ip -4 -o addr show dev "$dev" | awk '{print $4}') $(cat /sys/class/net/$dev/address) $(ip neigh show dev "$dev" | awk '/PERMANENT/ {print $1, $3; exit}')"`)
	fields := strings.Fields(out.stdout)
	if len(fields) != 5 {
		t.Fatalf("the guest's network device: %q %q", out.stdout, out.stderr)
	}
	nic := guestNIC{dev: fields[0], addr: strings.TrimSuffix(fields[1], "/32"), mac: fields[2], gateway: fields[3], gatewayMAC: fields[4]}
	if !strings.HasSuffix(fields[1], "/32") {
		t.Fatalf("the guest's address is %s, want a /32", fields[1])
	}
	// The run's namespace is the one that routes the guest's address to
	// a tap.
	for _, ns := range namesFor(vmTestConfig(t)).namespaces(t) {
		routes, _ := tryNS(ns, "ip", "-4", "-o", "route", "show", nic.addr)
		if match := regexp.MustCompile(` dev (\S+)`).FindStringSubmatch(routes); match != nil {
			nic.ns, nic.tap = ns, match[1]
		}
	}
	if nic.ns == "" {
		t.Fatalf("no namespace routes the guest's address %s", nic.addr)
	}
	slot := nic.tap[strings.LastIndex(nic.tap, "-")+1:]
	if want := namesFor(vmTestConfig(t)).nsPrefix + slot; nic.ns != want {
		t.Fatalf("the tap %s is in %s, want %s", nic.tap, nic.ns, want)
	}
	nic.link = namesFor(vmTestConfig(t)).linkPrefix + slot
	// The tap is in the run's namespace and not on the host.
	if _, err := hostTry("ip", "link", "show", "dev", nic.tap); err == nil {
		t.Fatalf("the tap %s is an interface of the host", nic.tap)
	}
	return nic
}

// installTools puts the suite's scripts in a guest.
func installTools(t *testing.T, manager *run.Manager, id string) {
	t.Helper()
	for name, content := range map[string]string{"frame.py": framePy, "listen.py": listenPy} {
		if err := manager.WriteFile(context.Background(), id, run.LeaseCredential{}, run.WorkDir+"/"+name, strings.NewReader(content)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

// reaches reports whether a guest gets the peer's page from addr. With
// direct, the guest's proxy settings are ignored.
func reaches(t *testing.T, manager *run.Manager, id, addr string, direct bool) bool {
	t.Helper()
	flags := ""
	if direct {
		flags = "--noproxy '*' "
	}
	out := sh(t, manager, id, fmt.Sprintf("curl -s %s--connect-timeout 3 --max-time 6 http://%s:%d/hello.txt", flags, addr, peerHTTP))
	return out.code == 0 && out.stdout == "peer-ok"
}

// hostProbe has a guest try the host itself: TCP to the canary's port and
// to SSH, UDP to the canary's port, and a ping, on each of the host's
// addresses. It returns what answered, which must be nothing.
func hostProbe(t *testing.T, manager *run.Manager, id string, c *canary, targets []string) string {
	t.Helper()
	script := fmt.Sprintf(`for t in %s; do
  for p in %d 22; do (nc -z -w 3 $t $p >/dev/null 2>&1 && echo "OPEN tcp $t:$p") & done
  (ping -c 1 -W 3 $t >/dev/null 2>&1 && echo "OPEN icmp $t") &
  (echo canary | nc -u -w 1 $t %d >/dev/null 2>&1) &
done; wait`, strings.Join(targets, " "), c.port, c.port)
	return strings.TrimSpace(sh(t, manager, id, script).stdout)
}

// guestHasIPv6 reports whether the guest's kernel has IPv6 at all. The
// kernel the README prescribes does not, and a guest without it cannot
// send an IPv6 packet: the IPv6 checks are then not applicable, which
// the tests say in their log rather than skip.
func guestHasIPv6(t *testing.T, manager *run.Manager, id string) bool {
	t.Helper()
	out := sh(t, manager, id, `if [ -d /proc/sys/net/ipv6 ]; then echo yes; else echo no; fi`)
	switch strings.TrimSpace(out.stdout) {
	case "yes":
		return true
	case "no":
		return false
	}
	t.Fatalf("whether guest %s has IPv6: %+v", id, out)
	return false
}

// hostAddress is the address the host uses towards the internet.
func hostAddress(t *testing.T) string {
	t.Helper()
	out := hostRun(t, "ip", "-4", "-o", "route", "get", "198.51.100.1")
	match := regexp.MustCompile(` src (\S+)`).FindStringSubmatch(out)
	if match == nil {
		t.Fatalf("the host's own address: %s", out)
	}
	return match[1]
}

// hostBroadcasts is the broadcast addresses the host's kernel takes for
// its own, loopback's aside: one per subnet the host is on.
func hostBroadcasts(t *testing.T) []string {
	t.Helper()
	var found []string
	for _, line := range strings.Split(hostRun(t, "ip", "-4", "route", "show", "table", "local", "type", "broadcast"), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "broadcast" && !strings.HasPrefix(fields[1], "127.") && !slices.Contains(found, fields[1]) {
			found = append(found, fields[1])
		}
	}
	if len(found) < 2 {
		t.Fatalf("the host's broadcast addresses (its own subnet's and the peer link's): %v", found)
	}
	return found
}

func setElements(t *testing.T, names netNames, set string) string {
	t.Helper()
	return hostRun(t, "nft", "list", "set", "inet", names.table, set)
}

// assertNoNetworkLeft checks that nothing of any run is left on the host:
// no namespace, no link, no admission, no route.
func assertNoNetworkLeft(t *testing.T, names netNames) {
	t.Helper()
	if left := names.namespaces(t); len(left) != 0 {
		t.Errorf("run namespaces left behind: %v", left)
	}
	if left := names.links(t); len(left) != 0 {
		t.Errorf("links or taps left behind on the host: %v", left)
	}
	if listing := setElements(t, names, "open"); strings.Contains(listing, "elements") {
		t.Errorf("the open set still admits something:\n%s", listing)
	}
	if _, err := hostTry("nft", "list", "table", "netdev", names.table); err == nil {
		t.Errorf("a netdev table of the driver is on the host")
	}
	if routes := hostRun(t, "ip", "-4", "route", "show"); strings.Contains(routes, names.linkPrefix) || strings.Contains(routes, names.tapPrefix) {
		t.Errorf("routes to guests left behind:\n%s", routes)
	}
}

func setupTimings(t *testing.T, logs *syncBuffer) {
	t.Helper()
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "vm proxy listener ready") {
			if host := regexp.MustCompile(`hostSetup=(\S+)`).FindStringSubmatch(line); host != nil {
				t.Logf("timing: an allowlist run's namespace and proxy listener, made before its VM: %s", host[1])
			}
		}
		if strings.Contains(line, "vm network device ready") {
			tier := regexp.MustCompile(`tier=(\S+)`).FindStringSubmatch(line)
			host := regexp.MustCompile(`hostSetup=(\S+)`).FindStringSubmatch(line)
			guest := regexp.MustCompile(`guestSetup=(\S+)`).FindStringSubmatch(line)
			if tier != nil && host != nil && guest != nil {
				t.Logf("timing: network setup for a %-9s run: host side (namespace, tap, sysctls, rulesets, routes) %s, guest side (address, routes, resolver) %s", tier[1], host[1], guest[1])
			}
		}
	}
}

// download has a guest fetch the peer's 1 GiB file and returns MB/s.
func download(t *testing.T, manager *run.Manager, id string) float64 {
	t.Helper()
	out := sh(t, manager, id, fmt.Sprintf("curl -s -o /dev/null --max-time 60 -w '%%{speed_download} %%{size_download}' http://%s:%d/blob", peerAddr, peerHTTP))
	fields := strings.Fields(out.stdout)
	if out.code != 0 || len(fields) != 2 || fields[1] != strconv.Itoa(1<<30) {
		t.Fatalf("download: exit %d %q %q", out.code, out.stdout, out.stderr)
	}
	speed, _ := strconv.ParseFloat(fields[0], 64)
	return speed / (1 << 20)
}

// TestVMNetworkIsolation is what a hostile guest cannot do, on a driver
// whose open tier also reaches private ranges (--vm-open-private): the
// widest setting, so that every control (the peer is a private address)
// succeeds and every refusal is the firewall's and not a missing route.
func TestVMNetworkIsolation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := vmTestConfig(t)
	config.OpenPrivate = true
	// The throughput at the end is the path's, not the limit's; the
	// limit has a test of its own (TestVMLimits).
	config.NetMbit = -1
	names := namesFor(config)
	ctx := context.Background()
	peer := startPeer(t)
	guard := startCanary(t)
	var logs syncBuffer
	manager, _, _, _ := newVMManagerLogging(t, config, t.TempDir(), &logs)
	baseline := poolListing(t, config.Pool)

	create := func(req run.CreateRequest) string {
		t.Helper()
		req.Image, req.Limits = vm.GoldenImage, &run.Limits{MemoryMB: 512, CPUs: 1}
		created, err := manager.Create(ctx, req)
		if err != nil {
			t.Fatalf("create %s: %v", req.Network, err)
		}
		t.Cleanup(func() { _ = manager.Destroy(context.Background(), created.ID) })
		installTools(t, manager, created.ID)
		return created.ID
	}
	a := create(run.CreateRequest{Network: "open"})
	b := create(run.CreateRequest{Network: "open"})
	c := create(run.CreateRequest{Network: "allowlist", EgressAllow: []string{fmt.Sprintf("%s:%d", peerAddr, peerHTTP)}})
	nicA, nicB, nicC := inspectNIC(t, manager, a), inspectNIC(t, manager, b), inspectNIC(t, manager, c)
	t.Logf("guest a %s in %s, guest b %s in %s, guest c (allowlist) %s in %s; gateway %s", nicA.addr, nicA.ns, nicB.addr, nicB.ns, nicC.addr, nicC.ns, nicA.gateway)
	if nicA.addr == nicB.addr || nicA.ns == nicB.ns || nicA.mac == nicB.mac || nicA.gateway != nicB.gateway {
		t.Fatalf("two runs share an address, a namespace or a MAC: %+v %+v", nicA, nicB)
	}
	// What is where: an open run's namespace has its tap and one link
	// out; an allowlist run's has its tap and nothing else; the host has
	// the open runs' links and no tap.
	for nic, want := range map[guestNIC][]string{nicA: {"lo", nicA.tap, "uplink"}, nicB: {"lo", nicB.tap, "uplink"}, nicC: {"lo", nicC.tap}} {
		var got []string
		for _, line := range strings.Split(inNS(t, nic.ns, "ip", "-o", "link", "show"), "\n") {
			if fields := strings.Fields(line); len(fields) > 1 {
				got = append(got, strings.TrimSuffix(strings.Split(fields[1], "@")[0], ":"))
			}
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("interfaces in %s: %v, want %v", nic.ns, got, want)
		}
	}
	if got, want := names.links(t), []string{nicA.link, nicB.link}; !slices.Equal(got, want) {
		t.Fatalf("the suite's interfaces on the host: %v, want the two open runs' links %v", got, want)
	}
	hostAddr := hostAddress(t)
	hostTargets := []string{nicA.gateway, hostAddr, peerHostAddr}

	// --- controls: the open guests do have a network, so what follows is
	// refused and not merely broken
	for name, id := range map[string]string{"a": a, "b": b} {
		if !reaches(t, manager, id, peerAddr, false) {
			t.Fatalf("control: open guest %s cannot reach the peer at all", name)
		}
	}
	if !reaches(t, manager, c, peerAddr, false) {
		t.Fatal("control: the allowlist guest cannot reach its allowlisted peer through its proxy")
	}

	// --- 1: guest to guest, by every means a guest has
	//
	// The IPv6 part needs a guest kernel with IPv6. The kernel the README
	// prescribes (Cloud Hypervisor's ch_defconfig) has none: such a guest
	// cannot send IPv6 at all, so there is nothing of it to refuse, and
	// the IPv4 and layer 2 checks run without it. The host side drops
	// IPv6 from a guest that has it either way (the tap's ingress takes
	// ARP and IPv4 only; the namespace's chains drop every other family).
	ipv6 := guestHasIPv6(t, manager, a) && guestHasIPv6(t, manager, b)
	if !ipv6 {
		t.Logf("not applicable: the guest kernel has no IPv6 (no /proc/sys/net/ipv6), so the guest-to-guest IPv6 checks do not run; the IPv4, ARP and layer 2 checks do")
	}
	isolation := func(when string) {
		t.Helper()
		// The target listens on TCP and UDP, has IPv6 up (where its
		// kernel has IPv6), and can reach its own listener: only the
		// path from another guest is missing.
		control := `rm -f /work/recv.log; (setsid python3 /work/listen.py /work/recv.log 9000 >/dev/null 2>&1 &)
for i in $(seq 50); do grep -q ready /work/recv.log 2>/dev/null && break; sleep 0.1; done
`
		if ipv6 {
			control += `echo 0 > /proc/sys/net/ipv6/conf/` + nicB.dev + `/disable_ipv6; sleep 3
nc -z -w 2 ` + nicB.addr + ` 9000 && ip -6 -o addr show dev ` + nicB.dev + ` scope link | awk '{print $4}' | cut -d/ -f1`
		} else {
			control += `nc -z -w 2 ` + nicB.addr + ` 9000`
		}
		listening := sh(t, manager, b, control)
		linkLocal := strings.TrimSpace(listening.stdout)
		if listening.code != 0 || (ipv6 && !strings.HasPrefix(linkLocal, "fe80:")) {
			t.Fatalf("%s: control: guest b's listener or link-local address: %d %q %q", when, listening.code, listening.stdout, listening.stderr)
		}
		attack := fmt.Sprintf(`b=%[1]s; bmac=%[2]s; dev=%[3]s; me=%[4]s; mymac=%[5]s; gw=%[6]s; gwmac=%[7]s
(ping -c 2 -W 2 $b >/dev/null 2>&1 && echo "OPEN icmp") &
(nc -z -w 3 $b 9000 >/dev/null 2>&1 && echo "OPEN tcp") &
(echo routed | nc -u -w 1 $b 9000 >/dev/null 2>&1) &
wait
# straight at the other guest's MAC, and at everyone
python3 /work/frame.py udp $dev $mymac $bmac $me $b 9000 direct-l2
python3 /work/frame.py udp $dev $mymac ff:ff:ff:ff:ff:ff $me $b 9000 broadcast-l2
python3 /work/frame.py udp $dev $mymac ff:ff:ff:ff:ff:ff $me 255.255.255.255 9000 broadcast-ip
python3 /work/frame.py udp $dev $mymac 01:00:5e:00:00:01 $me 224.0.0.1 9000 multicast
# ARP: claim the other guest's address, and the gateway's
python3 /work/frame.py arp $dev $mymac ff:ff:ff:ff:ff:ff 2 $mymac $b ff:ff:ff:ff:ff:ff $b
python3 /work/frame.py arp $dev $mymac ff:ff:ff:ff:ff:ff 1 $mymac $b 00:00:00:00:00:00 $gw
python3 /work/frame.py arp $dev $mymac $gwmac 2 $mymac $b $gwmac $gw
python3 /work/frame.py arp $dev $mymac ff:ff:ff:ff:ff:ff 2 $mymac $gw ff:ff:ff:ff:ff:ff $gw
# take the other guest's address as a second one and use it
ip addr add $b/32 dev $dev
(curl -s --interface $b --connect-timeout 3 --max-time 4 http://%[8]s:%[9]d/hello.txt >/dev/null 2>&1 && echo "OPEN as the other guest's address")
(nc -z -w 3 -s $b $b 9000 >/dev/null 2>&1 && echo "OPEN tcp from the other guest's address")
ip addr del $b/32 dev $dev
`, nicB.addr, nicB.mac, nicA.dev, nicA.addr, nicA.mac, nicA.gateway, nicA.gatewayMAC, peerAddr, peerHTTP)
		if ipv6 {
			attack += fmt.Sprintf(`dev=%[1]s
# IPv6: link-local needs no configuration from anyone
echo 0 > /proc/sys/net/ipv6/conf/$dev/disable_ipv6; sleep 3
own=$(ip -6 -o addr show dev $dev scope link | awk '{print $4}' | cut -d/ -f1)
[ -n "$own" ] || echo "no link-local address of my own: nothing was tested"
(ping -6 -c 2 -W 2 %[2]s%%$dev >/dev/null 2>&1 && echo "OPEN icmp6 link-local") &
(nc -6 -z -w 3 %[2]s%%$dev 9000 >/dev/null 2>&1 && echo "OPEN tcp6 link-local") &
# all nodes and all routers: a guest hears its own echo and nobody else's
(ping -6 -c 2 -W 2 ff02::1%%$dev 2>/dev/null | grep "bytes from" | grep -v "from $own" | sed 's/^/ANSWER all-nodes: /') &
(ping -6 -c 2 -W 2 ff02::2%%$dev 2>/dev/null | grep "bytes from" | grep -v "from $own" | sed 's/^/ANSWER all-routers: /') &
wait
echo 1 > /proc/sys/net/ipv6/conf/$dev/disable_ipv6
`, nicA.dev, linkLocal)
		}
		attack += "true"
		out := sh(t, manager, a, attack)
		if got := strings.TrimSpace(out.stdout); got != "" {
			t.Fatalf("%s: guest a reached guest b, or something answered on IPv6:\n%s\n%s", when, got, out.stderr)
		}
		// From the allowlist guest too, which has no route but can make one.
		out = sh(t, manager, c, fmt.Sprintf(`ip route replace default via %s dev %s; (ping -c 1 -W 2 %[3]s >/dev/null 2>&1 && echo "OPEN icmp"); (nc -z -w 3 %[3]s 9000 >/dev/null 2>&1 && echo "OPEN tcp"); echo routed-c | nc -u -w 1 %[3]s 9000 >/dev/null 2>&1; ip route del default; true`, nicC.gateway, nicC.dev, nicB.addr))
		if strings.TrimSpace(out.stdout) != "" {
			t.Fatalf("%s: the allowlist guest reached guest b: %s", when, out.stdout)
		}
		received := sh(t, manager, b, `sleep 1; grep -v -e ready -e "from `+nicB.addr+`" /work/recv.log; pkill -f '[l]isten.py'; [ ! -d /proc/sys/net/ipv6 ] || echo 1 > /proc/sys/net/ipv6/conf/`+nicB.dev+`/disable_ipv6; true`)
		if strings.TrimSpace(received.stdout) != "" {
			t.Fatalf("%s: guest b received something from another guest:\n%s", when, received.stdout)
		}
		// The idea of who has which address, in each run's namespace, did
		// not move, and the attacked guest still has its network.
		for _, nic := range []guestNIC{nicA, nicB} {
			if got, want := inNS(t, nic.ns, "ip", "-4", "neigh", "show", "dev", nic.tap), nic.addr+" lladdr "+nic.mac+" PERMANENT"; strings.TrimSpace(got) != want {
				t.Fatalf("%s: the neighbours on %s: %q, want only %q", when, nic.tap, got, want)
			}
			// No IPv6 on the other side of a tap, whatever the guest sends.
			if got := inNS(t, nic.ns, "ip", "-6", "addr", "show"); got != "" {
				t.Fatalf("%s: there is an IPv6 address in %s: %s", when, nic.ns, got)
			}
		}
		if !reaches(t, manager, b, peerAddr, false) {
			t.Fatalf("%s: guest b lost its network after guest a's ARP claims", when)
		}
	}
	isolation("guest to guest")

	// --- 2: guest to the host itself, on every address the host has
	hostIsClosed := func(when string) {
		t.Helper()
		for name, id := range map[string]string{"open guest a": a, "allowlist guest c": c} {
			if got := hostProbe(t, manager, id, guard, hostTargets); got != "" {
				t.Fatalf("%s: %s reached the host itself:\n%s", when, name, got)
			}
		}
		guard.untouched(t, when)
	}
	hostIsClosed("guest to host")
	// The one exception, and only for the run it belongs to: the
	// allowlist run's own proxy port on the gateway.
	proxyURL := strings.TrimSpace(sh(t, manager, c, `printf %s "$HTTP_PROXY"`).stdout)
	proxyPort := proxyURL[strings.LastIndex(proxyURL, ":")+1:]
	if out := sh(t, manager, c, "nc -z -w 3 "+nicC.gateway+" "+proxyPort); out.code != 0 {
		t.Fatalf("the allowlist guest cannot connect to its own proxy port %s", proxyPort)
	}
	for name, id := range map[string]string{"open guest a": a, "open guest b": b} {
		if out := sh(t, manager, id, "nc -z -w 3 "+nicA.gateway+" "+proxyPort); out.code == 0 {
			t.Fatalf("%s connected to another run's proxy port", name)
		}
	}
	// The port on the gateway is all it has: the same port on another of
	// the host's addresses stays closed.
	if out := sh(t, manager, c, "nc -z -w 3 "+hostAddr+" "+proxyPort); out.code == 0 {
		t.Fatal("the allowlist guest reached its proxy port on another of the host's addresses")
	}

	// --- 3: ranges. Even with private ranges opened, link-local (where
	// metadata services are) stays closed, and so does port 25.
	if !reaches(t, manager, a, "10.77.0.1", false) || !reaches(t, manager, a, "100.64.77.1", false) {
		t.Fatal("--vm-open-private: an open guest cannot reach the peer's private and shared addresses")
	}
	if reaches(t, manager, a, "169.254.169.254", false) {
		t.Fatal("an open guest reached the link-local metadata address")
	}
	if out := sh(t, manager, a, "nc -z -w 3 "+peerAddr+" 25"); out.code == 0 {
		t.Fatal("an open guest connected to port 25")
	}
	if out := sh(t, manager, a, fmt.Sprintf("nc -z -w 3 %s %d", peerAddr, peerHTTP)); out.code != 0 {
		t.Fatal("control: the same peer on another port is not reachable")
	}
	// One connection on port 25 ever reached the peer: startPeer's control.
	if strings.Count(peer.received(), "tcp 25 from") != 1 {
		t.Fatalf("connections on port 25 at the peer:\n%s", peer.received())
	}

	// --- 4: spoofed sources, at the tap
	spoof := fmt.Sprintf(`f="python3 /work/frame.py udp %[1]s"; gwmac=%[2]s; peer=%[3]s; port=%[4]d
$f %[5]s $gwmac %[6]s $peer $port legit
$f 02:54:de:ad:be:ef $gwmac %[6]s $peer $port spoofed-mac
$f %[7]s $gwmac %[6]s $peer $port spoofed-mac-of-the-other-guest
$f %[5]s $gwmac %[8]s $peer $port spoofed-address-of-the-other-guest
$f %[5]s $gwmac 10.209.99.99 $peer $port spoofed-address-in-the-subnet
$f %[5]s $gwmac 198.51.100.7 $peer $port spoofed-address-outside
$f %[5]s $gwmac %[9]s $peer $port spoofed-address-of-the-host
$f %[5]s $gwmac %[10]s $peer $port spoofed-address-of-the-gateway
$f %[7]s $gwmac %[8]s $peer $port spoofed-both
$f %[5]s $gwmac %[6]s 127.0.0.1 %[11]d to-loopback
$f %[5]s $gwmac 127.0.0.1 $peer $port from-loopback
sleep 1`, nicA.dev, nicA.gatewayMAC, peerAddr, peerUDP, nicA.mac, nicA.addr, nicB.mac, nicB.addr, hostAddr, nicA.gateway, guard.port)
	dropsBefore := ingressDrops(t, nicA.ns)
	if out := sh(t, manager, a, spoof); out.code != 0 {
		t.Fatalf("send frames: %s", out.stderr)
	}
	received := peer.received()
	// The one honest frame arrived, masqueraded as the host.
	if !strings.Contains(received, fmt.Sprintf("udp %d from %s legit", peerUDP, peerHostAddr)) {
		t.Fatalf("control: the guest's honest frame did not reach the peer:\n%s", received)
	}
	if strings.Contains(received, "spoofed") || strings.Contains(received, "loopback") {
		t.Fatalf("a frame with a spoofed source reached the peer:\n%s", received)
	}
	// Nine of them were dropped at the tap's own hook; the frame for
	// 127.0.0.1 is honest about its source and dies in the namespace's routing.
	if drops := ingressDrops(t, nicA.ns) - dropsBefore; drops < 9 {
		t.Fatalf("the tap's ingress filter dropped %d frames, want the 9 with a wrong source", drops)
	}
	guard.untouched(t, "after spoofed frames")

	// --- the rules removed and changed under the daemon: put back, and
	// everything above still holds. Twice: every table deleted (what a
	// "flush ruleset" does, on the host and in each run's namespace), and
	// every table left in place with nothing in it.
	rulesOf := func() string {
		// A table that is not there lists as an error, which is as
		// different from the rules as written as anything.
		listing, _ := hostTry("nft", "-s", "list", "table", "inet", names.table)
		for _, nic := range []guestNIC{nicA, nicB, nicC} {
			rules, _ := tryNS(nic.ns, "nft", "-s", "list", "ruleset")
			listing += "\n" + rules
		}
		return listing
	}
	intact := rulesOf()
	for _, want := range []string{nicA.addr, nicB.addr, `"` + nicA.link + `"`, "tcp dport " + proxyPort + " accept", "hook ingress device \"" + nicC.tap + "\"", "tcp dport 25", "169.254.0.0/16"} {
		if !strings.Contains(intact, want) {
			t.Fatalf("the rules as written lack %q:\n%s", want, intact)
		}
	}
	for how, damage := range map[string]func(){
		"deleted": func() {
			hostRun(t, "nft", "delete", "table", "inet", names.table)
			for _, nic := range []guestNIC{nicA, nicB, nicC} {
				inNS(t, nic.ns, "nft", "flush", "ruleset")
			}
		},
		"emptied": func() {
			hostRun(t, "nft", "flush", "table", "inet", names.table)
			hostRun(t, "nft", "flush", "set", "inet", names.table, "open")
			for _, nic := range []guestNIC{nicA, nicB, nicC} {
				inNS(t, nic.ns, "nft", "flush", "table", "inet", runTable)
				inNS(t, nic.ns, "nft", "flush", "table", "netdev", runTable)
			}
		},
	} {
		damage()
		if rulesOf() == intact {
			t.Fatalf("rules %s by hand are unchanged; nothing was tested", how)
		}
		removed := time.Now()
		for rulesOf() != intact {
			if time.Since(removed) > 20*time.Second {
				t.Fatalf("the daemon did not put back the rules that were %s:\n%s\nwant:\n%s", how, rulesOf(), intact)
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("timing: every ruleset (the host's table and three runs' namespaces) %s by hand was back, identical, after %s", how, time.Since(removed).Round(100*time.Millisecond))
	}
	for _, said := range []string{"removed by something else", "changed by something else", "a run's ruleset was removed or changed"} {
		if !strings.Contains(logs.String(), said) {
			t.Fatalf("the daemon restored its rules without saying %q", said)
		}
	}
	isolation("after the rules were restored")
	hostIsClosed("after the rules were restored")
	if !reaches(t, manager, a, peerAddr, false) || !reaches(t, manager, c, peerAddr, false) {
		t.Fatal("after the rules were restored the guests lost what their tiers allow")
	}

	// --- throughput, roughly: a 1 GiB download from the peer
	hostSpeed := hostRun(t, "curl", "-s", "-o", "/dev/null", "-w", "%{speed_download}", fmt.Sprintf("http://%s:%d/blob", peerAddr, peerHTTP))
	hostMB, _ := strconv.ParseFloat(hostSpeed, 64)
	t.Logf("throughput: host to peer directly (the ceiling of this setup): %.0f MB/s", hostMB/(1<<20))
	t.Logf("throughput: open tier, guest to peer (tap, the run's namespace, link, forward, masquerade): %.0f MB/s", download(t, manager, a))
	t.Logf("throughput: allowlist tier, guest to peer through its proxy: %.0f MB/s", download(t, manager, c))
	setupTimings(t, &logs)

	// --- teardown: each run's tap, rules and proxy go with it
	if tracked := hostRun(t, "conntrack", "-L", "-s", nicA.addr); !strings.Contains(tracked, "src="+nicA.addr) {
		t.Logf("note: no tracked connection of guest a to check the forgetting of: %s", tracked)
	}
	for _, id := range []string{a, c, b} {
		if err := manager.Destroy(ctx, id); err != nil {
			t.Fatalf("destroy: %v", err)
		}
	}
	for _, nic := range []guestNIC{nicA, nicB, nicC} {
		if tracked, _ := hostTry("conntrack", "-L", "-s", nic.addr); strings.Contains(tracked, "src="+nic.addr) {
			t.Errorf("the connection tracker still remembers %s:\n%s", nic.addr, tracked)
		}
	}
	// The allowlist run's proxy listened in the run's namespace, and
	// that is gone with everything else.
	assertNoNetworkLeft(t, names)
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("volumes left behind: %v", got)
	}
}

// ingressDrops is how many frames a run's tap's ingress filter has
// dropped.
func ingressDrops(t *testing.T, ns string) int {
	t.Helper()
	listing := inNS(t, ns, "nft", "list", "chain", "netdev", runTable, "ingress")
	match := regexp.MustCompile(`counter packets (\d+) bytes \d+ drop`).FindStringSubmatch(listing)
	if match == nil {
		t.Fatalf("no drop counter in:\n%s", listing)
	}
	count, _ := strconv.Atoi(match[1])
	return count
}

// TestVMNetworkTiers is what each tier means on a default driver, and
// that the meaning stays with a run across stop, resume and fork.
func TestVMNetworkTiers(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := vmTestConfig(t)
	names := namesFor(config)
	ctx := context.Background()
	startPeer(t)
	guard := startCanary(t)
	var logs syncBuffer
	manager, _, _, _ := newVMManagerLogging(t, config, t.TempDir(), &logs)
	baseline := poolListing(t, config.Pool)
	const cpus, memoryMB = 1, 512
	limits := &run.Limits{MemoryMB: memoryMB, CPUs: cpus}
	peerEntry := fmt.Sprintf("%s:%d", peerAddr, peerHTTP)
	hostAddr := hostAddress(t)

	// allowlist asserts everything the tier means for one run and returns
	// its proxy's port and credential.
	allowlist := func(when, id string) (port, credential string, nic guestNIC) {
		t.Helper()
		nic = inspectNIC(t, manager, id)
		proxy := strings.TrimSpace(sh(t, manager, id, `[ "$HTTP_PROXY" = "$HTTPS_PROXY" ] && [ "$http_proxy" = "$HTTP_PROXY" ] && [ "$https_proxy" = "$HTTP_PROXY" ] && printf %s "$HTTP_PROXY"`).stdout)
		match := regexp.MustCompile(`^http://run:([0-9a-f]{64})@` + regexp.QuoteMeta(nic.gateway) + `:(\d+)$`).FindStringSubmatch(proxy)
		if match == nil {
			t.Fatalf("%s: the run's proxy URL is %q, want a credential and a port on the gateway", when, proxy)
		}
		credential, port = match[1], match[2]
		// Through the proxy: a host on the built-in list (over the real
		// internet), the run's own entry, and a refusal for the rest.
		script := fmt.Sprintf(`code() { curl -sS -o /dev/null --max-time 25 -w '%%{http_code}/%%{http_connect}' "$@"; echo; }
echo "builtin $(code https://proxy.golang.org/)"
echo "entry $(curl -s --max-time 10 http://%[1]s/hello.txt)"
echo "other-port $(code http://%[2]s:25/)"
echo "denied-http $(code http://example.com/)"
echo "denied-https $(code https://example.com/)"
echo "no-credential $(code -x http://%[3]s:%[4]s http://%[1]s/hello.txt)"
echo "wrong-credential $(code -x http://run:%[5]s@%[3]s:%[4]s http://%[1]s/hello.txt)"
echo "no-credential-connect $(code -x http://%[3]s:%[4]s https://proxy.golang.org/)"`,
			peerEntry, peerAddr, nic.gateway, port, strings.Repeat("0", 64))
		through := sh(t, manager, id, script)
		got := through.stdout
		// Code of the request / code of the CONNECT, 000 for none.
		want := "builtin 200/200\nentry peer-ok\nother-port 403/000\ndenied-http 403/000\ndenied-https 000/403\nno-credential 407/000\nwrong-credential 407/000\nno-credential-connect 000/407\n"
		if got != want {
			t.Fatalf("%s: through the proxy:\n%s\nwant:\n%s\n%s", when, got, want, through.stderr)
		}
		// Around the proxy: nothing, with the routes the guest was given
		// and with the ones it can give itself.
		script = fmt.Sprintf(`ip route show default | sed 's/^/default route: /'
try() { curl -s --noproxy '*' --connect-timeout 3 --max-time 5 "$@" >/dev/null 2>&1 && echo "OPEN $*"; }
try http://%[1]s/hello.txt; try http://example.com/
ip route replace default via %[2]s dev %[3]s
try http://%[1]s/hello.txt; try http://example.com/; try http://%[4]s:%[5]d/
(nc -z -w 3 %[6]s 53 >/dev/null 2>&1 && echo "OPEN dns") ; (getent hosts example.com >/dev/null 2>&1 && echo "RESOLVED example.com")
ip route del default; true`, peerEntry, nic.gateway, nic.dev, hostAddr, guard.port, firstResolver(t))
		if out := sh(t, manager, id, script); strings.TrimSpace(out.stdout) != "" {
			t.Fatalf("%s: an allowlist run got out around its proxy:\n%s", when, out.stdout)
		}
		if got := hostProbe(t, manager, id, guard, []string{nic.gateway, hostAddr}); got != "" {
			t.Fatalf("%s: an allowlist run reached the host itself:\n%s", when, got)
		}
		guard.untouched(t, when)
		// The kernel's own switch, beside the firewall: nothing is routed
		// in an allowlist run's namespace, and there is nowhere to route
		// to (no link, no route but the guest's own).
		if got := inNS(t, nic.ns, "cat", "/proc/sys/net/ipv4/ip_forward"); got != "0" {
			t.Fatalf("%s: forwarding in an allowlist run's namespace: %q", when, got)
		}
		if routes := inNS(t, nic.ns, "ip", "-4", "route", "show"); strings.TrimSpace(routes) != nic.addr+" dev "+nic.tap+" scope link" {
			t.Fatalf("%s: routes in an allowlist run's namespace:\n%s", when, routes)
		}
		if _, err := hostTry("ip", "link", "show", "dev", nic.link); err == nil {
			t.Fatalf("%s: an allowlist run has a link to the host (%s)", when, nic.link)
		}
		return port, credential, nic
	}

	// open asserts what the open tier means on a default driver.
	open := func(when, id string) guestNIC {
		t.Helper()
		nic := inspectNIC(t, manager, id)
		script := `echo "proxy=${HTTP_PROXY:-}${HTTPS_PROXY:-}${http_proxy:-}${https_proxy:-}"
echo "resolved=$(getent hosts example.com >/dev/null 2>&1 && echo yes)"
echo "http=$(curl -s -o /dev/null --max-time 25 -w '%{http_code}' http://example.com/)"
echo "https=$(curl -s -o /dev/null --max-time 25 -w '%{http_code}' https://example.com/)"
echo "raw=$(nc -z -w 5 example.com 443 >/dev/null 2>&1 && echo connected)"`
		if got, want := sh(t, manager, id, script).stdout, "proxy=\nresolved=yes\nhttp=200\nhttps=200\nraw=connected\n"; got != want {
			t.Fatalf("%s: an open run and the internet:\n%s\nwant:\n%s", when, got, want)
		}
		// Not the public internet: every range the peer answers in. The
		// host reached each of them (startPeer); the guest reaches none.
		for kind, addr := range peerAddrs {
			if reaches(t, manager, id, addr, true) {
				t.Fatalf("%s: an open run reached a %s address (%s)", when, kind, addr)
			}
		}
		// The resolver is reachable for DNS and nothing else.
		if resolver := firstResolver(t); netip.MustParseAddr(resolver).IsPrivate() {
			if out := sh(t, manager, id, fmt.Sprintf(`for p in 22 80 443; do (nc -z -w 2 %s $p >/dev/null 2>&1 && echo "OPEN $p") & done; wait`, resolver)); strings.TrimSpace(out.stdout) != "" {
				t.Fatalf("%s: an open run reached its private resolver beyond DNS: %s", when, out.stdout)
			}
		}
		if got := hostProbe(t, manager, id, guard, []string{nic.gateway, hostAddr, peerHostAddr}); got != "" {
			t.Fatalf("%s: an open run reached the host itself:\n%s", when, got)
		}
		guard.untouched(t, when)
		return nic
	}

	// --- create
	created, err := manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Network: "egress", EgressAllow: []string{peerEntry}, Limits: limits, OnExpire: "stop"})
	if err != nil {
		t.Fatalf("create allowlist: %v", err)
	}
	allowID := created.ID
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), allowID) })
	if created.Network != run.NetworkAllowlist {
		t.Fatalf("network: %q", created.Network)
	}
	port1, credential1, allowNIC := allowlist("allowlist run", allowID)

	createdOpen, err := manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Network: "open", Limits: limits})
	if err != nil {
		t.Fatalf("create open: %v", err)
	}
	openID := createdOpen.ID
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), openID) })
	openNIC := open("open run", openID)
	// Another run's proxy port is not this run's to connect to.
	if out := sh(t, manager, openID, "nc -z -w 3 "+openNIC.gateway+" "+port1); out.code == 0 {
		t.Fatal("an open run connected to an allowlist run's proxy port")
	}

	// --- the hypervisor of a VM with a network is confined exactly as one
	// without: unprivileged, jailed, in a network namespace that holds
	// nothing. The tap is in the run's namespace, which is not the
	// hypervisor's, and the hypervisor only has a descriptor.
	confined := inspectVM(t, config, manager, openID, cpus, memoryMB)
	// Its command line is a VM's without a network (the device was handed
	// to it running, over its API socket); it holds the tap as a
	// descriptor; it was never told an interface name; and its own idea
	// of the device is the run's MAC.
	cmdline, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(confined.pid), "cmdline"))
	args := strings.Split(string(cmdline), "\x00")
	if slices.Contains(args, "--net") || strings.Contains(string(cmdline), "tap") {
		t.Fatalf("the hypervisor's command line names a network device: %q", args)
	}
	descriptors, _ := os.ReadDir(filepath.Join("/proc", strconv.Itoa(confined.pid), "fd"))
	taps := 0
	for _, each := range descriptors {
		if target, _ := os.Readlink(filepath.Join("/proc", strconv.Itoa(confined.pid), "fd", each.Name())); target == "/dev/net/tun" {
			taps++
		}
	}
	if taps == 0 {
		t.Fatal("the hypervisor of an open run holds no tap")
	}
	if code, info := hypervisorCall(t, http.MethodGet, filepath.Join(confined.runDir, "api.sock"), "vm.info", ""); code != 200 || !strings.Contains(info, `"mac":"`+openNIC.mac+`"`) || strings.Contains(info, `"tap":"t`) {
		t.Fatalf("the hypervisor's own view of the device: %d %s", code, info)
	}
	if out := inNS(t, openNIC.ns, "ip", "-o", "link", "show", "dev", openNIC.tap); !strings.Contains(out, "UP") {
		t.Fatalf("the tap is not up in the run's namespace: %s", out)
	}
	runNS, _ := os.Stat("/run/netns/" + openNIC.ns)
	hypervisorNS, _ := os.Stat(filepath.Join("/proc", strconv.Itoa(confined.pid), "ns", "net"))
	if runNS == nil || hypervisorNS == nil || os.SameFile(runNS, hypervisorNS) {
		t.Fatalf("the hypervisor is in its run's network namespace (or one of them could not be read)")
	}

	// --- stop and resume: the tier, the entries and the limits stay; the
	// tap and the proxy of the stopped run are gone, the resumed run has
	// new ones
	if _, err := manager.Stop(ctx, allowID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	// The namespace is gone, and with it the tap, the rules and the
	// only place the run's proxy could be reached from.
	if slices.Contains(names.namespaces(t), allowNIC.ns) {
		t.Fatalf("the stopped run's namespace %s is still there", allowNIC.ns)
	}
	resumed, err := manager.Resume(ctx, allowID, 1800)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.Network != run.NetworkAllowlist {
		t.Fatalf("resumed on %q", resumed.Network)
	}
	port2, credential2, resumedNIC := allowlist("resumed allowlist run", allowID)
	if credential2 == credential1 {
		t.Fatal("a resumed run was given its old proxy credential")
	}
	t.Logf("allowlist run: %s proxy port %s before the stop, %s proxy port %s after the resume", allowNIC.addr, port1, resumedNIC.addr, port2)

	// --- fork: the source's tier and entries, a tap, an address, a proxy
	// and a credential of its own
	forked, err := manager.Fork(ctx, allowID, run.ForkRequest{TTLSec: 1800})
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	t.Cleanup(func() { _ = manager.Destroy(context.Background(), forked.ID) })
	if forked.Network != run.NetworkAllowlist {
		t.Fatalf("forked on %q", forked.Network)
	}
	port3, credential3, forkNIC := allowlist("forked allowlist run", forked.ID)
	if forkNIC.addr == resumedNIC.addr || forkNIC.ns == resumedNIC.ns || forkNIC.mac == resumedNIC.mac || port3 == port2 || credential3 == credential2 {
		t.Fatalf("a fork shares its source's network: source %+v port %s, fork %+v port %s", resumedNIC, port2, forkNIC, port3)
	}
	// The source's proxy, with the source's own credential, from the fork:
	// the port is not the fork's to reach. And the other way round.
	for name, attempt := range map[string]struct{ from, port, credential string }{
		"the fork to its source's proxy": {forked.ID, port2, credential2},
		"the source to its fork's proxy": {allowID, port3, credential3},
	} {
		out := sh(t, manager, attempt.from, fmt.Sprintf(`curl -s --connect-timeout 3 --max-time 5 -x http://run:%s@%s:%s http://%s/hello.txt`, attempt.credential, forkNIC.gateway, attempt.port, peerEntry))
		if out.code == 0 || out.stdout != "" {
			t.Fatalf("%s: reached (%q)", name, out.stdout)
		}
	}
	// The source is untouched by its fork.
	if _, _, again := allowlist("source after its fork", allowID); again != resumedNIC {
		t.Fatalf("the source's device changed when it was forked: %+v, was %+v", again, resumedNIC)
	}

	// --- the open tier across stop and resume
	if _, err := manager.Stop(ctx, openID); err != nil {
		t.Fatalf("stop open: %v", err)
	}
	if resumedOpen, err := manager.Resume(ctx, openID, 1800); err != nil || resumedOpen.Network != run.NetworkOpen {
		t.Fatalf("resume open: %+v %v", resumedOpen, err)
	}
	open("resumed open run", openID)
	setupTimings(t, &logs)

	// --- teardown
	for _, id := range []string{allowID, forked.ID, openID} {
		if err := manager.Destroy(ctx, id); err != nil {
			t.Fatalf("destroy: %v", err)
		}
	}
	assertNoNetworkLeft(t, names)
	confined.assertGone(t)
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("volumes or snapshots left behind: %v", got)
	}
	if left := hypervisorProcesses(t, config.RunDir); len(left) != 0 {
		t.Fatalf("hypervisor processes left behind: %v", left)
	}
}

// TestVMNetworkFailsClosed is the driver with no firewall at all. The
// daemon's upkeep is stopped first (as if it were dead), so nothing puts a
// rule back; then every table it wrote is emptied, and then deleted, on
// the host and inside every run's namespace, while three guests run.
//
// What a guest can reach then is what exists in its namespace: an
// allowlist guest its own proxy, an open guest whatever its namespace's
// routes lead to. No host service and no other guest is among either, so
// none is reached, for as long as the rules stay away. Private ranges are
// opened (--vm-open-private) so that the refusals have controls beside
// them: the peer on another port and another address is reached, without
// masquerading, because the peer happens to route back through the host.
func TestVMNetworkFailsClosed(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := vmTestConfig(t)
	config.OpenPrivate = true
	names := namesFor(config)
	ctx := context.Background()
	peer := startPeer(t)
	guard := startCanary(t)
	manager, driver, _, _ := newVMManager(t, config, t.TempDir())
	baseline := poolListing(t, config.Pool)
	create := func(req run.CreateRequest) string {
		t.Helper()
		req.Image, req.Limits = vm.GoldenImage, &run.Limits{MemoryMB: 512, CPUs: 1}
		created, err := manager.Create(ctx, req)
		if err != nil {
			t.Fatalf("create %s: %v", req.Network, err)
		}
		t.Cleanup(func() { _ = manager.Destroy(context.Background(), created.ID) })
		installTools(t, manager, created.ID)
		return created.ID
	}
	a := create(run.CreateRequest{Network: "open"})
	b := create(run.CreateRequest{Network: "open"})
	c := create(run.CreateRequest{Network: "allowlist", EgressAllow: []string{fmt.Sprintf("%s:%d", peerAddr, peerHTTP)}})
	d := create(run.CreateRequest{Network: "allowlist"})
	nicA, nicB, nicC, nicD := inspectNIC(t, manager, a), inspectNIC(t, manager, b), inspectNIC(t, manager, c), inspectNIC(t, manager, d)
	nics := []guestNIC{nicA, nicB, nicC, nicD}
	hostAddr := hostAddress(t)
	// The broadcast addresses of the host's subnets are the host too: a
	// datagram to one is read by every socket bound to all addresses.
	hostTargets := append([]string{nicA.gateway, hostAddr, peerHostAddr}, hostBroadcasts(t)...)
	proxyOf := func(id string) (port, credential string) {
		match := regexp.MustCompile(`^http://run:([0-9a-f]{64})@[0-9.]+:(\d+)$`).FindStringSubmatch(strings.TrimSpace(sh(t, manager, id, `printf %s "$HTTP_PROXY"`).stdout))
		if match == nil {
			t.Fatalf("the proxy URL of %s", id)
		}
		return match[2], match[1]
	}
	portC, _ := proxyOf(c)
	portD, credentialD := proxyOf(d)

	// --- controls, with the rules in place
	if !reaches(t, manager, a, peerAddr, false) || !reaches(t, manager, b, peerAddr, false) || !reaches(t, manager, c, peerAddr, false) {
		t.Fatal("control: a guest cannot reach the peer at all")
	}
	if out := sh(t, manager, b, `(setsid python3 /work/listen.py /work/recv.log 9000 >/dev/null 2>&1 &); for i in $(seq 50); do grep -q ready /work/recv.log 2>/dev/null && break; sleep 0.1; done; nc -z -w 2 `+nicB.addr+` 9000`); out.code != 0 {
		t.Fatalf("control: guest b's listener: %+v", out)
	}

	// --- the daemon's upkeep stops. With VMs attached it removes
	// nothing; from here no rule that goes away comes back.
	if err := driver.Close(ctx); err != nil {
		t.Fatalf("stop the driver's upkeep: %v", err)
	}

	if !guestHasIPv6(t, manager, a) {
		t.Logf("not applicable: the guest kernel has no IPv6 (no /proc/sys/net/ipv6), so the all-nodes IPv6 check does not run; the IPv4 and layer 2 checks do")
	}
	// closed is everything that must hold with no rules, checked while
	// they are away.
	closed := func(when string, controls bool) {
		t.Helper()
		// Guest to guest: routed, at the other's MAC, to everyone, as
		// the other guest's address, and over IPv6.
		attack := fmt.Sprintf(`b=%[1]s; bmac=%[2]s; dev=%[3]s; me=%[4]s; mymac=%[5]s; gwmac=%[6]s
(ping -c 2 -W 2 $b >/dev/null 2>&1 && echo "OPEN icmp") &
(nc -z -w 3 $b 9000 >/dev/null 2>&1 && echo "OPEN tcp") &
(echo routed | nc -u -w 1 $b 9000 >/dev/null 2>&1) &
wait
python3 /work/frame.py udp $dev $mymac $bmac $me $b 9000 direct-l2
python3 /work/frame.py udp $dev $mymac ff:ff:ff:ff:ff:ff $me $b 9000 broadcast-l2
python3 /work/frame.py udp $dev $mymac $gwmac $me $b 9000 via-the-gateway
python3 /work/frame.py udp $dev $mymac $gwmac %[7]s $b 9000 spoofed-source
python3 /work/frame.py udp $dev $mymac $gwmac $b %[8]s %[9]d as-the-other-guest
ip addr add $b/32 dev $dev
(nc -z -w 3 -s $b $b 9000 >/dev/null 2>&1 && echo "OPEN tcp from the other guest's address")
(curl -s --interface $b --connect-timeout 3 --max-time 4 http://%[8]s:%[10]d/hello.txt >/dev/null 2>&1 && echo "OPEN as the other guest's address")
ip addr del $b/32 dev $dev
if [ -d /proc/sys/net/ipv6 ]; then
echo 0 > /proc/sys/net/ipv6/conf/$dev/disable_ipv6; sleep 3
(ping -6 -c 2 -W 2 ff02::1%%$dev 2>/dev/null | grep "bytes from" | grep -v "from $(ip -6 -o addr show dev $dev scope link | awk '{print $4}' | cut -d/ -f1)" | sed 's/^/ANSWER all-nodes: /')
echo 1 > /proc/sys/net/ipv6/conf/$dev/disable_ipv6
fi
true`, nicB.addr, nicB.mac, nicA.dev, nicA.addr, nicA.mac, nicA.gatewayMAC, hostAddr, peerAddr, peerUDP, peerHTTP)
		if out := sh(t, manager, a, attack); strings.TrimSpace(out.stdout) != "" {
			t.Fatalf("%s: open guest a reached open guest b, or sent as it:\n%s\n%s", when, out.stdout, out.stderr)
		}
		// From an allowlist guest, with whatever routes it gives itself:
		// another guest, the peer, the internet.
		out := sh(t, manager, c, fmt.Sprintf(`ip route replace default via %s dev %s
for t in %s %s %s; do (ping -c 1 -W 2 $t >/dev/null 2>&1 && echo "OPEN icmp $t") & (nc -z -w 3 $t 9000 >/dev/null 2>&1 && echo "OPEN tcp $t:9000") & (nc -z -w 3 $t %d >/dev/null 2>&1 && echo "OPEN tcp $t:%d") & done; wait
(curl -s --noproxy '*' --connect-timeout 3 --max-time 5 http://example.com/ >/dev/null 2>&1 && echo "OPEN the internet")
ip route del default; true`, nicC.gateway, nicC.dev, nicB.addr, nicD.addr, peerAddr, peerHTTP, peerHTTP))
		if strings.TrimSpace(out.stdout) != "" {
			t.Fatalf("%s: allowlist guest c got out of its namespace:\n%s", when, out.stdout)
		}
		received := sh(t, manager, b, `sleep 1; grep -v -e ready -e "from `+nicB.addr+`" /work/recv.log; true`)
		if strings.TrimSpace(received.stdout) != "" {
			t.Fatalf("%s: guest b received something from another guest:\n%s", when, received.stdout)
		}
		if got := peer.received(); strings.Contains(got, "as-the-other-guest") || strings.Contains(got, "spoofed") {
			t.Fatalf("%s: a frame with another guest's source address left the host:\n%s", when, got)
		}
		// Guest to the host itself: every address, the canary's port,
		// SSH, UDP and ping. The gateway address is the namespace's own
		// and nothing listens on it but a proxy.
		for name, id := range map[string]string{"open guest a": a, "open guest b": b, "allowlist guest c": c, "allowlist guest d": d} {
			if got := hostProbe(t, manager, id, guard, hostTargets); got != "" {
				t.Fatalf("%s: %s reached the host itself:\n%s", when, name, got)
			}
		}
		guard.untouched(t, when)
		// A proxy port is its own run's: from the other allowlist guest
		// and from the open guests, d's port is not there, with d's own
		// credential or without.
		for name, id := range map[string]string{"open guest a": a, "allowlist guest c": c} {
			out := sh(t, manager, id, fmt.Sprintf(`(nc -z -w 3 %[1]s %[2]s >/dev/null 2>&1 && echo "OPEN %[2]s"); (curl -s --connect-timeout 3 --max-time 5 -x http://run:%[3]s@%[1]s:%[2]s http://example.com/ -o /dev/null -w '%%{http_code}' | grep -v 000); true`, nicA.gateway, portD, credentialD))
			if strings.TrimSpace(out.stdout) != "" {
				t.Fatalf("%s: %s reached another run's proxy port %s: %s", when, name, portD, out.stdout)
			}
		}
		// An open guest's reach is still its tier: not link-local (where
		// metadata services are), not port 25, not its private resolver
		// beyond DNS; all by the namespace's routes.
		if reaches(t, manager, a, "169.254.169.254", true) {
			t.Fatalf("%s: an open guest reached the link-local metadata address", when)
		}
		if out := sh(t, manager, a, "nc -z -w 3 "+peerAddr+" 25"); out.code == 0 {
			t.Fatalf("%s: an open guest connected to port 25", when)
		}
		if strings.Count(peer.received(), "tcp 25 from") != 1 {
			t.Fatalf("%s: connections on port 25 at the peer:\n%s", when, peer.received())
		}
		if resolver := firstResolver(t); netip.MustParseAddr(resolver).IsPrivate() {
			if out := sh(t, manager, a, fmt.Sprintf(`for p in 22 80 443; do (nc -z -w 2 %s $p >/dev/null 2>&1 && echo "OPEN $p") & done; wait`, resolver)); strings.TrimSpace(out.stdout) != "" {
				t.Fatalf("%s: an open guest reached its private resolver beyond DNS: %s", when, out.stdout)
			}
		}
		if !controls {
			return
		}
		// The controls beside the refusals: what the tiers allow is still
		// there where it does not need the host's rules. The allowlist
		// guest reaches its allowlisted peer through its proxy; the open
		// guest reaches the peer on its ordinary port (unmasqueraded: the
		// peer's route back is through the host).
		if !reaches(t, manager, c, peerAddr, false) {
			t.Fatalf("%s: control: the allowlist guest lost its own proxy", when)
		}
		if out := sh(t, manager, c, "nc -z -w 3 "+nicC.gateway+" "+portC); out.code != 0 {
			t.Fatalf("%s: control: the allowlist guest cannot connect to its own proxy port", when)
		}
		if !reaches(t, manager, a, peerAddr, true) {
			t.Fatalf("%s: control: the open guest cannot reach the peer at all, so its refusals prove nothing", when)
		}
	}
	// rules is every rule and set element in the daemon's tables, on the
	// host and in the four namespaces; a chain's own line (its hook and
	// policy) is not one.
	rules := func() (found []string) {
		listing, _ := hostTry("nft", "list", "table", "inet", names.table)
		for _, nic := range nics {
			listing += "\n" + inNS(t, nic.ns, "nft", "list", "ruleset")
		}
		for _, line := range strings.Split(listing, "\n") {
			text := strings.TrimSpace(line)
			if (strings.HasPrefix(line, "\t\t") && !strings.HasPrefix(text, "type ")) || strings.HasPrefix(text, "elements") {
				found = append(found, text)
			}
		}
		return found
	}
	if len(rules()) < 30 {
		t.Fatalf("control: the rules as the daemon wrote them: %q", rules())
	}

	// --- flushed: every table and chain still there, with no rule in it.
	// The chains in the namespaces drop by default, so the guests have no
	// network at all; the host's chains accept by default, so the host's
	// table now passes everything.
	began := time.Now()
	hostRun(t, "nft", "flush", "table", "inet", names.table)
	hostRun(t, "nft", "flush", "set", "inet", names.table, "open")
	for _, nic := range nics {
		inNS(t, nic.ns, "nft", "flush", "table", "inet", runTable)
		inNS(t, nic.ns, "nft", "flush", "table", "netdev", runTable)
	}
	if left := rules(); len(left) != 0 {
		t.Fatalf("rules left after the flush: %q", left)
	}
	closed("with every table flushed", false)
	if reaches(t, manager, a, peerAddr, true) || reaches(t, manager, c, peerAddr, false) {
		t.Fatal("with every table flushed a guest still has a network: the namespaces' chains do not drop by default")
	}

	// --- deleted: no table of the daemon anywhere, so nothing is judged
	// by a rule or a policy. What is reachable is what has a route.
	hostRun(t, "nft", "delete", "table", "inet", names.table)
	for _, nic := range nics {
		inNS(t, nic.ns, "nft", "flush", "ruleset")
	}
	absent := func(when string) {
		t.Helper()
		if _, err := hostTry("nft", "list", "table", "inet", names.table); err == nil {
			t.Fatalf("%s: the host's table is there", when)
		}
		for _, nic := range nics {
			if listing := inNS(t, nic.ns, "nft", "list", "ruleset"); strings.TrimSpace(listing) != "" {
				t.Fatalf("%s: %s has a ruleset:\n%s", when, nic.ns, listing)
			}
		}
	}
	absent("before the probes")
	closed("with every table deleted", true)
	absent("after the probes")
	t.Logf("no rule of the daemon existed, on the host or in any of the four run namespaces, for %s (flushed, then deleted); in that time no guest reached a host service, another guest, or another run's proxy", time.Since(began).Round(time.Second))

	// --- teardown works without the tables too
	for _, id := range []string{a, b, c, d} {
		if err := manager.Destroy(ctx, id); err != nil {
			t.Fatalf("destroy: %v", err)
		}
	}
	if left := names.namespaces(t); len(left) != 0 {
		t.Fatalf("run namespaces left behind: %v", left)
	}
	if left := names.links(t); len(left) != 0 {
		t.Fatalf("links left behind: %v", left)
	}
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("volumes left behind: %v", got)
	}
}

// firstResolver is the resolver the daemon gives open guests on this host.
func firstResolver(t *testing.T) string {
	t.Helper()
	for _, path := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
		raw, _ := os.ReadFile(path)
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "nameserver" {
				if addr, err := netip.ParseAddr(fields[1]); err == nil && addr.Is4() && !addr.IsLoopback() {
					return addr.String()
				}
			}
		}
	}
	t.Fatal("the host has no resolver a guest could use")
	return ""
}

// TestVMNetworkAfterADaemonCrash: the daemon dies without tearing anything
// down. Until a new one starts, the rules it left are exactly the run's
// tier. From the first thing the new one does to the firewall the leftover
// guest has no network at all; the sweep then removes the VM, its
// namespace and whatever else carries this daemon's name, and nothing that
// does not.
func TestVMNetworkAfterADaemonCrash(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := vmTestConfig(t)
	config.OpenPrivate = true
	names := namesFor(config)
	ctx := context.Background()
	startPeer(t)
	guard := startCanary(t)
	crashed, crashedDriver, _, _ := newVMManager(t, config, t.TempDir())
	baseline := poolListing(t, config.Pool)

	created, err := crashed.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Network: "open", Limits: &run.Limits{MemoryMB: 512, CPUs: 1}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = crashed.Destroy(context.Background(), created.ID) })
	nic := inspectNIC(t, crashed, created.ID)
	if !reaches(t, crashed, created.ID, peerAddr, false) {
		t.Fatal("control: the open guest cannot reach the peer")
	}

	// Things on the host that look like the daemon's, and things that are
	// someone else's: a namespace and a link with this daemon's prefix
	// that no VM holds, what a version of the driver that kept taps on
	// the host would have left (a tap, a gateway device, a netdev table),
	// a namespace, a link and a table of another daemon identity, and an
	// unrelated namespace and tap.
	strayNS, otherNS, unrelatedNS := names.nsPrefix+"fe", "tvnffffff-0", "tsbxother"
	strayLink, otherLink := names.linkPrefix+"fe", "tvhffffff-0"
	legacyTap, legacyGateway, unrelatedTap := names.tapPrefix+"fd", "tvg"+config.Owner[:6], "tsbxother0"
	otherTable := "teploy_sbx_vm_ffffffff"
	forget := func() {
		for _, link := range []string{strayLink, otherLink, legacyTap, legacyGateway, unrelatedTap} {
			_, _ = hostTry("ip", "link", "del", link)
		}
		for _, ns := range []string{strayNS, otherNS, unrelatedNS} {
			_, _ = hostTry("ip", "netns", "del", ns)
		}
		_, _ = hostTry("nft", "delete", "table", "inet", otherTable)
		_, _ = hostTry("nft", "delete", "table", "netdev", names.table)
	}
	forget()
	t.Cleanup(forget)
	for _, ns := range []string{strayNS, otherNS, unrelatedNS} {
		hostRun(t, "ip", "netns", "add", ns)
	}
	hostRun(t, "ip", "link", "add", strayLink, "type", "veth", "peer", "name", "uplink", "netns", strayNS)
	hostRun(t, "ip", "link", "add", otherLink, "type", "veth", "peer", "name", "uplink", "netns", otherNS)
	for _, tap := range []string{legacyTap, unrelatedTap} {
		hostRun(t, "ip", "tuntap", "add", "dev", tap, "mode", "tap")
	}
	hostRun(t, "ip", "link", "add", legacyGateway, "type", "dummy")
	hostRun(t, "nft", "add", "table", "inet", otherTable)
	hostRun(t, "nft", "add", "chain", "inet", otherTable, "keep")
	hostRun(t, "nft", "add", "table", "netdev", names.table)
	hostRun(t, "nft", "add", "chain", "netdev", names.table, "stray", fmt.Sprintf(`{ type filter hook ingress device "%s" priority 0; }`, legacyTap))

	// --- the crash: nothing runs, so nothing changes. The run is admitted
	// as an open run and as nothing more, and the rules that say so are
	// in its own namespace, which no daemon has to be alive for.
	if listing := setElements(t, names, "open"); !strings.Contains(listing, fmt.Sprintf(`"%s" . %s`, nic.link, nic.addr)) {
		t.Fatalf("the crashed daemon's rules:\n%s", listing)
	}
	if rules := inNS(t, nic.ns, "nft", "list", "ruleset"); !strings.Contains(rules, "tcp dport 25") || !strings.Contains(rules, "hook ingress device \""+nic.tap+"\"") {
		t.Fatalf("the rules in the crashed daemon's run namespace:\n%s", rules)
	}
	if got := hostProbe(t, crashed, created.ID, guard, []string{nic.gateway, hostAddress(t)}); got != "" {
		t.Fatalf("after the crash the guest reached the host itself:\n%s", got)
	}

	// --- the restart, up to the moment before its sweep: the new daemon
	// has written its firewall and knows no run. The guest is still alive.
	warm := settledWarmPool(t, crashedDriver)
	restarted, err := vm.New(ctx, config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close(context.Background()) })
	if len(hypervisorProcesses(t, config.RunDir)) != 1 {
		t.Fatal("the leftover VM is not running any more; nothing was tested")
	}
	if reaches(t, crashed, created.ID, peerAddr, false) {
		t.Fatal("a guest left over from a crashed daemon still has its network after the restart")
	}
	if got := hostProbe(t, crashed, created.ID, guard, []string{nic.gateway, hostAddress(t)}); got != "" {
		t.Fatalf("after the restart the leftover guest reached the host itself:\n%s", got)
	}
	guard.untouched(t, "leftover guest")

	// --- the sweep
	processes, _, err := restarted.Sweep(ctx)
	if err != nil || processes != 1+warm {
		t.Fatalf("sweep: %d processes (want the leftover run's and %d warm pool VMs), %v", processes, warm, err)
	}
	for _, link := range []string{otherLink, unrelatedTap} {
		if _, err := hostTry("ip", "link", "show", "dev", link); err != nil {
			t.Errorf("the sweep removed %s, which is not this daemon's", link)
		}
	}
	for _, ns := range []string{otherNS, unrelatedNS} {
		if _, err := os.Stat("/run/netns/" + ns); err != nil {
			t.Errorf("the sweep removed the namespace %s, which is not this daemon's", ns)
		}
	}
	if _, err := hostTry("ip", "link", "show", "dev", legacyGateway); err == nil {
		t.Errorf("the sweep left the gateway device of an earlier version of the driver")
	}
	if listing, err := hostTry("nft", "list", "table", "inet", otherTable); err != nil || !strings.Contains(listing, "chain keep") {
		t.Errorf("the sweep touched another daemon's table: %v\n%s", err, listing)
	}
	// Its own stray namespace and link, the leftover VM's, and the taps
	// of an earlier version: all gone.
	assertNoNetworkLeft(t, names)

	// The crashed daemon's own teardown, arriving late, changes nothing of
	// what the new one owns.
	before := hostRun(t, "nft", "list", "table", "inet", names.table)
	if err := crashed.Destroy(ctx, created.ID); err != nil {
		t.Fatalf("destroy through the old manager: %v", err)
	}
	if after := hostRun(t, "nft", "list", "table", "inet", names.table); after != before {
		t.Fatalf("a superseded daemon instance rewrote the firewall:\n%s\nwas:\n%s", after, before)
	}
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("volumes left behind: %v", got)
	}
}
