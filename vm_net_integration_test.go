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

// netNames is what the driver names things for this suite's identity.
type netNames struct{ tapPrefix, table, gatewayDev string }

func namesFor(config vm.Config) netNames {
	return netNames{tapPrefix: "tv" + config.Owner[:6] + "-", table: "teploy_sbx_vm_" + config.Owner[:8], gatewayDev: "tvg" + config.Owner[:6]}
}

// taps lists the host's interfaces that are this suite's taps.
func (n netNames) taps(t *testing.T) []string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, each := range interfaces {
		if strings.HasPrefix(each.Name, n.tapPrefix) {
			names = append(names, each.Name)
		}
	}
	slices.Sort(names)
	return names
}

// guestNIC is a guest's network device as the guest sees it, and its tap.
type guestNIC struct {
	dev, addr, mac, gateway, gatewayMAC string
	tap, chain                          string
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
	route := hostRun(t, "ip", "-o", "route", "get", nic.addr)
	match := regexp.MustCompile(` dev (\S+)`).FindStringSubmatch(route)
	if match == nil {
		t.Fatalf("no route to the guest: %s", route)
	}
	nic.tap = match[1]
	nic.chain = "tap" + nic.tap[strings.LastIndex(nic.tap, "-")+1:]
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

func setElements(t *testing.T, names netNames, set string) string {
	t.Helper()
	return hostRun(t, "nft", "list", "set", "inet", names.table, set)
}

// assertNoNetworkLeft checks that nothing of any run is left on the host:
// no tap, no admission, no ingress filter.
func assertNoNetworkLeft(t *testing.T, names netNames) {
	t.Helper()
	if taps := names.taps(t); len(taps) != 0 {
		t.Errorf("taps left behind: %v", taps)
	}
	for _, set := range []string{"open", "proxy"} {
		if listing := setElements(t, names, set); strings.Contains(listing, "elements") {
			t.Errorf("the %s set still admits something:\n%s", set, listing)
		}
	}
	if listing := hostRun(t, "nft", "list", "table", "netdev", names.table); strings.Contains(listing, "chain") {
		t.Errorf("ingress filters left behind:\n%s", listing)
	}
	if routes := hostRun(t, "ip", "-4", "route", "show"); strings.Contains(routes, names.tapPrefix) {
		t.Errorf("routes to taps left behind:\n%s", routes)
	}
}

func setupTimings(t *testing.T, logs *syncBuffer) {
	t.Helper()
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "vm network device ready") {
			tier := regexp.MustCompile(`tier=(\S+)`).FindStringSubmatch(line)
			host := regexp.MustCompile(`hostSetup=(\S+)`).FindStringSubmatch(line)
			guest := regexp.MustCompile(`guestSetup=(\S+)`).FindStringSubmatch(line)
			if tier != nil && host != nil && guest != nil {
				t.Logf("timing: network setup for a %-9s run: host side (tap, sysctls, firewall, route) %s, guest side (address, routes, resolver) %s", tier[1], host[1], guest[1])
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
	t.Logf("guest a %s on %s, guest b %s on %s, guest c (allowlist) %s on %s; gateway %s", nicA.addr, nicA.tap, nicB.addr, nicB.tap, nicC.addr, nicC.tap, nicA.gateway)
	if nicA.addr == nicB.addr || nicA.tap == nicB.tap || nicA.mac == nicB.mac || nicA.gateway != nicB.gateway {
		t.Fatalf("two runs share an address, a tap or a MAC: %+v %+v", nicA, nicB)
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
	isolation := func(when string) {
		t.Helper()
		// The target listens on TCP and UDP, has IPv6 up, and can reach
		// its own listener: only the path from another guest is missing.
		listening := sh(t, manager, b, `rm -f /work/recv.log; (setsid python3 /work/listen.py /work/recv.log 9000 >/dev/null 2>&1 &)
for i in $(seq 50); do grep -q ready /work/recv.log 2>/dev/null && break; sleep 0.1; done
echo 0 > /proc/sys/net/ipv6/conf/`+nicB.dev+`/disable_ipv6; sleep 3
nc -z -w 2 `+nicB.addr+` 9000 && ip -6 -o addr show dev `+nicB.dev+` scope link | awk '{print $4}' | cut -d/ -f1`)
		linkLocal := strings.TrimSpace(listening.stdout)
		if listening.code != 0 || !strings.HasPrefix(linkLocal, "fe80:") {
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
# IPv6: link-local needs no configuration from anyone
echo 0 > /proc/sys/net/ipv6/conf/$dev/disable_ipv6; sleep 3
own=$(ip -6 -o addr show dev $dev scope link | awk '{print $4}' | cut -d/ -f1)
[ -n "$own" ] || echo "no link-local address of my own: nothing was tested"
(ping -6 -c 2 -W 2 %[10]s%%$dev >/dev/null 2>&1 && echo "OPEN icmp6 link-local") &
(nc -6 -z -w 3 %[10]s%%$dev 9000 >/dev/null 2>&1 && echo "OPEN tcp6 link-local") &
# all nodes and all routers: a guest hears its own echo and nobody else's
(ping -6 -c 2 -W 2 ff02::1%%$dev 2>/dev/null | grep "bytes from" | grep -v "from $own" | sed 's/^/ANSWER all-nodes: /') &
(ping -6 -c 2 -W 2 ff02::2%%$dev 2>/dev/null | grep "bytes from" | grep -v "from $own" | sed 's/^/ANSWER all-routers: /') &
wait
echo 1 > /proc/sys/net/ipv6/conf/$dev/disable_ipv6
true`, nicB.addr, nicB.mac, nicA.dev, nicA.addr, nicA.mac, nicA.gateway, nicA.gatewayMAC, peerAddr, peerHTTP, linkLocal)
		out := sh(t, manager, a, attack)
		if got := strings.TrimSpace(out.stdout); got != "" {
			t.Fatalf("%s: guest a reached guest b, or something answered on IPv6:\n%s\n%s", when, got, out.stderr)
		}
		// From the allowlist guest too, which has no route but can make one.
		out = sh(t, manager, c, fmt.Sprintf(`ip route replace default via %s dev %s; (ping -c 1 -W 2 %[3]s >/dev/null 2>&1 && echo "OPEN icmp"); (nc -z -w 3 %[3]s 9000 >/dev/null 2>&1 && echo "OPEN tcp"); echo routed-c | nc -u -w 1 %[3]s 9000 >/dev/null 2>&1; ip route del default; true`, nicC.gateway, nicC.dev, nicB.addr))
		if strings.TrimSpace(out.stdout) != "" {
			t.Fatalf("%s: the allowlist guest reached guest b: %s", when, out.stdout)
		}
		received := sh(t, manager, b, `sleep 1; grep -v -e ready -e "from `+nicB.addr+`" /work/recv.log; pkill -f '[l]isten.py'; echo 1 > /proc/sys/net/ipv6/conf/`+nicB.dev+`/disable_ipv6; true`)
		if strings.TrimSpace(received.stdout) != "" {
			t.Fatalf("%s: guest b received something from another guest:\n%s", when, received.stdout)
		}
		// The host's idea of who has which address did not move, and the
		// attacked guest still has its network.
		for _, nic := range []guestNIC{nicA, nicB} {
			if got, want := hostRun(t, "ip", "-4", "neigh", "show", "dev", nic.tap), nic.addr+" lladdr "+nic.mac+" PERMANENT"; strings.TrimSpace(got) != want {
				t.Fatalf("%s: the host's neighbours on %s: %q, want only %q", when, nic.tap, got, want)
			}
			// No IPv6 on the host's side of a tap, whatever the guest sends.
			if got := hostRun(t, "ip", "-6", "addr", "show", "dev", nic.tap); got != "" {
				t.Fatalf("%s: the host has an IPv6 address on %s: %s", when, nic.tap, got)
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
	dropsBefore := ingressDrops(t, names, nicA.chain)
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
	// 127.0.0.1 is honest about its source and dies in the host's routing.
	if drops := ingressDrops(t, names, nicA.chain) - dropsBefore; drops < 9 {
		t.Fatalf("the tap's ingress filter dropped %d frames, want the 9 with a wrong source", drops)
	}
	guard.untouched(t, "after spoofed frames")

	// --- the tables removed under the daemon (a firewall reload that
	// flushes everything): put back, and everything above still holds
	hostRun(t, "nft", "delete", "table", "inet", names.table)
	hostRun(t, "nft", "delete", "table", "netdev", names.table)
	removed := time.Now()
	for {
		inet, inetErr := hostTry("nft", "list", "table", "inet", names.table)
		netdev, _ := hostTry("nft", "list", "table", "netdev", names.table)
		if inetErr == nil && strings.Contains(inet, nicA.addr) && strings.Contains(inet, nicB.addr) && strings.Contains(inet, nicC.addr+" . "+proxyPort) && strings.Contains(netdev, "chain "+nicA.chain+" {") && strings.Contains(netdev, "chain "+nicC.chain+" {") {
			break
		}
		if time.Since(removed) > 20*time.Second {
			t.Fatalf("the daemon did not put its firewall back:\n%s\n%s", inet, netdev)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("timing: firewall tables removed by hand were back after %s", time.Since(removed).Round(100*time.Millisecond))
	if !strings.Contains(logs.String(), "removed by something else") {
		t.Fatal("the daemon restored its firewall without saying so")
	}
	isolation("after the firewall was restored")
	hostIsClosed("after the firewall was restored")
	if !reaches(t, manager, a, peerAddr, false) || !reaches(t, manager, c, peerAddr, false) {
		t.Fatal("after the firewall was restored the guests lost what their tiers allow")
	}

	// --- throughput, roughly: a 1 GiB download from the peer
	hostSpeed := hostRun(t, "curl", "-s", "-o", "/dev/null", "-w", "%{speed_download}", fmt.Sprintf("http://%s:%d/blob", peerAddr, peerHTTP))
	hostMB, _ := strconv.ParseFloat(hostSpeed, 64)
	t.Logf("throughput: host to peer directly (the ceiling of this setup): %.0f MB/s", hostMB/(1<<20))
	t.Logf("throughput: open tier, guest to peer (tap, forward, masquerade): %.0f MB/s", download(t, manager, a))
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
	assertNoNetworkLeft(t, names)
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort(nicC.gateway, proxyPort), 2*time.Second); err == nil {
		conn.Close()
		t.Error("the allowlist run's proxy still listens after the run was destroyed")
	}
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("volumes left behind: %v", got)
	}
}

// ingressDrops is how many frames a tap's ingress filter has dropped.
func ingressDrops(t *testing.T, names netNames, chain string) int {
	t.Helper()
	listing := hostRun(t, "nft", "list", "chain", "netdev", names.table, chain)
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
		// The kernel's own switch, beside the firewall.
		if raw, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + nic.tap + "/forwarding"); err != nil || strings.TrimSpace(string(raw)) != "0" {
			t.Fatalf("%s: forwarding on an allowlist run's tap: %q %v", when, raw, err)
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
	// without: unprivileged, in a network namespace that holds nothing.
	// The tap is the host's, and the hypervisor only has a descriptor.
	confined := inspectVM(t, config, manager, openID, cpus, memoryMB)
	cmdline, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(confined.pid), "cmdline"))
	args := strings.Split(string(cmdline), "\x00")
	if at := slices.Index(args, "--net"); at < 0 || args[at+1] != "fd=3,mac="+openNIC.mac {
		t.Fatalf("the hypervisor's network device: %q", args)
	}
	if target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(confined.pid), "fd", "3")); err != nil || target != "/dev/net/tun" {
		t.Fatalf("the hypervisor's descriptor 3: %q %v", target, err)
	}
	if strings.Contains(string(cmdline), "tap=") {
		t.Fatalf("the hypervisor was told an interface name: %q", args)
	}
	if out := hostRun(t, "ip", "-o", "link", "show", "dev", openNIC.tap); !strings.Contains(out, "UP") {
		t.Fatalf("the tap is not an interface of the host: %s", out)
	}

	// --- stop and resume: the tier, the entries and the limits stay; the
	// tap and the proxy of the stopped run are gone, the resumed run has
	// new ones
	if _, err := manager.Stop(ctx, allowID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := hostTry("ip", "link", "show", "dev", allowNIC.tap); err == nil {
		t.Fatalf("the stopped run's tap %s is still there", allowNIC.tap)
	}
	if listing := setElements(t, names, "proxy"); strings.Contains(listing, "elements") {
		t.Fatalf("a stopped run is still admitted to a proxy port:\n%s", listing)
	}
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort(allowNIC.gateway, port1), 2*time.Second); err == nil {
		conn.Close()
		t.Fatal("a stopped run's proxy still listens")
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
	if forkNIC.addr == resumedNIC.addr || forkNIC.tap == resumedNIC.tap || forkNIC.mac == resumedNIC.mac || port3 == port2 || credential3 == credential2 {
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
	for _, port := range []string{port2, port3} {
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort(forkNIC.gateway, port), 2*time.Second); err == nil {
			conn.Close()
			t.Errorf("proxy port %s still listens after its run was destroyed", port)
		}
	}
	confined.assertGone(t)
	if got := poolListing(t, config.Pool); !slices.Equal(got, baseline) {
		t.Fatalf("volumes or snapshots left behind: %v", got)
	}
	if left := hypervisorProcesses(t, config.RunDir); len(left) != 0 {
		t.Fatalf("hypervisor processes left behind: %v", left)
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
// guest has no network at all; the sweep then removes the VM, its tap and
// whatever else carries this daemon's name, and nothing that does not.
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
	crashed, _, _, _ := newVMManager(t, config, t.TempDir())
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
	// someone else's: a tap with this daemon's prefix that no VM holds
	// (with an ingress filter), a tap and a table of another daemon
	// identity, and an unrelated tap.
	strayTap, otherTap, unrelatedTap := names.tapPrefix+"fe", "tvffffff-0", "tsbxother0"
	otherTable := "teploy_sbx_vm_ffffffff"
	for _, tap := range []string{strayTap, otherTap, unrelatedTap} {
		_, _ = hostTry("ip", "link", "del", tap)
		hostRun(t, "ip", "tuntap", "add", "dev", tap, "mode", "tap")
	}
	_, _ = hostTry("nft", "delete", "table", "inet", otherTable)
	hostRun(t, "nft", "add", "table", "inet", otherTable)
	hostRun(t, "nft", "add", "chain", "inet", otherTable, "keep")
	hostRun(t, "nft", "add", "chain", "netdev", names.table, "stray", fmt.Sprintf(`{ type filter hook ingress device "%s" priority 0; }`, strayTap))
	t.Cleanup(func() {
		for _, tap := range []string{strayTap, otherTap, unrelatedTap} {
			_, _ = hostTry("ip", "link", "del", tap)
		}
		_, _ = hostTry("nft", "delete", "table", "inet", otherTable)
	})

	// --- the crash: nothing runs, so nothing changes. The run is admitted
	// as an open run and as nothing more.
	if listing := setElements(t, names, "open"); !strings.Contains(listing, fmt.Sprintf(`"%s" . %s`, nic.tap, nic.addr)) {
		t.Fatalf("the crashed daemon's rules:\n%s", listing)
	}
	if got := hostProbe(t, crashed, created.ID, guard, []string{nic.gateway, hostAddress(t)}); got != "" {
		t.Fatalf("after the crash the guest reached the host itself:\n%s", got)
	}

	// --- the restart, up to the moment before its sweep: the new daemon
	// has written its firewall and knows no run. The guest is still alive.
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
	if err != nil || processes != 1 {
		t.Fatalf("sweep: %d processes, %v", processes, err)
	}
	if taps := names.taps(t); len(taps) != 0 {
		t.Fatalf("taps of this daemon left after the sweep: %v", taps)
	}
	for _, tap := range []string{otherTap, unrelatedTap} {
		if _, err := hostTry("ip", "link", "show", "dev", tap); err != nil {
			t.Errorf("the sweep removed %s, which is not this daemon's", tap)
		}
	}
	if listing, err := hostTry("nft", "list", "table", "inet", otherTable); err != nil || !strings.Contains(listing, "chain keep") {
		t.Errorf("the sweep touched another daemon's table: %v\n%s", err, listing)
	}
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
