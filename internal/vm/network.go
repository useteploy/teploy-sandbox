package vm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// Guest networking.
//
// A guest controls its own kernel: it can send any frame, claim any
// address and speak any protocol. Nothing here trusts what a guest does
// with its network device; the host decides what leaves it.
//
// And the host does not decide it with a firewall alone. A firewall that
// is flushed (by an administrator, by another tool's reload, by anything
// while the daemon is dead) lets everything through, so the rules are the
// second layer here and the first is what exists at all:
//
//   - Every run with a network has a network namespace of its own, made
//     by the daemon, and its tap is in that namespace and nowhere else.
//     The host's services are not there: a socket bound to every address
//     of the host is bound in the host's namespace. Another run's tap is
//     not there either. There is no bridge and no shared segment.
//   - An "allowlist" run's namespace has no link to anywhere. The one
//     thing a guest can reach in it is the run's own proxy, which the
//     daemon listens for with a socket made inside that namespace (the
//     proxy's own connections leave from the host, as before). With no
//     rule at all, that is still all there is.
//   - An "open" run's namespace has one link to the host, which routes
//     and masquerades what arrives on it. Inside the namespace the ranges
//     that are not the public internet, the guests' subnet, the host's
//     own addresses and port 25 have no route (unreachable routes and
//     routing rules, not firewall rules).
//   - The firewall says the same again, twice: a ruleset inside each
//     run's namespace (which a "flush ruleset" on the host does not
//     touch: nftables is per namespace), and one table on the host for
//     the open runs' links. At the tap's ingress hook, before the
//     namespace's ARP or IP code sees a frame: only the VM's MAC, only
//     IPv4 from the VM's address, and only ARP that asks for the gateway.
//   - The daemon creates the tap and hands the hypervisor the open file.
//     The hypervisor stays unprivileged and in its own empty network
//     namespace; it never sees an interface, only a file descriptor. The
//     tap is not persistent: it exists exactly as long as the hypervisor
//     holds that descriptor.
//   - The daemon compares every ruleset it wrote with what the kernel
//     has, every watchInterval, and writes back what differs.
//
// Everything is named after the daemon identity, so the startup sweep
// removes what this daemon left and nothing else.

// DefaultSubnet is the range guests are addressed from. Each VM gets one
// address of it; the first is the gateway.
const DefaultSubnet = "10.209.0.0/16"

// notPublic is every IPv4 range that is not the public internet: private,
// shared (carrier-grade NAT, which overlay networks also use), loopback,
// link-local (where cloud metadata services live), documentation,
// benchmarking, multicast and reserved space. An "open" run reaches none
// of it unless the operator said otherwise.
var notPublic = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
}

// neverReachable stays closed even when the operator opens the private
// ranges: loopback, link-local and metadata, multicast, reserved.
var neverReachable = []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4"}

const (
	// uplinkDev is an open run's link to the host, as its namespace
	// names it; uplinkHop is the next hop on it. The hop is an address
	// nothing has: its hardware address is a permanent neighbour entry,
	// so the link carries no ARP and the host's end needs no address.
	uplinkDev = "uplink"
	uplinkHop = "169.254.0.1"
	// dnsTable is the routing table, in an open run's namespace, that
	// only DNS to the configured resolvers is looked up in.
	dnsTable = "100"
	// runTable is the name of both nftables tables in a run's namespace.
	runTable = "guest"
	// proxyPortBase is the port of slot 0's proxy listener.
	proxyPortBase = 20000
	// netnsDir is where iproute2 keeps named network namespaces.
	netnsDir = "/run/netns"
)

// netPlan is the network configuration, checked and resolved.
type netPlan struct {
	subnet  netip.Prefix
	gateway netip.Addr
	// first is the address of slot 0; slots is how many VMs can have one.
	first netip.Addr
	slots int
	// dns is what an open run's guest is told to resolve with.
	dns         []netip.Addr
	openPrivate bool
	// nsPrefix starts the name of every run's network namespace,
	// tapPrefix that of the tap inside it and linkPrefix that of the
	// host's end of an open run's link; table is the host's nftables
	// table. legacyGateway is a device earlier versions made on the host.
	nsPrefix, tapPrefix, linkPrefix, table, legacyGateway string
}

// planNetwork resolves the network part of a config. discovered is the
// host's own resolvers, used when the config names none; local is the
// host's own addresses, which no guest can reach and so cannot be a
// guest's resolver.
func planNetwork(config Config, discovered, local []netip.Addr) (netPlan, error) {
	raw := config.Subnet
	if raw == "" {
		raw = DefaultSubnet
	}
	subnet, err := netip.ParsePrefix(raw)
	switch {
	case err != nil:
		return netPlan{}, fmt.Errorf("%q is not a subnet (use CIDR form, such as %s)", raw, DefaultSubnet)
	case !subnet.Addr().Is4():
		return netPlan{}, fmt.Errorf("%q is not an IPv4 subnet", raw)
	case subnet.Masked() != subnet:
		return netPlan{}, fmt.Errorf("%q has host bits set; did you mean %s?", raw, subnet.Masked())
	case subnet.Bits() < 8 || subnet.Bits() > 28:
		return netPlan{}, fmt.Errorf("%q must be between a /8 and a /28", raw)
	}
	owner := config.Owner
	if len(owner) < 8 {
		return netPlan{}, errors.New("no daemon identity to name interfaces after")
	}
	plan := netPlan{
		subnet:      subnet,
		gateway:     subnet.Addr().Next(),
		openPrivate: config.OpenPrivate,
		// An interface name has 15 characters: 3 + 6 + 1 leaves 5 for the
		// slot. "n", "h" and "g" are not hex digits, so one kind of name
		// can never be taken for another.
		nsPrefix:      "tvn" + owner[:6] + "-",
		tapPrefix:     "tv" + owner[:6] + "-",
		linkPrefix:    "tvh" + owner[:6] + "-",
		table:         "teploy_sbx_vm_" + owner[:8],
		legacyGateway: "tvg" + owner[:6],
	}
	plan.first = plan.gateway.Next()
	// Without the network address, the gateway and the broadcast address.
	plan.slots = min(UIDCount, 1<<(32-subnet.Bits())-3)

	candidates := discovered
	if len(config.DNS) > 0 {
		candidates = nil
		for _, entry := range config.DNS {
			addr, err := netip.ParseAddr(strings.TrimSpace(entry))
			if err != nil || !addr.Is4() {
				return netPlan{}, fmt.Errorf("DNS resolver %q is not an IPv4 address", entry)
			}
			candidates = append(candidates, addr)
		}
	}
	for _, addr := range candidates {
		addr = addr.Unmap()
		if !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() || subnet.Contains(addr) || slices.Contains(local, addr) || slices.Contains(plan.dns, addr) {
			continue
		}
		if plan.dns = append(plan.dns, addr); len(plan.dns) == 3 {
			break
		}
	}
	return plan, nil
}

func (p netPlan) nsName(slot int) string   { return fmt.Sprintf("%s%x", p.nsPrefix, slot) }
func (p netPlan) tapName(slot int) string  { return fmt.Sprintf("%s%x", p.tapPrefix, slot) }
func (p netPlan) linkName(slot int) string { return fmt.Sprintf("%s%x", p.linkPrefix, slot) }

func (p netPlan) address(slot int) netip.Addr {
	raw := p.first.As4()
	value := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
	value += uint32(slot)
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

// A hardware address is locally administered and a function of an IPv4
// address, so the two are checked as a pair. macFor is a VM's own;
// the others are the daemon's ends of the links it makes, set rather
// than read so that every neighbour entry can be permanent.
func macFor(addr netip.Addr) string        { return macWith(0x54, addr) }
func gatewayMACFor(addr netip.Addr) string { return macWith(0x55, addr) }
func linkMACFor(addr netip.Addr) string    { return macWith(0x56, addr) }
func uplinkMACFor(addr netip.Addr) string  { return macWith(0x57, addr) }
func macWith(kind byte, addr netip.Addr) string {
	raw := addr.As4()
	return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", kind, raw[0], raw[1], raw[2], raw[3])
}

// GuestNetwork is one VM's network device and what its guest is told.
type GuestNetwork struct {
	// Tap is the open tap, for the hypervisor to inherit. The caller
	// closes it once the hypervisor has it (or was never started).
	Tap *os.File
	// MAC is the guest's address on the device, HostMAC the host's.
	MAC, HostMAC     string
	Address, Gateway netip.Addr
	// DNS is set on the open tier only.
	DNS  []netip.Addr
	Tier string
}

// Network gives VMs their network devices.
type Network interface {
	// Gateway is the address every guest reaches its run's proxy at.
	Gateway() netip.Addr
	// Listen makes the place in the network of the VM that will have
	// the given name, and a listener in it on the gateway address: the
	// only thing an allowlist run's guest can connect to. Closing the
	// listener gives the place back if no VM was ever attached to it.
	Listen(ctx context.Context, name string) (net.Listener, error)
	// Attach makes the device for a VM on a tier: run.NetworkAllowlist
	// with the port of the run's proxy, which Listen made the listener
	// for, or run.NetworkOpen.
	Attach(ctx context.Context, name, tier string, proxyPort int) (*GuestNetwork, error)
	// Detach removes a VM's device and everything that admitted it.
	// Detaching what is not attached succeeds.
	Detach(ctx context.Context, name string) error
	// Sweep removes what a previous daemon life left; it returns the
	// number of devices removed.
	Sweep(ctx context.Context) (int, error)
	// Close stops the network's upkeep and, when no VM is attached,
	// removes its table.
	Close(ctx context.Context) error
}

// netSys is the host as the network uses it; tests replace it. Where a
// function takes a namespace, the empty name is the host's own.
type netSys struct {
	// run runs ip, nft or conntrack and returns its stdout.
	run func(ctx context.Context, ns, name string, args ...string) ([]byte, error)
	// nft applies a script as one transaction; ip applies a batch of ip
	// commands, stopping at the first that fails.
	nft func(ctx context.Context, ns, script string) error
	ip  func(ctx context.Context, ns, batch string) error
	// openTap creates a tap device, down, and returns it open.
	openTap func(ns, name string) (*os.File, error)
	// listen makes a TCP listener that belongs to the namespace.
	listen func(ns, addr string) (net.Listener, error)
	// sysctl writes one value under /proc/sys.
	sysctl func(ns, key, value string) error
	// links lists the host's interfaces and namespaces the named network
	// namespaces.
	links      func() ([]string, error)
	namespaces func() ([]string, error)
	// addresses is every IPv4 destination the host takes for itself: its
	// own addresses and the broadcast addresses of their subnets.
	addresses func() ([]netip.Addr, error)
}

func realNetSys() netSys {
	command := func(ctx context.Context, ns string, stdin string, name string, args ...string) ([]byte, error) {
		var stdout, stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		// Started from a thread that is in the namespace, the command is
		// in it too.
		if err := inNamespace(ns, cmd.Run); err != nil {
			return nil, &CommandError{Command: strings.TrimSpace(name + " " + strings.Join(args, " ")), Stderr: strings.TrimSpace(stderr.String()), Err: err}
		}
		return stdout.Bytes(), nil
	}
	return netSys{
		run: func(ctx context.Context, ns, name string, args ...string) ([]byte, error) {
			return command(ctx, ns, "", name, args...)
		},
		nft: func(ctx context.Context, ns, script string) error {
			_, err := command(ctx, ns, script, "nft", "-f", "-")
			return err
		},
		ip: func(ctx context.Context, ns, batch string) error {
			_, err := command(ctx, ns, batch, "ip", "-batch", "-")
			return err
		},
		openTap: func(ns, name string) (tap *os.File, err error) {
			return tap, inNamespace(ns, func() error {
				tap, err = openTap(name)
				return err
			})
		},
		listen: func(ns, addr string) (listener net.Listener, err error) {
			return listener, inNamespace(ns, func() error {
				listener, err = net.Listen("tcp4", addr)
				return err
			})
		},
		sysctl: func(ns, key, value string) error {
			return inNamespace(ns, func() error { return os.WriteFile("/proc/sys/"+key, []byte(value), 0) })
		},
		links: func() ([]string, error) {
			interfaces, err := net.Interfaces()
			if err != nil {
				return nil, err
			}
			names := make([]string, 0, len(interfaces))
			for _, each := range interfaces {
				names = append(names, each.Name)
			}
			return names, nil
		},
		namespaces: func() ([]string, error) {
			entries, err := os.ReadDir(netnsDir)
			if os.IsNotExist(err) {
				return nil, nil
			}
			names := make([]string, 0, len(entries))
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			return names, err
		},
		addresses: func() ([]netip.Addr, error) {
			byInterface, err := hostAddresses()
			if err != nil {
				return nil, err
			}
			var found []netip.Addr
			for _, prefixes := range byInterface {
				for _, prefix := range prefixes {
					found = append(found, ownDestinations(prefix)...)
				}
			}
			return found, nil
		},
	}
}

// attachment is one VM's place in the network: its namespace and what
// is in it.
type attachment struct {
	name, ns, tap, link, mac, tier string
	slot                           int
	addr                           netip.Addr
	proxyPort                      int
	// listener is an allowlist run's proxy listener, in the namespace.
	listener net.Listener
	// attached: a VM was given the tap. Until then the place is only
	// held for one.
	attached bool
	// closing: no longer admitted, not yet cleaned up.
	closing bool
	// hostAddrs is the host's addresses the namespace has no route to.
	hostAddrs []netip.Addr
	// rules is the namespace's ruleset as the kernel listed it when it
	// was last written; gone says its tap went with its VM.
	rules string
	gone  bool
}

// errSuperseded is what a network answers once another instance of this
// daemon identity has taken the tables over.
var errSuperseded = errors.New("another daemon instance has taken over the vm network")

const watchInterval = 2 * time.Second

type hostNetwork struct {
	plan netPlan
	sys  netSys
	log  *slog.Logger
	// instance marks the host's table as written by this hostNetwork: a
	// chain of that name exists in it.
	instance string

	mu         sync.Mutex
	attached   map[string]*attachment
	slots      map[int]bool
	next       int
	superseded bool
	// hostRules is the host's table as the kernel listed it when it was
	// last written.
	hostRules string
	stop      chan struct{}
	stopped   sync.WaitGroup
}

func newHostNetwork(plan netPlan, sys netSys, log *slog.Logger) *hostNetwork {
	mark := make([]byte, 6)
	_, _ = rand.Read(mark)
	return &hostNetwork{
		plan: plan, sys: sys, log: log,
		instance: instancePrefix + hex.EncodeToString(mark),
		attached: map[string]*attachment{},
		slots:    map[int]bool{},
	}
}

func (n *hostNetwork) Gateway() netip.Addr { return n.plan.gateway }

// current is the hostNetwork of this process that last started on each
// table. One daemon has one; a second one in the same process (a test
// that restarts its daemon) replaces the first, which is told at once
// rather than left to find the other's mark in the tables.
var current = struct {
	sync.Mutex
	byTable map[string]*hostNetwork
}{byTable: map[string]*hostNetwork{}}

func (n *hostNetwork) claim() {
	current.Lock()
	previous := current.byTable[n.plan.table]
	current.byTable[n.plan.table] = n
	current.Unlock()
	if previous != nil && previous != n {
		previous.mu.Lock()
		previous.superseded = true
		previous.mu.Unlock()
	}
}

// start writes the host's table and begins watching it. From here on a
// link of this daemon identity that nothing admits is dropped at every
// hook: whatever a previous daemon life left running has no way out.
func (n *hostNetwork) start(ctx context.Context) error {
	n.claim()
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.writeHostLocked(ctx); err != nil {
		return fmt.Errorf("install the firewall (nftables with the inet family is needed): %w", err)
	}
	// An accept in this daemon's table does not overrule a drop in
	// another's: every table on a hook has to let a packet pass.
	if listing, err := n.sys.run(ctx, "", "nft", "list", "chains"); err == nil {
		for _, chain := range foreignDropChains(string(listing), n.plan.table) {
			n.log.Warn("another firewall table drops forwarded traffic by default; unless it allows what arrives on this daemon's links, runs with network \"open\" will not reach the internet",
				"chain", chain, "links", n.plan.linkPrefix+"*", "subnet", n.plan.subnet.String())
		}
	}
	n.stop = make(chan struct{})
	n.stopped.Add(1)
	go n.watch(n.stop)
	return nil
}

// foreignDropChains finds, in the output of `nft list chains`, the
// forward base chains of other tables whose policy is drop. Only the
// open tier passes the host's firewall at all: an allowlist run reaches
// its proxy inside its own namespace.
func foreignDropChains(listing, ownTable string) []string {
	var found []string
	table, chain := "", ""
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) >= 3 && fields[0] == "table":
			table = fields[1] + " " + fields[2]
		case len(fields) >= 2 && fields[0] == "chain":
			chain = fields[1]
		case len(fields) >= 4 && fields[0] == "type" && strings.Contains(line, "policy drop"):
			hook := ""
			for i, field := range fields {
				if field == "hook" && i+1 < len(fields) {
					hook = fields[i+1]
				}
			}
			if hook == "forward" && !strings.HasSuffix(table, " "+ownTable) {
				found = append(found, "table "+table+" chain "+chain+" (hook "+hook+")")
			}
		}
	}
	return found
}

func (n *hostNetwork) blocked() []string {
	if n.plan.openPrivate {
		return neverReachable
	}
	return notPublic
}

func joinAddrs(addrs []netip.Addr) string {
	text := make([]string, len(addrs))
	for i, addr := range addrs {
		text[i] = addr.String()
	}
	return strings.Join(text, ", ")
}

// rulesLocked is the host's whole table as one transaction that replaces
// whatever is there. It is a function of the attached open runs alone,
// so it can be applied again at any time, and a table that something
// else removed or emptied is put back exactly.
//
// Only open runs' links exist on the host, so only they are judged here,
// and what is said here is said again inside each run's namespace.
func (n *hostNetwork) rulesLocked() string {
	p := n.plan
	var open []string
	for _, each := range n.attached {
		if each.closing || !each.attached || each.tier != run.NetworkOpen {
			continue
		}
		open = append(open, fmt.Sprintf("%q . %s", each.link, each.addr))
	}
	slices.Sort(open)
	elements := ""
	if len(open) > 0 {
		elements = " elements = { " + strings.Join(open, ", ") + " }"
	}
	links := fmt.Sprintf("%q", p.linkPrefix+"*")
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	// "add" first so that "delete" cannot fail on a table that is not
	// there; the three statements are one transaction, so there is no
	// moment without the table.
	line("add table inet %s", p.table)
	line("delete table inet %s", p.table)
	line("table inet %s {", p.table)
	line("	set open { type ifname . ipv4_addr;%s }", elements)
	line("	chain %s { }", n.instance)
	// What an open run sends through the host.
	line("	chain from_guest {")
	line("		meta nfproto != ipv4 counter drop")
	line("		oifname %s counter drop", links)
	line("		ip daddr %s counter drop", p.subnet)
	line("		iifname . ip saddr != @open counter drop")
	if len(p.dns) > 0 {
		line("		ip daddr { %s } meta l4proto { tcp, udp } th dport 53 accept", joinAddrs(p.dns))
	}
	line("		ip daddr { %s } counter drop", strings.Join(n.blocked(), ", "))
	line("		tcp dport 25 counter drop")
	line("		accept")
	line("	}")
	// What the host forwards to a guest: answers, nothing else.
	line("	chain to_guest {")
	line("		ct state established,related accept")
	line("		counter drop")
	line("	}")
	// What a guest sends to the host itself, on any of its addresses:
	// nothing is for it there.
	line("	chain input {")
	line("		type filter hook input priority filter - 5; policy accept;")
	line("		iifname %s counter drop", links)
	line("	}")
	line("	chain forward {")
	line("		type filter hook forward priority filter - 5; policy accept;")
	line("		iifname %s jump from_guest", links)
	line("		oifname %s jump to_guest", links)
	line("	}")
	line("	chain postrouting {")
	line("		type nat hook postrouting priority srcnat; policy accept;")
	line("		iifname %s oifname != %s ip saddr %s masquerade", links, links, p.subnet)
	line("	}")
	line("}")
	return b.String()
}

// runRules is the whole ruleset of one run's namespace, as one
// transaction that replaces whatever is there. With sealed, nothing
// passes: the state of a namespace that has no VM (yet, or any more).
//
// Both base chains drop by default, so a rule that is missing closes
// something rather than opening it.
func (n *hostNetwork) runRules(a *attachment, sealed bool) string {
	p := n.plan
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	for _, family := range []string{"inet", "netdev"} {
		line("add table %s %s", family, runTable)
		line("delete table %s %s", family, runTable)
	}
	if !sealed {
		// At the tap's ingress hook a frame is judged before any of the
		// namespace's protocol code runs on it.
		line("table netdev %s {", runTable)
		line("	chain ingress {")
		line("		type filter hook ingress device %q priority -300; policy drop;", a.tap)
		// ARP: only a question about the gateway, from the VM's own MAC
		// and address. Nobody has to ask a guest anything (the neighbour
		// entry for the guest is permanent), so no answer is let in.
		line("		ether saddr %s ether type arp arp htype 1 arp ptype ip arp hlen 6 arp plen 4 arp operation request arp saddr ether %s arp saddr ip %s arp daddr ip %s accept",
			a.mac, a.mac, a.addr, p.gateway)
		line("		ether saddr %s ether type ip ip saddr %s ip daddr != { 224.0.0.0/4, 255.255.255.255 } accept", a.mac, a.addr)
		// Everything else: another MAC or source address, IPv6, VLAN
		// tags, multicast, any other ethertype.
		line("		counter drop")
		line("	}")
		line("}")
	}
	line("table inet %s {", runTable)
	// What the guest sends to the namespace itself: its proxy's port on
	// the gateway address, if it has a proxy.
	line("	chain input {")
	line("		type filter hook input priority filter; policy drop;")
	line("		meta nfproto != ipv4 counter drop")
	if !sealed && a.tier == run.NetworkAllowlist {
		line("		iifname %q ip saddr %s ip daddr %s tcp dport %d accept", a.tap, a.addr, p.gateway, a.proxyPort)
	}
	line("		counter drop")
	line("	}")
	line("	chain forward {")
	line("		type filter hook forward priority filter; policy drop;")
	line("		meta nfproto != ipv4 counter drop")
	if !sealed && a.tier == run.NetworkOpen {
		// To the guest: answers, nothing else.
		line("		iifname %q oifname %q ct state established,related accept", uplinkDev, a.tap)
		line("		iifname %q oifname %q ip saddr %s jump out", a.tap, uplinkDev, a.addr)
	}
	line("		counter drop")
	line("	}")
	if !sealed && a.tier == run.NetworkOpen {
		line("	chain out {")
		line("		ip daddr %s counter drop", p.subnet)
		if len(a.hostAddrs) > 0 {
			line("		ip daddr { %s } counter drop", joinAddrs(a.hostAddrs))
		}
		if len(p.dns) > 0 {
			line("		ip daddr { %s } meta l4proto { tcp, udp } th dport 53 accept", joinAddrs(p.dns))
		}
		line("		ip daddr { %s } counter drop", strings.Join(n.blocked(), ", "))
		line("		tcp dport 25 counter drop")
		line("		accept")
		line("	}")
	}
	line("}")
	return b.String()
}

// openRoutes is the routing of an open run's namespace: where a packet
// from the guest can go when no firewall rule is asked. The ranges that
// are not the public internet, the guests' subnet and the host's own
// addresses are unreachable routes; port 25 is an unreachable rule; DNS
// to the configured resolvers, which may be in a private range, is
// looked up in a table of its own that knows only the link.
func (n *hostNetwork) openRoutes(a *attachment) string {
	p := n.plan
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	line("link set dev %s up", uplinkDev)
	// Permanent: nothing is asked on the link and nothing sent on it can
	// change the answer.
	line("neigh replace %s lladdr %s dev %s nud permanent", uplinkHop, linkMACFor(a.addr), uplinkDev)
	line("rule add pref 100 ipproto tcp dport 25 unreachable")
	for i, resolver := range p.dns {
		line("rule add pref %d to %s/32 ipproto udp dport 53 lookup %s", 200+2*i, resolver, dnsTable)
		line("rule add pref %d to %s/32 ipproto tcp dport 53 lookup %s", 201+2*i, resolver, dnsTable)
	}
	line("route replace default via %s dev %s onlink table %s", uplinkHop, uplinkDev, dnsTable)
	for _, blocked := range append(slices.Clone(n.blocked()), p.subnet.String()) {
		line("route replace unreachable %s", blocked)
	}
	b.WriteString(hostRoutes(nil, a.hostAddrs))
	line("route replace default via %s dev %s onlink", uplinkHop, uplinkDev)
	return b.String()
}

// hostRoutes is the batch that moves a namespace's unreachable routes
// for the host's own addresses from one set to another.
func hostRoutes(old, current []netip.Addr) string {
	var b strings.Builder
	for _, addr := range old {
		if !slices.Contains(current, addr) {
			fmt.Fprintf(&b, "route del unreachable %s/32\n", addr)
		}
	}
	for _, addr := range current {
		fmt.Fprintf(&b, "route replace unreachable %s/32\n", addr)
	}
	return b.String()
}

// hostAddrsLocked is the IPv4 destinations the host takes for itself
// (its addresses and its subnets' broadcast addresses) that an open
// run's namespace must have no route to: every one that is not loopback
// (which never has a route from a guest) or in the guests' subnet.
func (n *hostNetwork) hostAddrsLocked() ([]netip.Addr, error) {
	all, err := n.sys.addresses()
	if err != nil {
		return nil, fmt.Errorf("list the host's addresses: %w", err)
	}
	var addrs []netip.Addr
	for _, addr := range all {
		addr = addr.Unmap()
		if addr.Is4() && !addr.IsLoopback() && !n.plan.subnet.Contains(addr) && !slices.Contains(addrs, addr) {
			addrs = append(addrs, addr)
		}
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	return addrs, nil
}

// tableState asks who wrote the host's table: this instance, another
// one, or nobody (it is gone).
type tableState int

const (
	tablesOurs tableState = iota
	tablesForeign
	tablesMissing
	// tablesUnknown: the kernel could not be asked. Nothing is concluded
	// from it; whoever asked asks again.
	tablesUnknown
)

// instancePrefix starts the name of the chain each hostNetwork marks the
// host's table with.
const instancePrefix = "instance_"

// tableStateLocked asks the kernel whose the host's table is.
//
// Another instance has taken over only when its mark is there to be
// read. That this instance's own mark could not be listed says nothing
// by itself: a command that could not be started, or was killed, or ran
// out of memory fails the same way, and an instance that stood down on
// that would leave every run it has without upkeep until a restart. So a
// table that is there without any mark, or not there at all, is one to
// write again, and a kernel that cannot be asked is asked again later.
func (n *hostNetwork) tableStateLocked(ctx context.Context) (tableState, error) {
	if n.superseded {
		return tablesForeign, nil
	}
	if _, err := n.sys.run(ctx, "", "nft", "list", "chain", "inet", n.plan.table, n.instance); err == nil {
		return tablesOurs, nil
	}
	listing, err := n.sys.run(ctx, "", "nft", "list", "table", "inet", n.plan.table)
	switch {
	case err != nil && isGone(err):
		return tablesMissing, nil
	case err != nil:
		return tablesUnknown, fmt.Errorf("ask the kernel for the firewall table %s: %w", n.plan.table, err)
	}
	ours := false
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "chain" || !strings.HasPrefix(fields[1], instancePrefix) {
			continue
		}
		if fields[1] != n.instance {
			n.superseded = true
			n.log.Warn("another daemon instance has taken over the vm firewall table; this one stops its upkeep", "table", n.plan.table, "mark", fields[1])
			return tablesForeign, nil
		}
		ours = true
	}
	if ours {
		// The first question failed and the second found the mark.
		return tablesOurs, nil
	}
	return tablesMissing, nil
}

// ownedLocked is the question everything that changes the network asks
// first: it is refused when another instance has the table, and when
// the kernel cannot say.
func (n *hostNetwork) ownedLocked(ctx context.Context) error {
	switch state, err := n.tableStateLocked(ctx); state {
	case tablesForeign:
		return errSuperseded
	case tablesUnknown:
		return err
	}
	return nil
}

// listHost and listRun are a ruleset as the kernel has it, without its
// counters: what is compared to find a change.
func (n *hostNetwork) listHost(ctx context.Context) (string, error) {
	out, err := n.sys.run(ctx, "", "nft", "-s", "list", "table", "inet", n.plan.table)
	return string(out), err
}

func (n *hostNetwork) listRun(ctx context.Context, a *attachment) (string, error) {
	out, err := n.sys.run(ctx, a.ns, "nft", "-s", "list", "ruleset")
	return string(out), err
}

// writeHostLocked writes the host's table and remembers how the kernel
// lists it.
func (n *hostNetwork) writeHostLocked(ctx context.Context) error {
	if err := n.sys.nft(ctx, "", n.rulesLocked()); err != nil {
		return err
	}
	listing, err := n.listHost(ctx)
	if err != nil {
		return fmt.Errorf("read the firewall back: %w", err)
	}
	n.hostRules = listing
	return nil
}

// writeRun writes a run's ruleset and remembers how the kernel lists it.
func (n *hostNetwork) writeRun(ctx context.Context, a *attachment, sealed bool) error {
	if err := n.sys.nft(ctx, a.ns, n.runRules(a, sealed)); err != nil {
		return err
	}
	listing, err := n.listRun(ctx, a)
	if err != nil {
		return fmt.Errorf("read the ruleset back: %w", err)
	}
	a.rules = listing
	return nil
}

// applyLocked brings the host's table in line with the attached VMs.
func (n *hostNetwork) applyLocked(ctx context.Context) error {
	if state, _ := n.tableStateLocked(ctx); state == tablesForeign {
		return errSuperseded
	}
	return n.writeHostLocked(ctx)
}

// watch puts back what something else removed or changed. A host's own
// firewall reload often starts with "flush ruleset". That does not open
// anything (see the top of this file), but it does take the open runs'
// way out, and a rule that was changed by hand is not the rule that was
// reviewed.
func (n *hostNetwork) watch(stop <-chan struct{}) {
	defer n.stopped.Done()
	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		if !n.check(context.Background()) {
			return
		}
	}
}

// check is one look at every ruleset this network wrote; it reports
// whether to keep looking. It stops only when another instance's mark is
// on the table: a look that failed is followed by the next.
func (n *hostNetwork) check(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	n.mu.Lock()
	defer n.mu.Unlock()
	switch state, err := n.tableStateLocked(ctx); state {
	case tablesForeign:
		return false
	case tablesUnknown:
		// The runs' own rulesets are still looked at below.
		n.log.Error("the vm firewall table could not be checked; trying again", "table", n.plan.table, "error", err)
	case tablesMissing:
		n.log.Error("the vm firewall table was removed by something else; putting it back", "table", n.plan.table)
		if err := n.writeHostLocked(ctx); err != nil {
			n.log.Error("restore the vm firewall table", "error", err)
			return true
		}
	default:
		if listing, err := n.listHost(ctx); err != nil || listing != n.hostRules {
			n.log.Error("the vm firewall table was changed by something else; putting it back", "table", n.plan.table)
			if err := n.writeHostLocked(ctx); err != nil {
				n.log.Error("restore the vm firewall table", "error", err)
				return true
			}
		}
	}
	hostAddrs, addrsErr := n.hostAddrsLocked()
	for _, each := range n.attached {
		if each.closing || !each.attached || each.gone {
			continue
		}
		if addrsErr == nil && each.tier == run.NetworkOpen && !slices.Equal(hostAddrs, each.hostAddrs) {
			// The host got or lost an address: the namespace's routes
			// and rules name the ones it has now.
			if err := n.sys.ip(ctx, each.ns, hostRoutes(each.hostAddrs, hostAddrs)); err != nil {
				n.log.Error("update a run's routes to the host's addresses", "namespace", each.ns, "error", err)
				continue
			}
			each.hostAddrs = hostAddrs
			if err := n.writeRun(ctx, each, false); err != nil {
				n.log.Error("update a run's ruleset to the host's addresses", "namespace", each.ns, "error", err)
			}
			continue
		}
		if listing, err := n.listRun(ctx, each); err == nil && listing == each.rules {
			continue
		}
		if _, err := n.sys.run(ctx, each.ns, "ip", "link", "show", "dev", each.tap); err != nil {
			// The VM is gone (its guest powered off, or its hypervisor
			// died) and took the tap along, and the kernel removed the
			// tap's filter with the device. There is nothing left to
			// filter; the namespace is sealed until the run is removed.
			// Said once: a guest must not be able to make the daemon log
			// an error every two seconds by shutting down.
			each.gone = true
			if err := n.writeRun(ctx, each, true); err != nil && !isGone(err) {
				n.log.Error("seal the namespace of a VM that is gone", "namespace", each.ns, "error", err)
			}
			continue
		}
		n.log.Error("a run's ruleset was removed or changed by something else; putting it back", "namespace", each.ns, "tap", each.tap)
		if err := n.writeRun(ctx, each, false); err != nil {
			n.log.Error("restore a run's ruleset", "namespace", each.ns, "error", err)
		}
	}
	return true
}

// Sysctls of a run's namespace, set before anything is in it. No IPv6
// at all: no link-local address, no neighbour discovery, no router
// advertisements in either direction. A packet is only accepted from the
// interface its source is routed to, which for the tap is the VM's one
// address. Nothing is routed until a run is open, and the namespace's
// own addresses do not answer a ping: the gateway address is where a
// proxy listens and nothing else.
var namespaceSysctls = [][2]string{
	{"net/ipv4/icmp_echo_ignore_all", "1"},
	{"net/ipv6/conf/all/disable_ipv6", "1"},
	{"net/ipv6/conf/default/disable_ipv6", "1"},
	{"net/ipv4/ip_forward", "0"},
	{"net/ipv4/conf/all/rp_filter", "1"},
	{"net/ipv4/conf/default/rp_filter", "1"},
	{"net/ipv4/conf/all/accept_redirects", "0"},
	{"net/ipv4/conf/default/accept_redirects", "0"},
	{"net/ipv4/conf/all/send_redirects", "0"},
	{"net/ipv4/conf/default/send_redirects", "0"},
	{"net/ipv4/conf/all/proxy_arp", "0"},
	{"net/ipv4/conf/default/proxy_arp", "0"},
}

// placeLocked makes the place of the VM that will be called name: a slot,
// an address, and a namespace that holds the gateway address, lets
// nothing in and leads nowhere.
func (n *hostNetwork) placeLocked(ctx context.Context, name string) (_ *attachment, err error) {
	if _, exists := n.attached[name]; exists {
		return nil, fmt.Errorf("%s already has a place in the network", name)
	}
	if err := n.ownedLocked(ctx); err != nil {
		return nil, err
	}
	// The next free slot after the last one given out, not the lowest: an
	// address is not handed to a new VM while anything might still
	// remember the VM that had it before.
	slot := -1
	for i := 0; i < n.plan.slots; i++ {
		if candidate := (n.next + i) % n.plan.slots; !n.slots[candidate] {
			slot = candidate
			break
		}
	}
	if slot < 0 {
		return nil, fmt.Errorf("all %d guest addresses in %s are in use", n.plan.slots, n.plan.subnet)
	}
	a := &attachment{name: name, slot: slot, ns: n.plan.nsName(slot), tap: n.plan.tapName(slot), link: n.plan.linkName(slot), addr: n.plan.address(slot)}
	a.mac = macFor(a.addr)
	n.next = (slot + 1) % n.plan.slots
	n.slots[slot] = true
	n.attached[name] = a
	defer func() {
		if err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			// What cannot be cleaned up now stays known, and the Detach
			// the caller makes on failure tries again.
			err = errors.Join(err, n.detachLocked(cleanupCtx, name))
		}
	}()
	// A namespace or a link of this name can only be a leftover: the slot
	// was free.
	if err = n.removeLocked(ctx, a); err != nil {
		return nil, err
	}
	if _, err = n.sys.run(ctx, "", "ip", "netns", "add", a.ns); err != nil {
		return nil, fmt.Errorf("create the network namespace %s: %w", a.ns, err)
	}
	for _, setting := range namespaceSysctls {
		if err = n.sys.sysctl(a.ns, setting[0], setting[1]); err != nil && !(os.IsNotExist(err) && strings.Contains(setting[0], "ipv6")) {
			return nil, fmt.Errorf("set %s in %s: %w", setting[0], a.ns, err)
		}
	}
	// The rules before anything can arrive.
	if err = n.writeRun(ctx, a, true); err != nil {
		return nil, fmt.Errorf("seal %s: %w", a.ns, err)
	}
	// The gateway address is the namespace's own, on its loopback: it is
	// there before the tap is, for the proxy to listen on.
	if err = n.sys.ip(ctx, a.ns, fmt.Sprintf("link set dev lo up\naddr replace %s/32 dev lo\n", n.plan.gateway)); err != nil {
		return nil, fmt.Errorf("give %s the gateway address: %w", a.ns, err)
	}
	return a, nil
}

func (n *hostNetwork) Listen(ctx context.Context, name string) (net.Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	a, err := n.placeLocked(ctx, name)
	if err != nil {
		return nil, err
	}
	// The socket belongs to the namespace: it is reachable from the run's
	// tap and from nowhere else, and what it accepts is served by the
	// daemon, in the host's namespace. The port is the slot's own, so no
	// two runs that exist at the same time have the same proxy address,
	// and a port is not used again before the namespace that had it is
	// gone.
	listener, err := n.sys.listen(a.ns, net.JoinHostPort(n.plan.gateway.String(), fmt.Sprint(proxyPortBase+a.slot)))
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		return nil, errors.Join(fmt.Errorf("listen in %s: %w", a.ns, err), n.detachLocked(cleanupCtx, name))
	}
	a.tier, a.listener = run.NetworkAllowlist, listener
	a.proxyPort = proxyPortBase + a.slot
	return &placedListener{Listener: listener, network: n, place: a}, nil
}

// placedListener is a run's proxy listener. Closing it gives back the
// place it was made in, unless a VM has it: then the place goes when the
// VM is detached.
type placedListener struct {
	net.Listener
	network *hostNetwork
	place   *attachment
	once    sync.Once
}

func (l *placedListener) Close() (err error) {
	l.once.Do(func() {
		err = l.Listener.Close()
		n := l.network
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.attached[l.place.name] != l.place || l.place.attached {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if detachErr := n.detachLocked(ctx, l.place.name); detachErr != nil {
			n.log.Error("give back the network place of a run that never started", "namespace", l.place.ns, "error", detachErr)
		}
	})
	return err
}

func (n *hostNetwork) Attach(ctx context.Context, name, tier string, proxyPort int) (_ *GuestNetwork, err error) {
	switch {
	case tier == run.NetworkAllowlist && (proxyPort < 1 || proxyPort > 65535):
		return nil, errors.New("an allowlist run needs its proxy's port")
	case tier != run.NetworkAllowlist && tier != run.NetworkOpen:
		return nil, fmt.Errorf("no network device for tier %q", tier)
	case tier == run.NetworkOpen && len(n.plan.dns) == 0:
		return nil, errors.New("no DNS resolver to give an open run")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	a := n.attached[name]
	switch {
	case a != nil && (a.attached || a.closing):
		return nil, fmt.Errorf("%s already has a network device", name)
	case tier == run.NetworkAllowlist && (a == nil || a.listener == nil || a.proxyPort != proxyPort):
		// The proxy is the tier, and it has to listen where this guest,
		// and no other, can reach it.
		return nil, fmt.Errorf("the proxy of %s does not listen on port %d in the run's own network namespace", name, proxyPort)
	case tier == run.NetworkOpen && a != nil:
		return nil, fmt.Errorf("%s holds a place in the network for a proxy, and an open run has none", name)
	}
	if err := n.ownedLocked(ctx); err != nil {
		return nil, err
	}
	if a == nil {
		if a, err = n.placeLocked(ctx, name); err != nil {
			return nil, err
		}
	}
	a.tier, a.attached = tier, true

	var tap *os.File
	defer func() {
		if err != nil {
			if tap != nil {
				_ = tap.Close()
			}
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			// What cannot be cleaned up now stays known, and the Detach
			// the caller makes on failure tries again.
			err = errors.Join(err, n.detachLocked(cleanupCtx, name))
		}
	}()

	if tier == run.NetworkOpen {
		if a.hostAddrs, err = n.hostAddrsLocked(); err != nil {
			return nil, err
		}
		// Whatever the host's connection tracker remembers about this
		// address belongs to a VM that is gone.
		if err = n.forgetConnections(ctx, a.addr); err != nil {
			return nil, err
		}
		// The link: one end on the host, the other in the namespace,
		// both down, with addresses that are set rather than learned.
		if _, err = n.sys.run(ctx, "", "ip", "link", "add", a.link, "address", linkMACFor(a.addr),
			"type", "veth", "peer", "name", uplinkDev, "address", uplinkMACFor(a.addr), "netns", a.ns); err != nil {
			return nil, fmt.Errorf("create the link %s: %w", a.link, err)
		}
		conf4, conf6 := "net/ipv4/conf/"+a.link+"/", "net/ipv6/conf/"+a.link+"/"
		if err = n.sys.sysctl("", conf6+"disable_ipv6", "1"); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("turn IPv6 off on %s: %w", a.link, err)
		}
		for _, setting := range [][2]string{{"forwarding", "1"}, {"rp_filter", "1"}, {"proxy_arp", "0"}, {"send_redirects", "0"}, {"accept_redirects", "0"}} {
			if err = n.sys.sysctl("", conf4+setting[0], setting[1]); err != nil {
				return nil, fmt.Errorf("set %s on %s: %w", setting[0], a.link, err)
			}
		}
	}
	if tap, err = n.sys.openTap(a.ns, a.tap); err != nil {
		return nil, fmt.Errorf("create tap %s in %s: %w", a.tap, a.ns, err)
	}
	// The devices are down. Everything that decides what they may do is
	// in place before they are brought up: the namespace's ruleset, the
	// host's table, the routes.
	if err = n.sys.ip(ctx, a.ns, fmt.Sprintf("link set dev %s address %s\n", a.tap, gatewayMACFor(n.plan.gateway))); err != nil {
		return nil, fmt.Errorf("set the address of %s: %w", a.tap, err)
	}
	if err = n.writeRun(ctx, a, false); err != nil {
		return nil, fmt.Errorf("install the ruleset of %s: %w", a.ns, err)
	}
	var routes strings.Builder
	fmt.Fprintf(&routes, "link set dev %s up\n", a.tap)
	fmt.Fprintf(&routes, "route replace %s/32 dev %s\n", a.addr, a.tap)
	// Permanent: the guest is never asked who has its address, and
	// nothing it sends can change the answer.
	fmt.Fprintf(&routes, "neigh replace %s lladdr %s dev %s nud permanent\n", a.addr, a.mac, a.tap)
	if tier == run.NetworkOpen {
		if err = n.writeHostLocked(ctx); err != nil {
			return nil, fmt.Errorf("admit %s: %w", a.link, err)
		}
		routes.WriteString(n.openRoutes(a))
	}
	if err = n.sys.ip(ctx, a.ns, routes.String()); err != nil {
		return nil, fmt.Errorf("route %s: %w", a.ns, err)
	}
	if tier == run.NetworkOpen {
		// Last: the kernel's own switch in the namespace, and the host's
		// end of the link.
		if err = n.sys.sysctl(a.ns, "net/ipv4/ip_forward", "1"); err != nil {
			return nil, fmt.Errorf("turn forwarding on in %s: %w", a.ns, err)
		}
		if err = n.sys.ip(ctx, "", fmt.Sprintf("link set dev %[1]s up\nroute replace %[2]s/32 dev %[1]s\nneigh replace %[2]s lladdr %[3]s dev %[1]s nud permanent\n",
			a.link, a.addr, uplinkMACFor(a.addr))); err != nil {
			return nil, fmt.Errorf("route %s on the host: %w", a.link, err)
		}
	}
	guest := &GuestNetwork{Tap: tap, MAC: a.mac, HostMAC: gatewayMACFor(n.plan.gateway), Address: a.addr, Gateway: n.plan.gateway, Tier: tier}
	if tier == run.NetworkOpen {
		guest.DNS = slices.Clone(n.plan.dns)
	}
	return guest, nil
}

// forgetConnections deletes the host's connection tracker's entries that
// began at addr. Without it, whoever a VM was talking to could keep
// sending to the next VM that gets the address, as "answers". (What a
// run's own namespace tracked goes with the namespace.)
func (n *hostNetwork) forgetConnections(ctx context.Context, addr netip.Addr) error {
	_, err := n.sys.run(ctx, "", "conntrack", "-D", "-s", addr.String())
	var failed *CommandError
	// It exits 1 with this message when there was nothing to delete.
	if err != nil && !(errors.As(err, &failed) && strings.Contains(failed.Stderr, "0 flow entries")) {
		return fmt.Errorf("forget tracked connections of %s: %w", addr, err)
	}
	return nil
}

func (n *hostNetwork) Detach(ctx context.Context, name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.detachLocked(ctx, name)
}

// removeLocked removes a place's link and namespace, and with the
// namespace everything in it. Both may be gone already.
func (n *hostNetwork) removeLocked(ctx context.Context, a *attachment) error {
	if _, err := n.sys.run(ctx, "", "ip", "link", "del", a.link); err != nil && !isGone(err) {
		return fmt.Errorf("remove the link %s: %w", a.link, err)
	}
	if _, err := n.sys.run(ctx, "", "ip", "netns", "del", a.ns); err != nil && !isGone(err) {
		return fmt.Errorf("remove the network namespace %s: %w", a.ns, err)
	}
	return nil
}

// detachLocked can be repeated: every step succeeds on what is already
// gone, and the VM's slot is only free once all of them have.
func (n *hostNetwork) detachLocked(ctx context.Context, name string) error {
	a, ok := n.attached[name]
	if !ok {
		return nil
	}
	// First the admission: from here the link is one the host's table
	// does not know, and it drops everything from it.
	a.closing = true
	if a.tier == run.NetworkOpen && a.attached {
		if err := n.applyLocked(ctx); err != nil && !errors.Is(err, errSuperseded) {
			return fmt.Errorf("revoke %s: %w", a.link, err)
		}
	}
	if !n.superseded {
		// The tap goes with the hypervisor that held it. The namespace
		// goes here, and its rules, routes and connection tracking with
		// it. Should a hypervisor that could not be killed still hold
		// the tap, the kernel keeps the namespace for it, without a
		// name and without the link: it leads nowhere.
		if err := n.removeLocked(ctx, a); err != nil {
			return err
		}
		if a.tier == run.NetworkOpen && a.attached {
			if err := n.forgetConnections(ctx, a.addr); err != nil {
				return err
			}
		}
	}
	delete(n.attached, name)
	delete(n.slots, a.slot)
	return nil
}

// isGone reports whether a command failed because what it was to remove
// is not there.
func isGone(err error) bool {
	var failed *CommandError
	if !errors.As(err, &failed) {
		return false
	}
	return strings.Contains(failed.Stderr, "No such file or directory") || strings.Contains(failed.Stderr, "Cannot find device") || strings.Contains(failed.Stderr, "No such device")
}

func (n *hostNetwork) Sweep(ctx context.Context) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.ownedLocked(ctx); err != nil {
		return 0, err
	}
	live := map[string]bool{}
	for _, each := range n.attached {
		live[each.ns], live[each.link] = true, true
	}
	removed := 0
	namespaces, err := n.sys.namespaces()
	if err != nil {
		return 0, fmt.Errorf("list network namespaces: %w", err)
	}
	for _, name := range namespaces {
		if !strings.HasPrefix(name, n.plan.nsPrefix) || live[name] {
			continue
		}
		if _, err := n.sys.run(ctx, "", "ip", "netns", "del", name); err != nil && !isGone(err) {
			return removed, fmt.Errorf("remove leftover network namespace %s: %w", name, err)
		}
		removed++
	}
	links, err := n.sys.links()
	if err != nil {
		return removed, fmt.Errorf("list interfaces: %w", err)
	}
	for _, name := range links {
		// The links of open runs, and what a version of this driver that
		// kept guests' taps on the host left there.
		legacy := strings.HasPrefix(name, n.plan.tapPrefix) || name == n.plan.legacyGateway
		if !(strings.HasPrefix(name, n.plan.linkPrefix) || legacy) || live[name] {
			continue
		}
		if _, err := n.sys.run(ctx, "", "ip", "link", "del", name); err != nil && !isGone(err) {
			return removed, fmt.Errorf("remove leftover interface %s: %w", name, err)
		}
		if legacy && name != n.plan.legacyGateway {
			removed++
		}
	}
	if err := n.sys.nft(ctx, "", fmt.Sprintf("add table netdev %[1]s\ndelete table netdev %[1]s\n", n.plan.table)); err != nil {
		return removed, err
	}
	return removed, n.writeHostLocked(ctx)
}

func (n *hostNetwork) Close(ctx context.Context) error {
	n.mu.Lock()
	stop := n.stop
	n.stop = nil
	n.mu.Unlock()
	if stop != nil {
		close(stop)
		n.stopped.Wait()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if state, _ := n.tableStateLocked(ctx); len(n.attached) > 0 || state != tablesOurs {
		// A VM that could not be torn down keeps the table that judges
		// its link; a table another instance wrote is that instance's.
		return nil
	}
	n.superseded = true
	return n.sys.nft(ctx, "", fmt.Sprintf("add table inet %[1]s\ndelete table inet %[1]s\n", n.plan.table))
}

// probeNamespace makes, and removes again, a network namespace with
// everything a run's is made of: the namespace itself, a link into it, a
// routing rule that matches a port, a ruleset and a tap. It is how a
// host that cannot do one of these is found before the first create.
func probeNamespace(ctx context.Context, sys netSys, name string) (err error) {
	link := "tvp" + strings.TrimPrefix(strings.TrimSuffix(name, "-probe"), "tvn")
	remove := func() {
		_, _ = sys.run(ctx, "", "ip", "link", "del", link)
		_, _ = sys.run(ctx, "", "ip", "netns", "del", name)
	}
	remove()
	defer remove()
	if _, err := sys.run(ctx, "", "ip", "netns", "add", name); err != nil {
		return err
	}
	if _, err := sys.run(ctx, "", "ip", "link", "add", link, "type", "veth", "peer", "name", uplinkDev, "netns", name); err != nil {
		return fmt.Errorf("a veth link into a namespace: %w", err)
	}
	if err := sys.ip(ctx, name, "rule add pref 100 ipproto tcp dport 25 unreachable\nroute replace unreachable 192.0.2.0/24\n"); err != nil {
		return fmt.Errorf("routing rules in a namespace: %w", err)
	}
	tap, err := sys.openTap(name, "probe")
	if err != nil {
		return fmt.Errorf("a tap in a namespace: %w", err)
	}
	defer tap.Close()
	rules := fmt.Sprintf("table netdev %[1]s {\n chain ingress { type filter hook ingress device \"probe\" priority -300; policy drop; }\n}\ntable inet %[1]s {\n chain forward { type filter hook forward priority filter; policy drop; ct state established,related accept; }\n}\n", runTable)
	if err := sys.nft(ctx, name, rules); err != nil {
		return fmt.Errorf("an nftables ruleset in a namespace (the inet and netdev families and connection tracking are needed): %w", err)
	}
	return nil
}

// hostResolvers is the IPv4 resolvers the host itself uses. Where
// systemd-resolved runs, /etc/resolv.conf names its local stub, which no
// guest can reach; the file it keeps beside it names the real ones.
func hostResolvers(read func(path string) ([]byte, error)) []netip.Addr {
	for _, path := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
		raw, err := read(path)
		if err != nil {
			continue
		}
		var found []netip.Addr
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "nameserver" {
				continue
			}
			if addr, err := netip.ParseAddr(fields[1]); err == nil && addr.Is4() && !addr.IsLoopback() {
				found = append(found, addr)
			}
		}
		if len(found) > 0 {
			return found
		}
	}
	return nil
}

// ownDestinations is every IPv4 destination the host's kernel delivers to
// its own sockets because of one address on one of its interfaces: the
// address itself, and the broadcast address of its subnet. The second is
// easy to miss: a datagram to the broadcast address of any subnet the
// host is on is the host's own whichever interface it arrives on, an
// open run's link included, and every UDP socket bound to all addresses
// gets it. The subnet's first address is the older spelling of the same
// (kernels before 5.14 take it as a broadcast too). A /31 and a /32 have
// neither.
func ownDestinations(prefix netip.Prefix) []netip.Addr {
	addr := prefix.Addr().Unmap()
	if !addr.Is4() {
		return nil
	}
	own := []netip.Addr{addr}
	if bits := prefix.Bits(); bits >= 0 && bits <= 30 {
		raw := addr.As4()
		value := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
		mask := ^uint32(0) << (32 - bits)
		for _, each := range []uint32{value | ^mask, value & mask} {
			own = append(own, netip.AddrFrom4([4]byte{byte(each >> 24), byte(each >> 16), byte(each >> 8), byte(each)}))
		}
	}
	return own
}

// hostAddresses is every address on the host's interfaces, by interface.
func hostAddresses() (map[string][]netip.Prefix, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	found := map[string][]netip.Prefix{}
	for _, each := range interfaces {
		addrs, err := each.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
				found[each.Name] = append(found[each.Name], netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()))
			}
		}
	}
	return found, nil
}

// guestNetScript is what a guest runs, as root, to use its device. It is
// a convenience for the guest and nothing the host relies on: a guest
// that configures itself differently is held to the same rules.
func guestNetScript(n *GuestNetwork) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	line("set -eu")
	line("mac=%s addr=%s gw=%s gwmac=%s", n.MAC, n.Address, n.Gateway, n.HostMAC)
	// The device is found by its address: its name is the guest's choice.
	// It can appear a moment after the agent does.
	line(`dev="" tries=0`)
	line(`while :; do`)
	line(`  for d in /sys/class/net/*; do`)
	line(`    if [ "$(cat "$d/address" 2>/dev/null)" = "$mac" ]; then dev="${d##*/}"; break; fi`)
	line(`  done`)
	line(`  [ -z "$dev" ] || break`)
	line(`  tries=$((tries + 1))`)
	line(`  [ "$tries" -le 150 ] || { echo "no network device with the address $mac appeared" >&2; exit 1; }`)
	line(`  sleep 0.1`)
	line(`done`)
	line(`echo 1 > "/proc/sys/net/ipv6/conf/$dev/disable_ipv6" 2>/dev/null || true`)
	line(`ip link set dev "$dev" up`)
	line(`ip addr replace "$addr/32" dev "$dev"`)
	line(`ip route replace "$gw/32" dev "$dev"`)
	line(`ip neigh replace "$gw" lladdr "$gwmac" dev "$dev" nud permanent`)
	if n.Tier == run.NetworkOpen {
		dns := make([]string, len(n.DNS))
		for i, addr := range n.DNS {
			dns[i] = addr.String()
		}
		servers := strings.Join(dns, " ")
		line(`ip route replace default via "$gw" dev "$dev"`)
		// Through the guest's resolver service where it has one, so that
		// its /etc/resolv.conf stays what the image made it.
		line(`if command -v resolvectl >/dev/null 2>&1 && resolvectl dns "$dev" %s 2>/dev/null; then`, servers)
		line(`  resolvectl domain "$dev" '~.' || true`)
		line(`  resolvectl default-route "$dev" yes 2>/dev/null || true`)
		line(`else`)
		line(`  rm -f /etc/resolv.conf`)
		line(`  printf 'nameserver %%s\n' %s > /etc/resolv.conf`, servers)
		line(`fi`)
	}
	return b.String()
}

// proxyEnv is the environment that points a run's tools at its proxy: the
// same variables, with the same values, as the Docker driver injects.
func proxyEnv(proxyURL string) map[string]string {
	env := map[string]string{"NO_PROXY": "localhost,127.0.0.1", "no_proxy": "localhost,127.0.0.1"}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		env[key] = proxyURL
	}
	return env
}
