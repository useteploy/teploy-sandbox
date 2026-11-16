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
//   - One tap per VM, in the host's network namespace, never on a bridge.
//     There is no layer-2 path between two guests at all: a frame a guest
//     sends reaches the host's own stack and nothing else.
//   - The daemon creates the tap and hands the hypervisor the open file.
//     The hypervisor stays unprivileged and in its empty network
//     namespace; it never sees an interface, only a file descriptor. The
//     tap is not persistent: it exists exactly as long as the hypervisor
//     holds that descriptor.
//   - At the tap's ingress hook (nftables, netdev family), before the
//     host's ARP or IP code sees a frame: only the VM's MAC, only IPv4
//     from the VM's address, and only ARP that asks for the gateway. IPv6
//     and every other ethertype are dropped there.
//   - Each VM has one address (a /32) routed to its tap, and a gateway
//     address that is the same for all and lives on a dummy interface.
//   - What a guest sends to the host itself is dropped, except TCP to its
//     own run's proxy port on the gateway (the allowlist tier). What it
//     sends through the host is dropped, unless the run's tier is "open":
//     then it is masqueraded to the internet, without the address ranges
//     that are not the public internet and without port 25. Nothing is
//     forwarded to a guest that is not an answer.
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
	// tapPrefix starts every tap's name; gatewayDev holds the gateway
	// address; table is the name of both nftables tables.
	tapPrefix, gatewayDev, table string
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
		// An interface name has 15 characters: 2 + 6 + 1 leaves 6 for the
		// slot. "g" is not a hex digit, so the gateway device can never
		// be taken for a tap.
		tapPrefix:  "tv" + owner[:6] + "-",
		gatewayDev: "tvg" + owner[:6],
		table:      "teploy_sbx_vm_" + owner[:8],
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

func (p netPlan) tapName(slot int) string { return fmt.Sprintf("%s%x", p.tapPrefix, slot) }

func (p netPlan) address(slot int) netip.Addr {
	raw := p.first.As4()
	value := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
	value += uint32(slot)
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

// macFor is a VM's MAC: locally administered, and a function of its
// address, so the two are checked as a pair.
func macFor(addr netip.Addr) string {
	raw := addr.As4()
	return fmt.Sprintf("02:54:%02x:%02x:%02x:%02x", raw[0], raw[1], raw[2], raw[3])
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
	// Gateway is the address every guest reaches the host's proxies at.
	Gateway() netip.Addr
	// Attach makes the device for a VM on a tier: run.NetworkAllowlist
	// with the port of the run's proxy, or run.NetworkOpen.
	Attach(ctx context.Context, name, tier string, proxyPort int) (*GuestNetwork, error)
	// Detach removes a VM's device and everything that admitted it.
	// Detaching what is not attached succeeds.
	Detach(ctx context.Context, name string) error
	// Sweep removes what a previous daemon life left; it returns the
	// number of devices removed.
	Sweep(ctx context.Context) (int, error)
	// Close stops the network's upkeep and, when no VM is attached,
	// removes its tables and gateway device.
	Close(ctx context.Context) error
}

// netSys is the host as the network uses it; tests replace it.
type netSys struct {
	// run runs ip, nft or conntrack and returns its stdout.
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// nft applies a script as one transaction.
	nft func(ctx context.Context, script string) error
	// openTap creates a tap device, down, and returns it open.
	openTap func(name string) (*os.File, error)
	// sysctl writes one value under /proc/sys.
	sysctl func(key, value string) error
	// links lists the host's interfaces, and linkMAC one's address.
	links   func() ([]string, error)
	linkMAC func(name string) (string, error)
}

func realNetSys() netSys {
	return netSys{
		run: execCommander{}.Run,
		nft: func(ctx context.Context, script string) error {
			var stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, "nft", "-f", "-")
			cmd.Stdin, cmd.Stderr = strings.NewReader(script), &stderr
			if err := cmd.Run(); err != nil {
				return &CommandError{Command: "nft -f", Stderr: strings.TrimSpace(stderr.String()), Err: err}
			}
			return nil
		},
		openTap: openTap,
		sysctl: func(key, value string) error {
			return os.WriteFile("/proc/sys/"+key, []byte(value), 0)
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
		linkMAC: func(name string) (string, error) {
			raw, err := os.ReadFile("/sys/class/net/" + name + "/address")
			return strings.TrimSpace(string(raw)), err
		},
	}
}

// attachment is one VM's place in the network.
type attachment struct {
	name, tap, mac, tier string
	slot                 int
	addr                 netip.Addr
	proxyPort            int
	// closing: no longer admitted, not yet cleaned up.
	closing bool
}

// errSuperseded is what a network answers once another instance of this
// daemon identity has taken the tables over.
var errSuperseded = errors.New("another daemon instance has taken over the vm network")

const watchInterval = 2 * time.Second

type hostNetwork struct {
	plan netPlan
	sys  netSys
	log  *slog.Logger
	// instance marks the tables as written by this hostNetwork: a chain
	// of that name exists in them.
	instance string

	mu         sync.Mutex
	attached   map[string]*attachment
	slots      map[int]bool
	next       int
	superseded bool
	stop       chan struct{}
	stopped    sync.WaitGroup
}

func newHostNetwork(plan netPlan, sys netSys, log *slog.Logger) *hostNetwork {
	mark := make([]byte, 6)
	_, _ = rand.Read(mark)
	return &hostNetwork{
		plan: plan, sys: sys, log: log,
		instance: "instance_" + hex.EncodeToString(mark),
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

// start makes the gateway device and the tables, and begins watching
// them. From here on a tap of this daemon identity that nothing admits is
// dropped at every hook.
func (n *hostNetwork) start(ctx context.Context) error {
	gateway := n.plan.gateway.String() + "/32"
	if _, err := n.sys.run(ctx, "ip", "link", "add", n.plan.gatewayDev, "type", "dummy"); err != nil && !strings.Contains(err.Error(), "File exists") {
		return fmt.Errorf("create the gateway device %s (is the dummy module available? `modprobe dummy`): %w", n.plan.gatewayDev, err)
	}
	if _, err := n.sys.run(ctx, "ip", "addr", "replace", gateway, "dev", n.plan.gatewayDev); err != nil {
		return fmt.Errorf("give %s the gateway address: %w", n.plan.gatewayDev, err)
	}
	if _, err := n.sys.run(ctx, "ip", "link", "set", "dev", n.plan.gatewayDev, "up"); err != nil {
		return err
	}
	n.claim()
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.sys.nft(ctx, n.rulesLocked()); err != nil {
		return fmt.Errorf("install the firewall (nftables with the inet and netdev families is needed): %w", err)
	}
	if err := n.sys.nft(ctx, "add table netdev "+n.plan.table+"\n"); err != nil {
		return fmt.Errorf("install the firewall (nftables with the netdev family is needed): %w", err)
	}
	// An accept in this daemon's table does not overrule a drop in
	// another's: every table on a hook has to let a packet pass.
	if listing, err := n.sys.run(ctx, "nft", "list", "chains"); err == nil {
		for _, chain := range foreignDropChains(string(listing), n.plan.table) {
			n.log.Warn("another firewall table drops by default on a hook guests' traffic passes; unless it allows that traffic, runs with a network will not reach their proxy (input) or the internet (forward)",
				"chain", chain, "taps", n.plan.tapPrefix+"*", "subnet", n.plan.subnet.String())
		}
	}
	n.stop = make(chan struct{})
	n.stopped.Add(1)
	go n.watch(n.stop)
	return nil
}

// foreignDropChains finds, in the output of `nft list chains`, the input
// and forward base chains of other tables whose policy is drop.
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
			if (hook == "input" || hook == "forward") && !strings.HasSuffix(table, " "+ownTable) {
				found = append(found, "table "+table+" chain "+chain+" (hook "+hook+")")
			}
		}
	}
	return found
}

// rulesLocked is the whole inet table as one transaction that replaces
// whatever is there. It is a function of the attached VMs alone, so it
// can be applied again at any time, and a table that something else
// removed is put back exactly.
func (n *hostNetwork) rulesLocked() string {
	p := n.plan
	var open, proxies []string
	for _, each := range n.attached {
		if each.closing {
			continue
		}
		switch each.tier {
		case run.NetworkOpen:
			open = append(open, fmt.Sprintf("%q . %s", each.tap, each.addr))
		case run.NetworkAllowlist:
			proxies = append(proxies, fmt.Sprintf("%q . %s . %d", each.tap, each.addr, each.proxyPort))
		}
	}
	slices.Sort(open)
	slices.Sort(proxies)
	elements := func(list []string) string {
		if len(list) == 0 {
			return ""
		}
		return " elements = { " + strings.Join(list, ", ") + " }"
	}
	blocked := notPublic
	if p.openPrivate {
		blocked = neverReachable
	}
	taps := fmt.Sprintf("%q", p.tapPrefix+"*")
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	// "add" first so that "delete" cannot fail on a table that is not
	// there; the three statements are one transaction, so there is no
	// moment without the table.
	line("add table inet %s", p.table)
	line("delete table inet %s", p.table)
	line("table inet %s {", p.table)
	line("	set open { type ifname . ipv4_addr;%s }", elements(open))
	line("	set proxy { type ifname . ipv4_addr . inet_service;%s }", elements(proxies))
	line("	chain %s { }", n.instance)
	// What a guest sends to the host itself, on any of its addresses.
	line("	chain guest_input {")
	line("		meta nfproto ipv4 ip daddr %s meta l4proto tcp iifname . ip saddr . tcp dport @proxy accept", p.gateway)
	line("		counter drop")
	line("	}")
	// What a guest sends through the host.
	line("	chain guest_forward {")
	line("		meta nfproto != ipv4 counter drop")
	line("		oifname %s counter drop", taps)
	line("		ip daddr %s counter drop", p.subnet)
	line("		iifname . ip saddr != @open counter drop")
	if len(p.dns) > 0 {
		dns := make([]string, len(p.dns))
		for i, addr := range p.dns {
			dns[i] = addr.String()
		}
		line("		ip daddr { %s } meta l4proto { tcp, udp } th dport 53 accept", strings.Join(dns, ", "))
	}
	line("		ip daddr { %s } counter drop", strings.Join(blocked, ", "))
	line("		tcp dport 25 counter drop")
	line("		accept")
	line("	}")
	// What the host forwards to a guest: answers, nothing else.
	line("	chain to_guest {")
	line("		ct state established,related accept")
	line("		counter drop")
	line("	}")
	line("	chain input {")
	line("		type filter hook input priority filter - 5; policy accept;")
	line("		iifname %s jump guest_input", taps)
	line("		iifname != \"lo\" ip daddr %s counter drop", p.subnet)
	line("	}")
	line("	chain forward {")
	line("		type filter hook forward priority filter - 5; policy accept;")
	line("		iifname %s jump guest_forward", taps)
	line("		oifname %s jump to_guest", taps)
	line("	}")
	line("	chain postrouting {")
	line("		type nat hook postrouting priority srcnat; policy accept;")
	line("		iifname %s oifname != %s ip saddr %s masquerade", taps, taps, p.subnet)
	line("	}")
	line("}")
	return b.String()
}

func chainName(slot int) string { return fmt.Sprintf("tap%x", slot) }

// ingressRules is the filter at one tap's ingress hook, where a frame is
// judged before any of the host's protocol code runs on it.
func (n *hostNetwork) ingressRules(a *attachment) string {
	table, chain := n.plan.table, chainName(a.slot)
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	line("add table netdev %s", table)
	line("add chain netdev %s %s { type filter hook ingress device %q priority -300; policy drop; }", table, chain, a.tap)
	// ARP: only a question about the gateway, from the VM's own MAC and
	// address. The host never has to ask a guest anything (its neighbour
	// entry for the guest is permanent), so no answer is let in.
	line("add rule netdev %s %s ether saddr %s ether type arp arp htype 1 arp ptype ip arp hlen 6 arp plen 4 arp operation request arp saddr ether %s arp saddr ip %s arp daddr ip %s accept",
		table, chain, a.mac, a.mac, a.addr, n.plan.gateway)
	line("add rule netdev %s %s ether saddr %s ether type ip ip saddr %s ip daddr != { 224.0.0.0/4, 255.255.255.255 } accept",
		table, chain, a.mac, a.addr)
	// Everything else: another MAC or source address, IPv6, VLAN tags,
	// multicast, any other ethertype.
	line("add rule netdev %s %s counter drop", table, chain)
	return b.String()
}

// tableState asks who wrote the tables: this instance, another one, or
// nobody (they are gone).
type tableState int

const (
	tablesOurs tableState = iota
	tablesForeign
	tablesMissing
)

func (n *hostNetwork) tableStateLocked(ctx context.Context) tableState {
	if n.superseded {
		return tablesForeign
	}
	if _, err := n.sys.run(ctx, "nft", "list", "chain", "inet", n.plan.table, n.instance); err == nil {
		return tablesOurs
	}
	if _, err := n.sys.run(ctx, "nft", "list", "table", "inet", n.plan.table); err == nil {
		n.superseded = true
		return tablesForeign
	}
	return tablesMissing
}

// applyLocked brings the inet table in line with the attached VMs.
func (n *hostNetwork) applyLocked(ctx context.Context) error {
	if n.tableStateLocked(ctx) == tablesForeign {
		return errSuperseded
	}
	return n.sys.nft(ctx, n.rulesLocked())
}

// watch puts the tables back when something else removed them. A host's
// own firewall reload often starts with "flush ruleset", and without the
// tables a guest's packets would be forwarded like anyone's.
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

// check is one look at the tables; it reports whether to keep looking.
func (n *hostNetwork) check(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	n.mu.Lock()
	defer n.mu.Unlock()
	switch n.tableStateLocked(ctx) {
	case tablesForeign:
		return false
	case tablesMissing:
		n.log.Error("the vm firewall table was removed by something else; putting it back", "table", n.plan.table)
		if err := n.sys.nft(ctx, n.rulesLocked()); err != nil {
			n.log.Error("restore the vm firewall table", "error", err)
			return true
		}
	}
	chains, err := n.sys.run(ctx, "nft", "list", "table", "netdev", n.plan.table)
	links, linksErr := n.sys.links()
	for _, each := range n.attached {
		if each.closing || (err == nil && strings.Contains(string(chains), "chain "+chainName(each.slot)+" {")) {
			continue
		}
		if linksErr == nil && !slices.Contains(links, each.tap) {
			// The VM is gone (its guest powered off, or its hypervisor
			// died) and took the tap along, and the kernel removed the
			// filter with the device. There is nothing to filter and
			// nothing to restore until the run is removed; a guest must
			// not be able to make the daemon log an error every two
			// seconds by shutting down.
			continue
		}
		n.log.Error("a tap's ingress filter was removed by something else; putting it back", "tap", each.tap)
		if err := n.sys.nft(ctx, n.ingressRules(each)); err != nil {
			// The tap may be gone with its VM; the inet table still
			// drops what it does not know.
			n.log.Error("restore a tap's ingress filter", "tap", each.tap, "error", err)
		}
	}
	return true
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
	if _, exists := n.attached[name]; exists {
		return nil, fmt.Errorf("%s already has a network device", name)
	}
	if n.tableStateLocked(ctx) == tablesForeign {
		return nil, errSuperseded
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
	a := &attachment{name: name, slot: slot, tap: n.plan.tapName(slot), addr: n.plan.address(slot), tier: tier, proxyPort: proxyPort}
	a.mac = macFor(a.addr)
	n.next = (slot + 1) % n.plan.slots
	n.slots[slot] = true
	n.attached[name] = a

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

	// A device of this name can only be a leftover: the slot was free.
	_, _ = n.sys.run(ctx, "ip", "link", "del", a.tap)
	if tap, err = n.sys.openTap(a.tap); err != nil {
		return nil, fmt.Errorf("create tap %s: %w", a.tap, err)
	}
	// The device is down. Everything that decides what it may do is in
	// place before it is brought up.
	conf4, conf6 := "net/ipv4/conf/"+a.tap+"/", "net/ipv6/conf/"+a.tap+"/"
	// No IPv6 on the host's side of the tap: no link-local address, no
	// neighbour discovery, no router advertisements in either direction.
	if err = n.sys.sysctl(conf6+"disable_ipv6", "1"); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("turn IPv6 off on %s: %w", a.tap, err)
	}
	forwarding := "0"
	if tier == run.NetworkOpen {
		forwarding = "1"
	}
	// The kernel's own switch, beside the firewall's: nothing that
	// arrives on an allowlist run's tap is routed anywhere.
	for _, setting := range [][2]string{{"forwarding", forwarding}, {"proxy_arp", "0"}, {"send_redirects", "0"}, {"accept_redirects", "0"}} {
		if err = n.sys.sysctl(conf4+setting[0], setting[1]); err != nil {
			return nil, fmt.Errorf("set %s on %s: %w", setting[0], a.tap, err)
		}
	}
	// Whatever the connection tracker remembers about this address
	// belongs to a VM that is gone.
	if err = n.forgetConnections(ctx, a.addr); err != nil {
		return nil, err
	}
	_, _ = n.sys.run(ctx, "nft", "delete", "chain", "netdev", n.plan.table, chainName(slot))
	if err = n.sys.nft(ctx, n.ingressRules(a)); err != nil {
		return nil, fmt.Errorf("install the ingress filter of %s: %w", a.tap, err)
	}
	if err = n.sys.nft(ctx, n.rulesLocked()); err != nil {
		return nil, fmt.Errorf("admit %s: %w", a.tap, err)
	}
	for _, args := range [][]string{
		{"link", "set", "dev", a.tap, "up"},
		{"route", "replace", a.addr.String() + "/32", "dev", a.tap},
		// Permanent: the host never asks the guest who has its address,
		// and nothing the guest sends can change the answer.
		{"neigh", "replace", a.addr.String(), "lladdr", a.mac, "dev", a.tap, "nud", "permanent"},
	} {
		if _, err = n.sys.run(ctx, "ip", args...); err != nil {
			return nil, err
		}
	}
	hostMAC, err := n.sys.linkMAC(a.tap)
	if err != nil {
		return nil, fmt.Errorf("read the address of %s: %w", a.tap, err)
	}
	guest := &GuestNetwork{Tap: tap, MAC: a.mac, HostMAC: hostMAC, Address: a.addr, Gateway: n.plan.gateway, Tier: tier}
	if tier == run.NetworkOpen {
		guest.DNS = slices.Clone(n.plan.dns)
	}
	return guest, nil
}

// forgetConnections deletes the connection tracker's entries that began
// at addr. Without it, whoever a VM was talking to could keep sending to
// the next VM that gets the address, as "answers".
func (n *hostNetwork) forgetConnections(ctx context.Context, addr netip.Addr) error {
	_, err := n.sys.run(ctx, "conntrack", "-D", "-s", addr.String())
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

// detachLocked can be repeated: every step succeeds on what is already
// gone, and the VM's slot is only free once all of them have.
func (n *hostNetwork) detachLocked(ctx context.Context, name string) error {
	a, ok := n.attached[name]
	if !ok {
		return nil
	}
	// First the admission: from here the tap is one the tables do not
	// know, and they drop everything from it.
	a.closing = true
	if err := n.applyLocked(ctx); err != nil && !errors.Is(err, errSuperseded) {
		return fmt.Errorf("revoke %s: %w", a.tap, err)
	}
	if !n.superseded {
		if _, err := n.sys.run(ctx, "nft", "delete", "chain", "netdev", n.plan.table, chainName(a.slot)); err != nil && !isGone(err) {
			return fmt.Errorf("remove the ingress filter of %s: %w", a.tap, err)
		}
		// The tap goes with the hypervisor that held it; this is for one
		// that is somehow still there.
		if _, err := n.sys.run(ctx, "ip", "link", "del", a.tap); err != nil && !isGone(err) {
			return fmt.Errorf("remove tap %s: %w", a.tap, err)
		}
		if err := n.forgetConnections(ctx, a.addr); err != nil {
			return err
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
	if n.tableStateLocked(ctx) == tablesForeign {
		return 0, errSuperseded
	}
	names, err := n.sys.links()
	if err != nil {
		return 0, fmt.Errorf("list interfaces: %w", err)
	}
	live := map[string]bool{}
	for _, each := range n.attached {
		live[each.tap] = true
	}
	removed := 0
	for _, name := range names {
		if !strings.HasPrefix(name, n.plan.tapPrefix) || live[name] {
			continue
		}
		if _, err := n.sys.run(ctx, "ip", "link", "del", name); err != nil && !isGone(err) {
			return removed, fmt.Errorf("remove leftover tap %s: %w", name, err)
		}
		removed++
	}
	if len(n.attached) == 0 {
		// Ingress filters of taps that are gone.
		if err := n.sys.nft(ctx, fmt.Sprintf("add table netdev %[1]s\ndelete table netdev %[1]s\nadd table netdev %[1]s\n", n.plan.table)); err != nil {
			return removed, err
		}
	}
	return removed, n.sys.nft(ctx, n.rulesLocked())
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
	if len(n.attached) > 0 || n.tableStateLocked(ctx) != tablesOurs {
		// A VM that could not be torn down keeps the tables that confine
		// it; tables another instance wrote are that instance's.
		return nil
	}
	n.superseded = true
	script := fmt.Sprintf("add table netdev %[1]s\ndelete table netdev %[1]s\nadd table inet %[1]s\ndelete table inet %[1]s\n", n.plan.table)
	if err := n.sys.nft(ctx, script); err != nil {
		return err
	}
	if _, err := n.sys.run(ctx, "ip", "link", "del", n.plan.gatewayDev); err != nil && !isGone(err) {
		return err
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
