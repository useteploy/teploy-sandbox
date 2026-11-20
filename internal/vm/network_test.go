package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

func testPlan(t *testing.T, change func(*Config)) netPlan {
	t.Helper()
	config := Config{Owner: testOwner, DNS: []string{"192.0.2.53"}}
	if change != nil {
		change(&config)
	}
	plan, err := planNetwork(config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// fakeSpace is one network namespace of a fakeNet.
type fakeSpace struct {
	links map[string]bool
	// rules is the ruleset as the script last applied left it.
	rules string
	// ip is every line of every batch applied, in order.
	ip      []string
	sysctls map[string]string
}

// fakeNet is a host's network as hostNetwork drives it: the host's
// interfaces and table, the named namespaces and what is in each, and a
// record of every step in order. A step in a namespace is recorded as
// "[name] step".
type fakeNet struct {
	t  *testing.T
	mu sync.Mutex
	// events is every step, in order.
	events []string
	links  map[string]bool
	spaces map[string]*fakeSpace
	// inet is the host's table as last applied ("" when there is none).
	inet string
	// addrs is the host's own addresses.
	addrs []netip.Addr
	// fail makes the first step that contains the key fail, once.
	fail      map[string]error
	files     []*os.File
	listeners []net.Listener
}

func newFakeNet(t *testing.T) *fakeNet {
	return &fakeNet{t: t, links: map[string]bool{"lo": true, "eth0": true}, spaces: map[string]*fakeSpace{}, fail: map[string]error{},
		addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("192.168.7.1")}}
}

func (f *fakeNet) failing(event string) error {
	for key, err := range f.fail {
		if strings.Contains(event, key) {
			delete(f.fail, key)
			return err
		}
	}
	return nil
}

func (f *fakeNet) sys() netSys {
	gone := func(what string) error {
		return &CommandError{Command: what, Stderr: "Error: No such file or directory", Err: errors.New("exit status 1")}
	}
	// note records a step and returns the namespace it is in.
	note := func(ns, event string, record bool) (*fakeSpace, error) {
		if ns != "" {
			event = "[" + ns + "] " + event
		}
		if record {
			f.events = append(f.events, event)
		}
		if err := f.failing(event); err != nil {
			return nil, err
		}
		if ns == "" {
			return nil, nil
		}
		space, ok := f.spaces[ns]
		if !ok {
			return nil, gone(event)
		}
		return space, nil
	}
	has := func(args []string, prefix ...string) bool {
		return len(args) >= len(prefix) && slices.Equal(args[:len(prefix)], prefix)
	}
	return netSys{
		run: func(_ context.Context, ns, name string, args ...string) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			query := name == "nft" && slices.Contains(args, "list")
			space, err := note(ns, name+" "+strings.Join(args, " "), !query)
			if err != nil {
				return nil, err
			}
			switch {
			case space != nil && name == "nft" && has(args, "-s", "list", "ruleset"):
				return []byte(space.rules), nil
			case space != nil && name == "ip" && has(args, "link", "show", "dev"):
				if !space.links[args[3]] {
					return nil, &CommandError{Command: "ip link", Stderr: `Device "` + args[3] + `" does not exist.`, Err: errors.New("exit status 1")}
				}
			case name == "nft" && has(args, "list", "chain", "inet"):
				if !strings.Contains(f.inet, "chain "+args[4]+" {") {
					return nil, gone("nft list")
				}
			case name == "nft" && (has(args, "list", "table", "inet") || has(args, "-s", "list", "table", "inet")):
				if f.inet == "" {
					return nil, gone("nft list")
				}
				return []byte(f.inet), nil
			case name == "ip" && has(args, "netns", "add"):
				f.spaces[args[2]] = &fakeSpace{links: map[string]bool{"lo": true}, sysctls: map[string]string{}}
			case name == "ip" && has(args, "netns", "del"):
				if _, ok := f.spaces[args[2]]; !ok {
					return nil, gone("ip netns del")
				}
				delete(f.spaces, args[2])
			case space != nil && name == "ip" && has(args, "link", "del"):
				if !space.links[args[2]] {
					return nil, &CommandError{Command: "ip link", Stderr: `Cannot find device "` + args[2] + `"`, Err: errors.New("exit status 1")}
				}
				delete(space.links, args[2])
			case name == "ip" && has(args, "link", "del"):
				if !f.links[args[2]] {
					return nil, &CommandError{Command: "ip link", Stderr: `Cannot find device "` + args[2] + `"`, Err: errors.New("exit status 1")}
				}
				delete(f.links, args[2])
			case name == "ip" && has(args, "link", "add"):
				f.links[args[2]] = true
				if peer, ok := f.spaces[args[len(args)-1]]; ok {
					peer.links[uplinkDev] = true
				}
			case name == "conntrack":
				return nil, &CommandError{Command: "conntrack -D", Stderr: "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.", Err: errors.New("exit status 1")}
			}
			return nil, nil
		},
		nft: func(_ context.Context, ns, script string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			event := "nft -f: table"
			switch {
			case ns != "" && strings.Contains(script, "hook ingress"):
				event = "nft -f: ruleset"
			case ns != "":
				event = "nft -f: sealed"
			case !strings.Contains(script, "chain input"):
				first, _, _ := strings.Cut(script, "\n")
				event = "nft -f: " + first
			}
			space, err := note(ns, event, true)
			switch {
			case err != nil:
				return err
			case space != nil:
				space.rules = script
			case event == "nft -f: table":
				f.inet = script
			case strings.Contains(script, "delete table inet"):
				f.inet = ""
			}
			return nil
		},
		ip: func(_ context.Context, ns, batch string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, line := range strings.Split(strings.TrimSpace(batch), "\n") {
				space, err := note(ns, "ip: "+line, true)
				if err != nil {
					return err
				}
				if space != nil {
					space.ip = append(space.ip, line)
				}
			}
			return nil
		},
		openTap: func(ns, name string) (*os.File, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			space, err := note(ns, "tap "+name, true)
			if err != nil {
				return nil, err
			}
			file, err := os.CreateTemp(f.t.TempDir(), "tap")
			if err != nil {
				return nil, err
			}
			space.links[name] = true
			f.files = append(f.files, file)
			return file, nil
		},
		listen: func(ns, addr string) (net.Listener, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if _, err := note(ns, "listen "+addr, true); err != nil {
				return nil, err
			}
			// A real socket, somewhere this machine can bind.
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			f.listeners = append(f.listeners, listener)
			f.t.Cleanup(func() { listener.Close() })
			return listener, nil
		},
		sysctl: func(ns, key, value string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			space, err := note(ns, "sysctl "+key+"="+value, true)
			if space != nil {
				space.sysctls[key] = value
			}
			return err
		},
		links: func() ([]string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			var names []string
			for name := range f.links {
				names = append(names, name)
			}
			slices.Sort(names)
			return names, nil
		},
		namespaces: func() ([]string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			var names []string
			for name := range f.spaces {
				names = append(names, name)
			}
			slices.Sort(names)
			return names, nil
		},
		addresses: func() ([]netip.Addr, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return slices.Clone(f.addrs), nil
		},
	}
}

func (f *fakeNet) index(t *testing.T, fragment string) int {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, event := range f.events {
		if strings.Contains(event, fragment) {
			return i
		}
	}
	t.Fatalf("no step containing %q in:\n%s", fragment, strings.Join(f.events, "\n"))
	return -1
}

// space is a copy of what is in a namespace, or nil when it is gone.
func (f *fakeNet) space(name string) *fakeSpace {
	f.mu.Lock()
	defer f.mu.Unlock()
	space, ok := f.spaces[name]
	if !ok {
		return nil
	}
	return &fakeSpace{links: space.links, rules: space.rules, ip: slices.Clone(space.ip), sysctls: space.sysctls}
}

func (f *fakeNet) table() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inet
}

func startedNetwork(t *testing.T, change func(*Config)) (*hostNetwork, *fakeNet) {
	t.Helper()
	fake := newFakeNet(t)
	network := newHostNetwork(testPlan(t, change), fake.sys(), quietLog())
	must(t, network.start(bg))
	t.Cleanup(func() { _ = network.Close(bg) })
	return network, fake
}

// attachAllowlist makes an allowlist run's place the way the daemon does:
// the proxy's listener first, then the VM's device on the listener's port.
func attachAllowlist(t *testing.T, network *hostNetwork, name string) (*GuestNetwork, net.Listener, int) {
	t.Helper()
	listener, err := network.Listen(bg, name)
	must(t, err)
	port := network.attached[name].proxyPort
	guest, err := network.Attach(bg, name, run.NetworkAllowlist, port)
	must(t, err)
	return guest, listener, port
}

func TestPlanNetworkAddressesGuestsFromTheSubnet(t *testing.T) {
	plan := testPlan(t, nil)
	if plan.gateway.String() != "10.209.0.1" || plan.address(0).String() != "10.209.0.2" || plan.address(254).String() != "10.209.1.0" {
		t.Fatalf("gateway %s, slot 0 %s, slot 254 %s", plan.gateway, plan.address(0), plan.address(254))
	}
	if plan.slots != UIDCount {
		t.Fatalf("slots: %d", plan.slots)
	}
	if got := macFor(plan.address(0)); got != "02:54:0a:d1:00:02" {
		t.Fatalf("mac: %s", got)
	}
	// Names carry the daemon identity, and one kind of name can never be
	// taken for another: the sweep removes by prefix.
	names := []string{plan.nsName(4095), plan.tapName(4095), plan.linkName(4095), plan.legacyGateway}
	if !slices.Equal(names, []string{"tvn012345-fff", "tv012345-fff", "tvh012345-fff", "tvg012345"}) || plan.table != "teploy_sbx_vm_01234567" {
		t.Fatalf("names: %v %s", names, plan.table)
	}
	for i, name := range names {
		if len(name) > 15 {
			t.Errorf("%s does not fit an interface name", name)
		}
		for j, prefix := range []string{plan.nsPrefix, plan.tapPrefix, plan.linkPrefix} {
			if i != j && strings.HasPrefix(name, prefix) {
				t.Errorf("%s would be taken for a name that starts with %s", name, prefix)
			}
		}
	}
	// The hardware addresses the daemon sets are distinct per address and
	// per role.
	addr := plan.address(0)
	if macs := []string{macFor(addr), gatewayMACFor(addr), linkMACFor(addr), uplinkMACFor(addr)}; len(slices.Compact(slices.Sorted(slices.Values(macs)))) != 4 {
		t.Fatalf("hardware addresses collide: %v", macs)
	}
	small := testPlan(t, func(c *Config) { c.Subnet = "198.18.4.0/28" })
	if small.slots != 13 || small.address(12).String() != "198.18.4.14" {
		t.Fatalf("a /28 has 13 guest addresses up to .14, got %d up to %s", small.slots, small.address(small.slots-1))
	}
}

func TestPlanNetworkOnlyNamesResolversAGuestCanReach(t *testing.T) {
	local := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	discovered := []netip.Addr{
		netip.MustParseAddr("127.0.0.53"), // the host's own stub
		netip.MustParseAddr("192.0.2.10"), // the host itself
		netip.MustParseAddr("10.209.0.9"), // inside the guest subnet
		netip.MustParseAddr("192.0.2.53"),
		netip.MustParseAddr("192.0.2.53"), // twice
		netip.MustParseAddr("192.0.2.54"),
		netip.MustParseAddr("192.0.2.55"),
		netip.MustParseAddr("192.0.2.56"), // a fourth
	}
	plan, err := planNetwork(Config{Owner: testOwner}, discovered, local)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(plan.dns); got != "[192.0.2.53 192.0.2.54 192.0.2.55]" {
		t.Fatalf("resolvers: %s", got)
	}
	// What the operator names replaces what the host uses.
	plan, err = planNetwork(Config{Owner: testOwner, DNS: []string{" 198.51.100.1 "}}, discovered, local)
	if err != nil || fmt.Sprint(plan.dns) != "[198.51.100.1]" {
		t.Fatalf("named resolvers: %v %v", plan.dns, err)
	}
}

func TestHostResolversPreferTheRealOnesOverTheLocalStub(t *testing.T) {
	files := map[string]string{
		"/etc/resolv.conf":                 "nameserver 127.0.0.53\noptions edns0\n",
		"/run/systemd/resolve/resolv.conf": "# comment\nnameserver 192.0.2.53\nnameserver 2001:db8::53\nsearch example.com\n",
	}
	read := func(path string) ([]byte, error) {
		if content, ok := files[path]; ok {
			return []byte(content), nil
		}
		return nil, os.ErrNotExist
	}
	if got := fmt.Sprint(hostResolvers(read)); got != "[192.0.2.53]" {
		t.Fatalf("resolvers: %s", got)
	}
	delete(files, "/run/systemd/resolve/resolv.conf")
	if got := hostResolvers(read); len(got) != 0 {
		t.Fatalf("a loopback stub is not a resolver for guests: %v", got)
	}
}

// What exists is the first layer: an allowlist run's namespace has a tap
// and the gateway address and no way out; only an open run has a link,
// and only an open run is known to the host at all.
func TestARunsNamespaceHoldsOnlyWhatItsTierNeeds(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	allow, listener, port := attachAllowlist(t, network, "run-a")
	open, err := network.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	if allow.Address.String() != "10.209.0.2" || open.Address.String() != "10.209.0.3" || allow.MAC == open.MAC {
		t.Fatalf("addresses: %s %s, macs %s %s", allow.Address, open.Address, allow.MAC, open.MAC)
	}
	if len(allow.DNS) != 0 || fmt.Sprint(open.DNS) != "[192.0.2.53]" {
		t.Fatalf("resolvers are for the open tier only: %v %v", allow.DNS, open.DNS)
	}
	if allow.HostMAC != "02:55:0a:d1:00:01" || open.HostMAC != allow.HostMAC {
		t.Fatalf("the gateway's hardware address: %s %s", allow.HostMAC, open.HostMAC)
	}
	if port != proxyPortBase || listener == nil {
		t.Fatalf("slot 0's proxy port: %d", port)
	}
	a, b := fake.space("tvn012345-0"), fake.space("tvn012345-1")
	if a == nil || b == nil {
		t.Fatalf("namespaces: %v", fake.spaces)
	}
	// The allowlist run: a tap, the loopback that holds the gateway
	// address, and nothing else. No link, no forwarding, and no route
	// but the guest's own.
	if !a.links["tv012345-0"] || len(a.links) != 2 || a.sysctls["net/ipv4/ip_forward"] != "0" {
		t.Fatalf("an allowlist run's namespace: links %v, forwarding %q", a.links, a.sysctls["net/ipv4/ip_forward"])
	}
	wantA := []string{
		"link set dev lo up", "addr replace 10.209.0.1/32 dev lo",
		"link set dev tv012345-0 address 02:55:0a:d1:00:01",
		"link set dev tv012345-0 up", "route replace 10.209.0.2/32 dev tv012345-0",
		"neigh replace 10.209.0.2 lladdr 02:54:0a:d1:00:02 dev tv012345-0 nud permanent",
	}
	if !slices.Equal(a.ip, wantA) {
		t.Fatalf("an allowlist run's namespace was given:\n%s\nwant:\n%s", strings.Join(a.ip, "\n"), strings.Join(wantA, "\n"))
	}
	if fake.links["tvh012345-0"] {
		t.Fatal("an allowlist run was given a link to the host")
	}
	// The open run: a tap and one link.
	if !b.links["tv012345-1"] || !b.links[uplinkDev] || len(b.links) != 3 || b.sysctls["net/ipv4/ip_forward"] != "1" || !fake.links["tvh012345-1"] {
		t.Fatalf("an open run's namespace: links %v, forwarding %q; host links %v", b.links, b.sysctls["net/ipv4/ip_forward"], fake.links)
	}
	// Both: no IPv6, no answer to a ping, strict source validation.
	for name, space := range map[string]*fakeSpace{"allowlist": a, "open": b} {
		for key, want := range map[string]string{"net/ipv6/conf/all/disable_ipv6": "1", "net/ipv6/conf/default/disable_ipv6": "1",
			"net/ipv4/conf/all/rp_filter": "1", "net/ipv4/conf/default/rp_filter": "1", "net/ipv4/icmp_echo_ignore_all": "1"} {
			if space.sysctls[key] != want {
				t.Errorf("%s namespace: %s = %q, want %s", name, key, space.sysctls[key], want)
			}
		}
	}
	// The host knows the open run's link and address and nothing of the
	// allowlist run.
	table := fake.table()
	if !strings.Contains(table, `set open { type ifname . ipv4_addr; elements = { "tvh012345-1" . 10.209.0.3 } }`) || strings.Contains(table, "10.209.0.2") || strings.Contains(table, fmt.Sprint(port)) {
		t.Fatalf("the host's table:\n%s", table)
	}

	must(t, network.Detach(bg, "run-a"))
	must(t, network.Detach(bg, "run-b"))
	if strings.Contains(fake.table(), "elements") || len(fake.spaces) != 0 || fake.links["tvh012345-1"] {
		t.Fatalf("detached runs left something: namespaces=%v links=%v\n%s", fake.spaces, fake.links, fake.table())
	}
	must(t, network.Detach(bg, "run-a")) // again: nothing to do
}

// The rules say again what the namespaces already are: in each run's own
// namespace, and on the host for the open runs' links.
func TestRulesAdmitExactlyWhatATierAllows(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	table := fake.table()
	for _, want := range []string{
		"set open { type ifname . ipv4_addr; }",
		// to the host itself: nothing
		"type filter hook input priority filter - 5; policy accept;\n\t\tiifname \"tvh012345-*\" counter drop",
		// through the host: never to another guest, only a known open
		// run, never to what is not the public internet, never port 25
		"meta nfproto != ipv4 counter drop\n\t\toifname \"tvh012345-*\" counter drop\n\t\tip daddr 10.209.0.0/16 counter drop\n\t\tiifname . ip saddr != @open counter drop",
		"ip daddr { 192.0.2.53 } meta l4proto { tcp, udp } th dport 53 accept",
		"10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12",
		"192.168.0.0/16",
		"tcp dport 25 counter drop\n\t\taccept",
		// to a guest: answers only
		"oifname \"tvh012345-*\" jump to_guest",
		"ct state established,related accept\n\t\tcounter drop",
		`iifname "tvh012345-*" oifname != "tvh012345-*" ip saddr 10.209.0.0/16 masquerade`,
	} {
		if !strings.Contains(table, want) {
			t.Errorf("the host's table lacks %q:\n%s", want, table)
		}
	}
	// One transaction that replaces the table: no moment without it.
	if !strings.HasPrefix(table, "add table inet teploy_sbx_vm_01234567\ndelete table inet teploy_sbx_vm_01234567\ntable inet teploy_sbx_vm_01234567 {") {
		t.Fatalf("not an atomic replace:\n%s", table[:120])
	}

	_, _, port := attachAllowlist(t, network, "run-a")
	_, err := network.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	allow, open := fake.space("tvn012345-0").rules, fake.space("tvn012345-1").rules
	for name, rules := range map[string]string{"allowlist": allow, "open": open} {
		if !strings.HasPrefix(rules, "add table inet guest\ndelete table inet guest\nadd table netdev guest\ndelete table netdev guest\n") {
			t.Errorf("the %s run's ruleset is not an atomic replace:\n%s", name, rules)
		}
		// Both base chains drop by default, and all that is not IPv4.
		for _, want := range []string{
			"type filter hook input priority filter; policy drop;\n\t\tmeta nfproto != ipv4 counter drop",
			"type filter hook forward priority filter; policy drop;\n\t\tmeta nfproto != ipv4 counter drop",
		} {
			if !strings.Contains(rules, want) {
				t.Errorf("the %s run's ruleset lacks %q:\n%s", name, want, rules)
			}
		}
	}
	// At the tap: this MAC, this address, IPv4 and a question to the
	// gateway. The policy drops the rest, IPv6 included.
	for _, want := range []string{
		`type filter hook ingress device "tv012345-0" priority -300; policy drop;`,
		"ether saddr 02:54:0a:d1:00:02 ether type arp arp htype 1 arp ptype ip arp hlen 6 arp plen 4 arp operation request arp saddr ether 02:54:0a:d1:00:02 arp saddr ip 10.209.0.2 arp daddr ip 10.209.0.1 accept",
		"ether saddr 02:54:0a:d1:00:02 ether type ip ip saddr 10.209.0.2 ip daddr != { 224.0.0.0/4, 255.255.255.255 } accept",
		// to the namespace itself: its own proxy's port, from its own
		// address, and that is the only accept
		fmt.Sprintf(`iifname "tv012345-0" ip saddr 10.209.0.2 ip daddr 10.209.0.1 tcp dport %d accept`, port),
	} {
		if !strings.Contains(allow, want) {
			t.Errorf("the allowlist run's ruleset lacks %q:\n%s", want, allow)
		}
	}
	if strings.Contains(allow, "ip6") || strings.Count(allow, " accept") != 3 || strings.Contains(allow, "chain out") || strings.Contains(allow, uplinkDev) {
		t.Fatalf("the allowlist run's ruleset accepts more than ARP, IPv4 at the tap and its proxy port:\n%s", allow)
	}
	for _, want := range []string{
		`iifname "uplink" oifname "tv012345-1" ct state established,related accept`,
		`iifname "tv012345-1" oifname "uplink" ip saddr 10.209.0.3 jump out`,
		// never another guest, never the host itself, on any address it has
		"chain out {\n\t\tip daddr 10.209.0.0/16 counter drop\n\t\tip daddr { 192.168.7.1, 198.51.100.10 } counter drop",
		"ip daddr { 192.0.2.53 } meta l4proto { tcp, udp } th dport 53 accept",
		"169.254.0.0/16",
		"tcp dport 25 counter drop\n\t\taccept",
	} {
		if !strings.Contains(open, want) {
			t.Errorf("the open run's ruleset lacks %q:\n%s", want, open)
		}
	}
	// Nothing reaches the open run's namespace itself, and neither
	// ruleset knows the other run.
	if strings.Contains(open, "tcp dport "+fmt.Sprint(port)) || strings.Contains(open, "10.209.0.2") || strings.Contains(allow, "10.209.0.3") {
		t.Fatalf("a run's ruleset knows another run:\n%s\n%s", allow, open)
	}
}

// With no firewall at all an open run's packets go where its namespace
// has a route, so the routes are the tier: nothing that is not the public
// internet, no other guest, none of the host's own addresses, no port 25,
// and the resolver for DNS only.
func TestAnOpenRunsRoutesAreItsTier(t *testing.T) {
	network, fake := startedNetwork(t, func(c *Config) { c.DNS = []string{"192.168.7.53"} })
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	routes := fake.space("tvn012345-0").ip
	for _, want := range append([]string{
		"neigh replace 169.254.0.1 lladdr 02:56:0a:d1:00:02 dev uplink nud permanent",
		"rule add pref 100 ipproto tcp dport 25 unreachable",
		"rule add pref 200 to 192.168.7.53/32 ipproto udp dport 53 lookup 100",
		"rule add pref 201 to 192.168.7.53/32 ipproto tcp dport 53 lookup 100",
		"route replace default via 169.254.0.1 dev uplink onlink table 100",
		"route replace unreachable 10.209.0.0/16",
		"route replace unreachable 198.51.100.10/32",
		"route replace unreachable 192.168.7.1/32",
		"route replace default via 169.254.0.1 dev uplink onlink",
	}, func() (blocked []string) {
		for _, each := range notPublic {
			blocked = append(blocked, "route replace unreachable "+each)
		}
		return blocked
	}()...) {
		if !slices.Contains(routes, want) {
			t.Errorf("an open run's namespace lacks %q:\n%s", want, strings.Join(routes, "\n"))
		}
	}
	// The loopback address of the host is nothing a guest has a route to
	// in the first place, and is not listed.
	if slices.Contains(routes, "route replace unreachable 127.0.0.1/32") {
		t.Error("the host's loopback address was given a route of its own")
	}
	// The only route out is the last thing added, after everything that
	// takes away from it.
	if routes[len(routes)-1] != "route replace default via 169.254.0.1 dev uplink onlink" {
		t.Fatalf("the default route is not last:\n%s", strings.Join(routes, "\n"))
	}
}

func TestOpenPrivateStillBlocksLinkLocalAndLoopback(t *testing.T) {
	network, fake := startedNetwork(t, func(c *Config) { c.OpenPrivate = true })
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	space := fake.space("tvn012345-0")
	for name, rules := range map[string]string{"host": fake.table(), "run": space.rules} {
		if !strings.Contains(rules, "ip daddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } counter drop") {
			t.Errorf("%s: the ranges that are never reachable:\n%s", name, rules)
		}
		if strings.Contains(rules, "192.168.0.0/16") || strings.Contains(rules, "10.0.0.0/8") {
			t.Errorf("%s: private ranges are still blocked with --vm-open-private:\n%s", name, rules)
		}
		// Other guests and port 25 stay closed whatever is opened.
		if !strings.Contains(rules, "ip daddr 10.209.0.0/16 counter drop") || !strings.Contains(rules, "tcp dport 25 counter drop") {
			t.Errorf("%s: guests or port 25 were opened:\n%s", name, rules)
		}
	}
	// And the host's own addresses, private ones included: opening the
	// private ranges does not open the host.
	if !strings.Contains(space.rules, "ip daddr { 192.168.7.1, 198.51.100.10 } counter drop") {
		t.Errorf("the host's addresses in the run's ruleset:\n%s", space.rules)
	}
	for _, want := range []string{"route replace unreachable 169.254.0.0/16", "route replace unreachable 10.209.0.0/16", "route replace unreachable 192.168.7.1/32", "rule add pref 100 ipproto tcp dport 25 unreachable"} {
		if !slices.Contains(space.ip, want) {
			t.Errorf("the namespace lacks %q", want)
		}
	}
	if slices.Contains(space.ip, "route replace unreachable 192.168.0.0/16") {
		t.Error("private ranges have no route with --vm-open-private")
	}
}

// Everything that decides what a device may do is in place before the
// device is up.
func TestAttachInstallsTheRulesBeforeAnythingComesUp(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	order := []string{
		"ip netns add tvn012345-0",
		"[tvn012345-0] sysctl net/ipv6/conf/all/disable_ipv6=1",
		"[tvn012345-0] nft -f: sealed",
		"[tvn012345-0] ip: addr replace 10.209.0.1/32 dev lo",
		"conntrack -D -s 10.209.0.2",
		"ip link add tvh012345-0 address 02:56:0a:d1:00:02 type veth peer name uplink address 02:57:0a:d1:00:02 netns tvn012345-0",
		"sysctl net/ipv6/conf/tvh012345-0/disable_ipv6=1",
		"[tvn012345-0] tap tv012345-0",
		"[tvn012345-0] nft -f: ruleset",
		"[tvn012345-0] ip: link set dev tv012345-0 up",
		"[tvn012345-0] ip: link set dev uplink up",
		"[tvn012345-0] ip: route replace default via 169.254.0.1 dev uplink onlink",
		"[tvn012345-0] sysctl net/ipv4/ip_forward=1",
		"ip: link set dev tvh012345-0 up",
		"ip: route replace 10.209.0.2/32 dev tvh012345-0",
		"ip: neigh replace 10.209.0.2 lladdr 02:57:0a:d1:00:02 dev tvh012345-0 nud permanent",
	}
	last := -1
	for _, step := range order {
		at := fake.index(t, step)
		if at <= last {
			t.Fatalf("%q happened before the step it must follow:\n%s", step, strings.Join(fake.events, "\n"))
		}
		last = at
	}
	// The host's table knows the link before the link is up.
	fake.mu.Lock()
	admitted := -1
	for i, event := range fake.events {
		if event == "nft -f: table" {
			admitted = i
		}
	}
	fake.mu.Unlock()
	if up := fake.index(t, "ip: link set dev tvh012345-0 up"); admitted < 0 || admitted > up || admitted < fake.index(t, "ip link add tvh012345-0") {
		t.Fatalf("the host's table was written at step %d, the link came up at %d", admitted, up)
	}
	for _, setting := range []string{"forwarding=1", "rp_filter=1", "proxy_arp=0", "send_redirects=0", "accept_redirects=0"} {
		fake.index(t, "sysctl net/ipv4/conf/tvh012345-0/"+setting)
	}
}

func TestAttachRefusesWhatItCannotHonour(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	for name, try := range map[string]func() error{
		"allowlist without a port": func() error { _, err := network.Attach(bg, "x", run.NetworkAllowlist, 0); return err },
		// The proxy is the tier: a port nothing listens on in the run's
		// own namespace is not one.
		"allowlist without a listener": func() error { _, err := network.Attach(bg, "x", run.NetworkAllowlist, 40001); return err },
		"none":                         func() error { _, err := network.Attach(bg, "x", run.NetworkNone, 0); return err },
		"unknown":                      func() error { _, err := network.Attach(bg, "x", "bridge", 0); return err },
	} {
		if try() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// The listener's own port and no other.
	_, err := network.Listen(bg, "run-l")
	must(t, err)
	if _, err := network.Attach(bg, "run-l", run.NetworkAllowlist, proxyPortBase+7); err == nil {
		t.Fatal("an allowlist run was attached on a port its proxy does not listen on")
	}
	if _, err := network.Attach(bg, "run-l", run.NetworkOpen, 0); err == nil {
		t.Fatal("a place made for a proxy was given to an open run")
	}
	if _, err := network.Listen(bg, "run-l"); err == nil {
		t.Fatal("a second listener was made for the same run")
	}
	must(t, network.Detach(bg, "run-l"))
	if len(network.attached) != 0 || len(fake.spaces) != 0 {
		t.Fatalf("a refused attach left something: %v %v", network.attached, fake.spaces)
	}
	_, err = network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	if _, err := network.Attach(bg, "run-a", run.NetworkOpen, 0); err == nil {
		t.Fatal("a second device for the same VM")
	}
	// Without a resolver an open run would have a network it cannot use.
	bare := newHostNetwork(testPlan(t, func(c *Config) { c.DNS = nil }), newFakeNet(t).sys(), quietLog())
	if _, err := bare.Attach(bg, "run-a", run.NetworkOpen, 0); err == nil || !strings.Contains(err.Error(), "DNS") {
		t.Fatalf("open without a resolver: %v", err)
	}
}

func TestAFailedAttachLeavesNothingBehind(t *testing.T) {
	for _, step := range []string{"ip netns add", "sysctl net/ipv4/conf/all/rp_filter", "nft -f: sealed", "ip: addr replace", "ip link add tvh", "sysctl net/ipv4/conf/tvh012345-0/forwarding",
		"tap tv", "nft -f: ruleset", "nft -f: table", "ip: route replace 10.209.0.2/32 dev tv012345-0", "ip: rule add pref 100", "sysctl net/ipv4/ip_forward=1", "ip: route replace 10.209.0.2/32 dev tvh"} {
		network, fake := startedNetwork(t, nil)
		fake.mu.Lock()
		fake.fail[step] = errors.New("refused by the kernel")
		fake.mu.Unlock()
		if _, err := network.Attach(bg, "run-a", run.NetworkOpen, 0); err == nil {
			t.Fatalf("%s: attach succeeded", step)
		}
		if len(network.attached) != 0 || len(network.slots) != 0 || len(fake.spaces) != 0 || fake.links["tvh012345-0"] || strings.Contains(fake.table(), "elements") {
			t.Errorf("after a failure at %q: attached=%v namespaces=%v links=%v\n%s", step, network.attached, fake.spaces, fake.links, fake.table())
		}
		for _, file := range fake.files {
			if _, err := file.Stat(); err == nil {
				t.Errorf("after a failure at %q the tap is still open", step)
			}
		}
	}
	// An allowlist run whose listener cannot be made holds no place.
	network, fake := startedNetwork(t, nil)
	fake.fail["listen"] = errors.New("address in use")
	if _, err := network.Listen(bg, "run-a"); err == nil || len(network.attached) != 0 || len(fake.spaces) != 0 {
		t.Fatalf("a failed listen: %v, attached=%v namespaces=%v", err, network.attached, fake.spaces)
	}
}

// A run's proxy listens before its VM exists. The place it listens in is
// the VM's once there is one, and is given back with the listener if
// there never is.
func TestAProxyListenerHoldsItsPlaceUntilAVMHasIt(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	listener, err := network.Listen(bg, "run-a")
	must(t, err)
	fake.index(t, "[tvn012345-0] listen 10.209.0.1:20000")
	// Until a VM is attached nothing passes: the namespace is sealed, has
	// no tap, and is not known to the host.
	space := fake.space("tvn012345-0")
	if strings.Contains(space.rules, " accept") || len(space.links) != 1 || strings.Contains(fake.table(), "elements") {
		t.Fatalf("a place without a VM:\n%s\nlinks %v", space.rules, space.links)
	}
	// The run never started: closing the listener gives the place back.
	must(t, listener.Close())
	if len(network.attached) != 0 || len(network.slots) != 0 || fake.space("tvn012345-0") != nil {
		t.Fatalf("a closed listener left its place: %v %v", network.attached, fake.spaces)
	}
	must(t, listener.Close()) // again: nothing to do

	// With a VM, closing the listener closes the door and nothing else:
	// the namespace stays the VM's until the VM is detached.
	_, second, port := attachAllowlist(t, network, "run-b")
	if port != proxyPortBase+1 {
		t.Fatalf("port %d", port)
	}
	must(t, second.Close())
	if network.attached["run-b"] == nil || fake.space("tvn012345-1") == nil {
		t.Fatal("closing a running VM's proxy took its namespace away")
	}
	// The port is the slot's: it cannot be given to another run while
	// this one's namespace exists, and another run's proxy is in another
	// namespace anyway.
	_, _, other := attachAllowlist(t, network, "run-c")
	if other == port || network.attached["run-c"].ns == network.attached["run-b"].ns {
		t.Fatalf("two runs share a proxy port or a namespace: %d %d", port, other)
	}
	fake.mu.Lock()
	fake.fail["ip netns del tvn012345-1"] = errors.New("busy")
	fake.mu.Unlock()
	if err := network.Detach(bg, "run-b"); err == nil {
		t.Fatal("a failed removal was reported as success")
	}
	_, _, third := attachAllowlist(t, network, "run-d")
	if third == port {
		t.Fatal("a port was given out again while the namespace that had it is still there")
	}
	must(t, network.Detach(bg, "run-b"))
	// A listener closed after its VM was detached touches nobody else's
	// place.
	must(t, network.Detach(bg, "run-c"))
	if network.attached["run-d"] == nil {
		t.Fatal("detaching one run took another's place")
	}
}

func TestDetachRevokesFirstAndCanBeRepeated(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	fake.mu.Lock()
	before := len(fake.events)
	fake.fail["ip netns del"] = errors.New("namespace busy")
	fake.mu.Unlock()
	if err := network.Detach(bg, "run-a"); err == nil {
		t.Fatal("a failed detach was reported as success")
	}
	// The admission is gone although the namespace is not: the host
	// drops everything from the link.
	if strings.Contains(fake.table(), "elements") {
		t.Fatalf("still admitted after a failed detach:\n%s", fake.table())
	}
	fake.mu.Lock()
	events := slices.Clone(fake.events[before:])
	fake.mu.Unlock()
	if len(events) < 2 || events[0] != "nft -f: table" {
		t.Fatalf("a detach must revoke before it removes: %v", events)
	}
	// The slot stays taken until the removal succeeds.
	if len(network.attached) != 1 || len(network.slots) != 1 {
		t.Fatalf("a failed detach gave the slot up: %v", network.slots)
	}
	must(t, network.Detach(bg, "run-a"))
	if len(network.attached) != 0 || len(network.slots) != 0 || len(fake.spaces) != 0 || fake.links["tvh012345-0"] {
		t.Fatalf("after the retry: %v %v", network.attached, fake.spaces)
	}
	// The host's connection tracker is told to forget the address.
	fake.index(t, "conntrack -D -s 10.209.0.2")
}

// A VM that died under its claim is replaced under the same name: its
// device goes, and an allowlist run's place stays, sealed, with its
// proxy's listener in it, for the replacement's device on the same port.
// An open run's place goes entirely, as with Detach.
func TestUnplugKeepsAnAllowlistRunsPlaceForTheNextVM(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, listener, port := attachAllowlist(t, network, "run-a")
	ns, tap := network.attached["run-a"].ns, network.attached["run-a"].tap
	// The hypervisor is gone, and its tap with it.
	fake.mu.Lock()
	delete(fake.spaces[ns].links, tap)
	fake.mu.Unlock()
	must(t, network.Unplug(bg, "run-a"))
	space := fake.space(ns)
	if space == nil {
		t.Fatal("unplug removed the run's namespace, and its proxy's listener with it")
	}
	if strings.Contains(space.rules, " accept") || strings.Contains(space.rules, "hook ingress") {
		t.Fatalf("an unplugged place is not sealed:\n%s", space.rules)
	}
	if a := network.attached["run-a"]; a == nil || a.attached || a.listener == nil {
		t.Fatalf("the place after unplug: %+v", a)
	}
	// The replacement's device, on the same proxy.
	_, err := network.Attach(bg, "run-a", run.NetworkAllowlist, port)
	must(t, err)
	// A tap still there is removed; a second unplug has nothing to do.
	must(t, network.Unplug(bg, "run-a"))
	if fake.space(ns).links[tap] {
		t.Fatal("unplug left the tap")
	}
	must(t, network.Unplug(bg, "run-a"))
	// The run never got its replacement: closing the proxy gives the
	// place back, as for a run that never started.
	must(t, listener.Close())
	if network.attached["run-a"] != nil || fake.space(ns) != nil {
		t.Fatal("the place outlived its proxy")
	}

	_, err = network.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	nsB := network.attached["run-b"].ns
	must(t, network.Unplug(bg, "run-b"))
	if network.attached["run-b"] != nil || fake.space(nsB) != nil {
		t.Fatal("an open run's place survived unplug")
	}
	_, err = network.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	must(t, network.Unplug(bg, "nobody"))
}

func TestAnAddressIsNotReusedAtOnce(t *testing.T) {
	network, _ := startedNetwork(t, func(c *Config) { c.Subnet = "198.18.4.0/28" }) // thirteen addresses
	first, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	must(t, network.Detach(bg, "run-a"))
	second, err := network.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	if second.Address == first.Address {
		t.Fatalf("%s was handed to the next VM at once", first.Address)
	}
	for i := 0; i < 12; i++ {
		_, err := network.Attach(bg, fmt.Sprintf("run-%d", i), run.NetworkOpen, 0)
		must(t, err)
	}
	if _, err := network.Attach(bg, "run-x", run.NetworkOpen, 0); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("a fourteenth VM in a /28: %v", err)
	}
}

func TestSweepRemovesThisDaemonsNamespacesAndNoOthers(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	fake.mu.Lock()
	for _, name := range []string{"tvn012345-7", "tvn012345-fe", "tvnabcdef-0", "cni-1234"} {
		fake.spaces[name] = &fakeSpace{links: map[string]bool{}}
	}
	for _, name := range []string{"tvh012345-7", "tvhabcdef-0", "tap0", "docker0",
		// What a version of the driver that kept taps on the host left.
		"tv012345-3", "tvg012345", "tvabcdef-0", "tvgabcdef"} {
		fake.links[name] = true
	}
	fake.mu.Unlock()
	removed, err := network.Sweep(bg)
	must(t, err)
	// Two namespaces and one tap of an earlier version.
	if removed != 3 {
		t.Fatalf("removed %d", removed)
	}
	for _, name := range []string{"tvn012345-0", "tvnabcdef-0", "cni-1234"} {
		if fake.space(name) == nil {
			t.Errorf("the sweep removed the namespace %s", name)
		}
	}
	for _, name := range []string{"tvh012345-0", "tvhabcdef-0", "tap0", "docker0", "eth0", "lo", "tvabcdef-0", "tvgabcdef"} {
		if !fake.links[name] {
			t.Errorf("the sweep removed %s", name)
		}
	}
	for _, name := range []string{"tvh012345-7", "tv012345-3", "tvg012345"} {
		if fake.links[name] {
			t.Errorf("the sweep left %s", name)
		}
	}
	for _, name := range []string{"tvn012345-7", "tvn012345-fe"} {
		if fake.space(name) != nil {
			t.Errorf("the sweep left the namespace %s", name)
		}
	}
	// The live VM is still admitted.
	if !strings.Contains(fake.table(), `"tvh012345-0" . 10.209.0.2`) {
		t.Fatalf("the sweep revoked a live VM:\n%s", fake.table())
	}
}

func TestCloseKeepsTheTableWhileAVMIsAttached(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	must(t, network.Close(bg))
	if fake.table() == "" || fake.space("tvn012345-0") == nil {
		t.Fatal("Close removed what a live VM is judged by")
	}
	must(t, network.Detach(bg, "run-a"))
	must(t, network.Close(bg))
	if fake.table() != "" {
		t.Fatalf("Close left the table:\n%s", fake.table())
	}
}

// A second instance of the same daemon identity (a restart inside one
// process, or a second daemon) takes the table over. The first stops
// writing: it would revoke runs it does not know.
func TestASupersededInstanceLeavesEverythingAlone(t *testing.T) {
	fake := newFakeNet(t)
	plan := testPlan(t, nil)
	first := newHostNetwork(plan, fake.sys(), quietLog())
	must(t, first.start(bg))
	_, err := first.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	second := newHostNetwork(plan, fake.sys(), quietLog())
	must(t, second.start(bg))
	t.Cleanup(func() { _ = second.Close(bg) })
	// The new instance's table knows no run: the old one's is cut off.
	if strings.Contains(fake.table(), "elements") {
		t.Fatalf("a new instance admitted a run it does not know:\n%s", fake.table())
	}
	_, err = second.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	want := fake.table()
	if _, err := first.Attach(bg, "run-c", run.NetworkOpen, 0); !errors.Is(err, errSuperseded) {
		t.Fatalf("attach on a superseded instance: %v", err)
	}
	if _, err := first.Listen(bg, "run-d"); !errors.Is(err, errSuperseded) {
		t.Fatalf("listen on a superseded instance: %v", err)
	}
	if first.check(bg) {
		t.Fatal("a superseded instance keeps watching")
	}
	// Its teardown, arriving late, removes nothing: slot 0 is the new
	// instance's now, name and all.
	must(t, first.Detach(bg, "run-a"))
	must(t, first.Close(bg))
	if fake.table() != want || fake.space("tvn012345-0") == nil || !fake.links["tvh012345-0"] {
		t.Fatalf("a superseded instance changed what the new one owns:\n%s", fake.table())
	}
}

func TestATableWithAnotherInstancesMarkIsLeftAlone(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	foreign := strings.Replace(fake.table(), network.instance, "instance_ffffffffffff", 1)
	fake.mu.Lock()
	fake.inet = foreign
	fake.mu.Unlock()
	if _, err := network.Attach(bg, "run-a", run.NetworkOpen, 0); !errors.Is(err, errSuperseded) {
		t.Fatalf("attach: %v", err)
	}
	if network.check(bg) {
		t.Fatal("the watch must stop")
	}
	must(t, network.Close(bg))
	if fake.table() != foreign {
		t.Fatal("another instance's table was rewritten")
	}
}

// The watch stood down for good when it could not list its own mark
// beside a table that was there: one failed command was read as another
// instance having taken over. Only another instance's mark is that.
func TestTheWatchOnlyStandsDownForAnotherInstancesMark(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	said := logOf(network)
	table := fake.table()
	busy := errors.New("fork/exec /usr/sbin/nft: resource temporarily unavailable")

	// The kernel cannot be asked at all: nothing is concluded.
	fake.mu.Lock()
	fake.fail["nft list chain"], fake.fail["nft list table"] = busy, busy
	fake.mu.Unlock()
	if !network.check(bg) {
		t.Fatal("the watch gave up after one failed look")
	}
	if network.superseded {
		t.Fatal("a failed command was taken for another instance")
	}
	if !strings.Contains(said.String(), "could not be checked") {
		t.Fatalf("a look that failed was not reported: %s", said)
	}
	// While it cannot be asked, nothing new is admitted, and the reason
	// is the failure, not a takeover.
	fake.mu.Lock()
	fake.fail["nft list chain"], fake.fail["nft list table"] = busy, busy
	fake.mu.Unlock()
	if _, err := network.Attach(bg, "run-b", run.NetworkOpen, 0); err == nil || errors.Is(err, errSuperseded) || !strings.Contains(err.Error(), "resource temporarily unavailable") {
		t.Fatalf("attach while the kernel cannot be asked: %v", err)
	}
	if _, err := network.Listen(bg, "run-b"); err != nil {
		t.Fatalf("listen once the kernel answers again: %v", err)
	}

	// Its own mark cannot be listed, and the table shows it: still its
	// own. (The old watch stopped here.)
	fake.mu.Lock()
	fake.fail["nft list chain"] = busy
	fake.mu.Unlock()
	if !network.check(bg) || network.superseded {
		t.Fatal("the watch gave up although the table carries its own mark")
	}
	// And the upkeep goes on: damage done afterwards is repaired.
	said.Reset()
	fake.mu.Lock()
	fake.inet = strings.Replace(fake.inet, "tcp dport 25 counter drop", "tcp dport 25 accept", 1)
	fake.fail["nft list chain"] = busy
	fake.mu.Unlock()
	if !network.check(bg) || fake.table() != table {
		t.Fatalf("a changed table was not restored after a failed look:\n%s", fake.table())
	}

	// The table is there without any mark (its marker chain was
	// deleted): nobody else owns it, so it is written again.
	fake.mu.Lock()
	fake.inet = "table inet teploy_sbx_vm_01234567 {\n\tchain forward {\n\t}\n}"
	fake.mu.Unlock()
	if !network.check(bg) || network.superseded || fake.table() != table {
		t.Fatalf("a table that lost its mark was not written again:\n%s", fake.table())
	}

	// Another instance's mark: positive evidence, and the only thing
	// that stops the watch.
	foreign := strings.Replace(table, network.instance, "instance_ffffffffffff", 1)
	fake.mu.Lock()
	fake.inet = foreign
	fake.mu.Unlock()
	said.Reset()
	if network.check(bg) || !network.superseded {
		t.Fatal("the watch went on under another instance's mark")
	}
	if !strings.Contains(said.String(), "instance_ffffffffffff") {
		t.Fatalf("standing down was not reported with the mark that caused it: %s", said)
	}
	if fake.table() != foreign {
		t.Fatal("another instance's table was rewritten")
	}
}

// The watch loop itself: a look that fails is followed by the next one.
func TestTheWatchKeepsLooking(t *testing.T) {
	fake := newFakeNet(t)
	network := newHostNetwork(testPlan(t, nil), fake.sys(), quietLog())
	must(t, network.writeHostLocked(bg))
	table := fake.table()
	busy := errors.New("cannot allocate memory")
	fake.mu.Lock()
	fake.fail["nft list chain"], fake.fail["nft list table"] = busy, busy
	fake.mu.Unlock()
	if !network.check(bg) {
		t.Fatal("the watch would have ended")
	}
	fake.mu.Lock()
	fake.inet = ""
	fake.mu.Unlock()
	if !network.check(bg) || fake.table() != table {
		t.Fatal("the look after a failed one did not restore the table")
	}
}

// A run's share of the host's network: a rate on what leaves its
// devices, and a count of the connections it may have tracked.
func TestARunsNetworkIsBounded(t *testing.T) {
	network, fake := startedNetwork(t, func(c *Config) { c.NetMbit, c.NetConnections = 100, 512 })
	attachAllowlist(t, network, "run-a")
	_, err := network.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	const tbf = "root tbf rate 100mbit burst 250000b latency 50ms"
	// The rate is on a device before the device is up.
	for _, each := range [][2]string{
		{"[tvn012345-0] tc qdisc replace dev tv012345-0 " + tbf, "[tvn012345-0] ip: link set dev tv012345-0 up"},
		{"[tvn012345-1] tc qdisc replace dev tv012345-1 " + tbf, "[tvn012345-1] ip: link set dev tv012345-1 up"},
		{"[tvn012345-1] tc qdisc replace dev uplink " + tbf, "[tvn012345-1] ip: link set dev uplink up"},
	} {
		if fake.index(t, each[0]) > fake.index(t, each[1]) {
			t.Errorf("%q came after %q", each[0], each[1])
		}
	}
	// An allowlist run has no link, so nothing to limit there.
	for _, event := range fake.events {
		if strings.Contains(event, "[tvn012345-0] tc") && strings.Contains(event, "uplink") {
			t.Errorf("an allowlist run was given a link to limit: %s", event)
		}
	}
	allow, open := fake.space("tvn012345-0").rules, fake.space("tvn012345-1").rules
	count := `iifname "tv012345-%d" ct state new ct count over 512 counter drop`
	for _, each := range []struct{ rules, limit, admits string }{
		{allow, fmt.Sprintf(count, 0), "tcp dport 20000 accept"},
		{open, fmt.Sprintf(count, 1), "jump out"},
	} {
		at, admitted := strings.Index(each.rules, each.limit), strings.Index(each.rules, each.admits)
		if at < 0 || admitted < at {
			t.Errorf("the connection limit %q is not ahead of %q in:\n%s", each.limit, each.admits, each.rules)
		}
	}

	// A small rate still passes the kernel's largest packets.
	if got := strings.Join(tbfArgs(1), " "); got != "tbf rate 1mbit burst 65536b latency 50ms" {
		t.Errorf("a 1 Mbit/s limit: %q", got)
	}

	// No limit: no queue and no count.
	network, fake = startedNetwork(t, func(c *Config) { c.NetMbit, c.NetConnections = -1, -1 })
	_, err = network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	for _, event := range fake.events {
		if strings.Contains(event, " tc ") {
			t.Errorf("a network without a rate was given one: %s", event)
		}
	}
	if strings.Contains(fake.space("tvn012345-0").rules, "ct count") {
		t.Error("a network without a connection limit was given one")
	}
	// The daemon's defaults.
	plan, err := planNetwork(Config{Owner: testOwner}.withDefaults(), nil, nil)
	must(t, err)
	if plan.rateMbit != DefaultNetMbit || plan.connections != DefaultNetConnections {
		t.Errorf("default network limits: %d Mbit/s, %d connections", plan.rateMbit, plan.connections)
	}
}

// A device that cannot be given its rate is not brought up.
func TestARunWithoutItsRateIsNotAttached(t *testing.T) {
	network, fake := startedNetwork(t, func(c *Config) { c.NetMbit = 50 })
	fake.fail["tc qdisc"] = errors.New("RTNETLINK answers: Operation not supported")
	if _, err := network.Attach(bg, "run-a", run.NetworkOpen, 0); err == nil || !strings.Contains(err.Error(), "50 Mbit/s") {
		t.Fatalf("attach without a rate: %v", err)
	}
	if fake.space("tvn012345-0") != nil || fake.links["tvh012345-0"] || len(network.attached) != 0 {
		t.Fatal("a run that could not be limited was left attached")
	}
}

// logOf is a network's log, to see what it said.
func logOf(network *hostNetwork) *strings.Builder {
	var log strings.Builder
	network.log = slog.New(slog.NewTextHandler(&log, nil))
	return &log
}

// Something else removed the rules, or changed them: every ruleset is
// compared with what was written and put back as it was. Rules that were
// only emptied are not "still there".
func TestCheckRestoresRulesSomethingElseRemovedOrChanged(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	attachAllowlist(t, network, "run-a")
	_, err := network.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	said := logOf(network)
	table, allow, open := fake.table(), fake.space("tvn012345-0").rules, fake.space("tvn012345-1").rules
	intact := func() bool {
		return fake.table() == table && fake.space("tvn012345-0").rules == allow && fake.space("tvn012345-1").rules == open
	}
	fake.mu.Lock()
	before := len(fake.events)
	fake.mu.Unlock()
	if !network.check(bg) || !intact() || said.Len() != 0 {
		t.Fatalf("a check of intact rules changed them or said something: %s", said)
	}
	fake.mu.Lock()
	if len(fake.events) != before {
		t.Fatalf("a check of intact rules wrote something: %v", fake.events[before:])
	}
	fake.mu.Unlock()

	for name, damage := range map[string]func(){
		"the host's table removed": func() { fake.inet = "" },
		// Flushed: the table and its chains are there, the rules are not.
		"the host's table emptied": func() {
			fake.inet = "table inet teploy_sbx_vm_01234567 {\n\tchain " + network.instance + " {\n\t}\n\tchain forward {\n\t}\n}"
		},
		"one rule of the host's table changed": func() {
			fake.inet = strings.Replace(fake.inet, "tcp dport 25 counter drop", "tcp dport 25 accept", 1)
		},
		"a run's ruleset removed": func() { fake.spaces["tvn012345-0"].rules = "" },
		"a run's ruleset emptied": func() {
			fake.spaces["tvn012345-1"].rules = "table inet guest {\n\tchain forward {\n\t}\n}"
		},
		"one rule of a run's ruleset changed": func() {
			fake.spaces["tvn012345-1"].rules = strings.Replace(fake.spaces["tvn012345-1"].rules, "ip daddr 10.209.0.0/16 counter drop", "ip daddr 10.209.0.0/16 accept", 1)
		},
	} {
		said.Reset()
		fake.mu.Lock()
		damage()
		fake.mu.Unlock()
		if intact() {
			t.Fatalf("%s: nothing was damaged", name)
		}
		if !network.check(bg) {
			t.Fatalf("%s: the watch gave up", name)
		}
		if !intact() {
			t.Errorf("%s: not restored:\n%s\n%s\n%s", name, fake.table(), fake.space("tvn012345-0").rules, fake.space("tvn012345-1").rules)
		}
		if !strings.Contains(said.String(), "something else") {
			t.Errorf("%s: restored without saying so: %s", name, said)
		}
	}
}

// A guest that powers off takes its tap with it, and the kernel removes
// the tap's ingress filter with the device. That is not a rule that
// something else removed. The namespace is sealed, once, and nothing is
// attempted or said every two seconds until the run is removed.
func TestCheckSealsTheNamespaceOfAVMThatIsGone(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	_, err = network.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	said := logOf(network)
	live := fake.space("tvn012345-1").rules
	fake.mu.Lock()
	delete(fake.spaces["tvn012345-0"].links, "tv012345-0")
	fake.spaces["tvn012345-0"].rules = "table inet guest {\n}"
	fake.mu.Unlock()
	if !network.check(bg) {
		t.Fatal("the watch gave up")
	}
	sealed := fake.space("tvn012345-0").rules
	if strings.Contains(sealed, " accept") || strings.Contains(sealed, "hook ingress") || !strings.Contains(sealed, "policy drop") {
		t.Fatalf("the namespace of a VM that is gone is not sealed:\n%s", sealed)
	}
	if said.Len() != 0 {
		t.Fatalf("a guest that shut down made the daemon log: %s", said)
	}
	fake.mu.Lock()
	before := len(fake.events)
	fake.mu.Unlock()
	if !network.check(bg) {
		t.Fatal("the watch gave up")
	}
	fake.mu.Lock()
	if len(fake.events) != before {
		t.Fatalf("the check keeps working on a VM that is gone: %v", fake.events[before:])
	}
	fake.mu.Unlock()
	if fake.space("tvn012345-1").rules != live {
		t.Fatal("the VM that is still there lost its ruleset")
	}
	must(t, network.Detach(bg, "run-a"))
}

// A datagram to the broadcast address of a subnet the host is on is the
// host's own, on whichever interface it arrives: an open run's namespace
// must have no route to those either. (Seen live before this was so: with
// no firewall rule left, an open guest's datagram to the broadcast
// address of the host's subnet was read by a socket on the host bound to
// every address.)
func TestTheHostsBroadcastAddressesAreItsOwn(t *testing.T) {
	text := func(prefix string) string {
		return joinAddrs(ownDestinations(netip.MustParsePrefix(prefix)))
	}
	for prefix, want := range map[string]string{
		"192.0.2.15/24":   "192.0.2.15, 192.0.2.255, 192.0.2.0",
		"172.30.77.1/30":  "172.30.77.1, 172.30.77.3, 172.30.77.0",
		"10.1.2.3/8":      "10.1.2.3, 10.255.255.255, 10.0.0.0",
		"198.51.100.4/31": "198.51.100.4",
		"198.51.100.7/32": "198.51.100.7",
		"2001:db8::1/64":  "",
	} {
		if got := text(prefix); got != want {
			t.Errorf("what the host takes for itself because of %s: %q, want %q", prefix, got, want)
		}
	}
	// And they end up where the addresses do: in an open run's routes and
	// in its ruleset.
	network, fake := startedNetwork(t, nil)
	fake.mu.Lock()
	fake.addrs = ownDestinations(netip.MustParsePrefix("198.51.100.10/24"))
	fake.mu.Unlock()
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	space := fake.space("tvn012345-0")
	for _, want := range []string{"route replace unreachable 198.51.100.10/32", "route replace unreachable 198.51.100.255/32", "route replace unreachable 198.51.100.0/32"} {
		if !slices.Contains(space.ip, want) {
			t.Errorf("the namespace was not told %q:\n%s", want, strings.Join(space.ip, "\n"))
		}
	}
	if !strings.Contains(space.rules, "ip daddr { 198.51.100.0, 198.51.100.10, 198.51.100.255 } counter drop") {
		t.Errorf("the ruleset does not name the host's broadcast addresses:\n%s", space.rules)
	}
}

// The host's addresses are not fixed for the life of a run. When they
// change, an open run's namespace is told: the new ones get no route, and
// the old ones get theirs back.
func TestCheckFollowsTheHostsAddresses(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	attachAllowlist(t, network, "run-b")
	fake.mu.Lock()
	fake.addrs = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("203.0.113.77")}
	before := len(fake.spaces["tvn012345-1"].ip)
	fake.mu.Unlock()
	if !network.check(bg) {
		t.Fatal("the watch gave up")
	}
	space := fake.space("tvn012345-0")
	for _, want := range []string{"route del unreachable 192.168.7.1/32", "route replace unreachable 203.0.113.77/32"} {
		if !slices.Contains(space.ip, want) {
			t.Errorf("the namespace was not told %q:\n%s", want, strings.Join(space.ip, "\n"))
		}
	}
	if !strings.Contains(space.rules, "ip daddr { 198.51.100.10, 203.0.113.77 } counter drop") {
		t.Errorf("the ruleset does not name the host's addresses as they are now:\n%s", space.rules)
	}
	// An allowlist run has no route to anything; there is nothing to tell it.
	if len(fake.space("tvn012345-1").ip) != before {
		t.Error("an allowlist run's namespace was given routes")
	}
}

func TestProbeNamespaceTriesEverythingARunNeedsAndRemovesIt(t *testing.T) {
	fake := newFakeNet(t)
	must(t, probeNamespace(bg, fake.sys(), "tvn012345-probe"))
	for _, step := range []string{"ip netns add tvn012345-probe", "ip link add tvp012345 type veth peer name uplink netns tvn012345-probe",
		"[tvn012345-probe] ip: rule add pref 100 ipproto tcp dport 25 unreachable", "[tvn012345-probe] tap probe", "[tvn012345-probe] nft -f:"} {
		fake.index(t, step)
	}
	if len(fake.spaces) != 0 || fake.links["tvp012345"] {
		t.Fatalf("the probe left something: %v %v", fake.spaces, fake.links)
	}
	for _, step := range []string{"[tvn012345-probe] nft -f: sealed", "[tvn012345-probe] tc qdisc replace dev probe root tbf rate 1mbit"} {
		fake.index(t, step)
	}
	for _, step := range []string{"ip netns add", "ip link add", "ip: rule add", "tap probe", "nft -f: ruleset", "nft -f: sealed", "tc qdisc"} {
		fake := newFakeNet(t)
		fake.fail[step] = errors.New("operation not supported")
		if err := probeNamespace(bg, fake.sys(), "tvn012345-probe"); err == nil {
			t.Errorf("a host that cannot do %q passed", step)
		}
		if len(fake.spaces) != 0 || fake.links["tvp012345"] {
			t.Errorf("a failed probe at %q left something: %v %v", step, fake.spaces, fake.links)
		}
	}
}

func TestGuestNetScriptConfiguresTheTier(t *testing.T) {
	allow := guestNetScript(&GuestNetwork{MAC: "02:54:0a:d1:00:02", HostMAC: "fe:54:00:00:00:01",
		Address: netip.MustParseAddr("10.209.0.2"), Gateway: netip.MustParseAddr("10.209.0.1"), Tier: run.NetworkAllowlist})
	for _, want := range []string{
		"mac=02:54:0a:d1:00:02 addr=10.209.0.2 gw=10.209.0.1 gwmac=fe:54:00:00:00:01",
		`ip addr replace "$addr/32" dev "$dev"`,
		`ip route replace "$gw/32" dev "$dev"`,
		`disable_ipv6`,
	} {
		if !strings.Contains(allow, want) {
			t.Errorf("script lacks %q:\n%s", want, allow)
		}
	}
	// An allowlist guest has a route to its proxy and nowhere else, and
	// no resolver: the proxy resolves.
	if strings.Contains(allow, "default") || strings.Contains(allow, "resolv") {
		t.Fatalf("an allowlist guest was given a default route or a resolver:\n%s", allow)
	}
	open := guestNetScript(&GuestNetwork{MAC: "02:54:0a:d1:00:03", HostMAC: "fe:54:00:00:00:01",
		Address: netip.MustParseAddr("10.209.0.3"), Gateway: netip.MustParseAddr("10.209.0.1"), Tier: run.NetworkOpen,
		DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("192.0.2.54")}})
	for _, want := range []string{`ip route replace default via "$gw" dev "$dev"`, `resolvectl dns "$dev" 192.0.2.53 192.0.2.54`, `printf 'nameserver %s\n' 192.0.2.53 192.0.2.54 > /etc/resolv.conf`} {
		if !strings.Contains(open, want) {
			t.Errorf("script lacks %q:\n%s", want, open)
		}
	}
}

// fakeNetwork is a Network that hands out devices and remembers them.
type fakeNetwork struct {
	mu        sync.Mutex
	attached  map[string]*GuestNetwork
	ports     map[string]int
	history   []string
	attaches  int
	attachErr error
	detachErr error
	swept     int
	dir       string
	// strict has the fake keep places as the real network does: an
	// allowlist device only where a proxy listens (places, made by the
	// fakeEgress that has this network), a place Detach removes is gone
	// with its listener, and a name has one device at a time.
	strict bool
	places map[string]bool
}

func newFakeNetwork(t *testing.T) *fakeNetwork {
	return &fakeNetwork{attached: map[string]*GuestNetwork{}, ports: map[string]int{}, dir: t.TempDir()}
}

func (n *fakeNetwork) Gateway() netip.Addr { return netip.MustParseAddr("10.209.0.1") }

func (n *fakeNetwork) Listen(_ context.Context, name string) (net.Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.history = append(n.history, "listen "+name)
	return net.Listen("tcp4", "127.0.0.1:0")
}

func (n *fakeNetwork) Attach(_ context.Context, name, tier string, proxyPort int) (*GuestNetwork, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.attachErr != nil {
		return nil, n.attachErr
	}
	if n.strict {
		if _, ok := n.attached[name]; ok {
			return nil, fmt.Errorf("%s already has a network device", name)
		}
		if tier == run.NetworkAllowlist && !n.places[name] {
			return nil, fmt.Errorf("the proxy of %s does not listen in the run's own network namespace", name)
		}
	}
	file, err := os.CreateTemp(n.dir, "tap")
	if err != nil {
		return nil, err
	}
	n.attaches++
	addr := netip.AddrFrom4([4]byte{10, 209, 0, byte(1 + n.attaches)})
	guest := &GuestNetwork{Tap: file, MAC: macFor(addr), HostMAC: "fe:54:00:00:00:01", Address: addr, Gateway: n.Gateway(), Tier: tier}
	n.attached[name], n.ports[name] = guest, proxyPort
	n.history = append(n.history, "attach "+name+" "+tier)
	return guest, nil
}

func (n *fakeNetwork) Detach(_ context.Context, name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.detachErr != nil {
		return n.detachErr
	}
	if _, ok := n.attached[name]; ok {
		delete(n.attached, name)
		n.history = append(n.history, "detach "+name)
	}
	delete(n.places, name)
	return nil
}

func (n *fakeNetwork) Unplug(ctx context.Context, name string) error {
	n.mu.Lock()
	guest, ok := n.attached[name]
	if ok && guest.Tier == run.NetworkAllowlist {
		delete(n.attached, name)
		n.history = append(n.history, "unplug "+name)
	}
	n.mu.Unlock()
	if ok && guest.Tier != run.NetworkAllowlist {
		return n.Detach(ctx, name)
	}
	return nil
}

// place is what the proxy's Listen does to the network: the run's place,
// with a listener in it.
func (n *fakeNetwork) place(name string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.places == nil {
		n.places = map[string]bool{}
	}
	n.places[name] = true
	n.history = append(n.history, "listen "+name)
}

func (n *fakeNetwork) Sweep(context.Context) (int, error) { n.swept++; return 0, nil }
func (n *fakeNetwork) Close(context.Context) error        { return nil }

// fakeEgress is the daemon's proxy pool as the manager sees it.
type fakeEgress struct {
	mu     sync.Mutex
	opened map[string][]string
	closed []string
	next   int
	// network, when set, is given the run's place as the real proxy's
	// listener makes it.
	network *fakeNetwork
}

func (e *fakeEgress) OpenFor(runID string, extra []string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.opened == nil {
		e.opened = map[string][]string{}
	}
	e.opened[runID] = extra
	e.next++
	if e.network != nil {
		e.network.place(run.ContainerName(runID))
	}
	return fmt.Sprintf("http://run:secret%d@10.209.0.1:%d", e.next, 40000+e.next), nil
}

func (e *fakeEgress) Close(runID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = append(e.closed, runID)
}

func newNetworkedRig(t *testing.T) (*testRig, *fakeNetwork, *fakeEgress) {
	t.Helper()
	rig := newRig(t, nil)
	network, egress := newFakeNetwork(t), &fakeEgress{}
	rig.driver.network = network
	rig.manager.Egress = egress
	return rig, network, egress
}

// The tiers through the manager, as the HTTP API reaches them: each run
// has a device of its own on its tier, an allowlist run has a proxy of its
// own whose address its commands are given, and stop, resume and fork keep
// the tier while never sharing a device or a proxy.
func TestNetworkTiersThroughTheManager(t *testing.T) {
	rig, network, egress := newNetworkedRig(t)
	must(t, func() error { _, err := rig.manager.LoadState(bg, t.TempDir()); return err }())

	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: "egress", Env: map[string]string{"NO_PROXY": "internal.example", "TOKEN": "t"}})
	must(t, err)
	if created.Network != run.NetworkAllowlist {
		t.Fatalf("network: %q", created.Network)
	}
	name := containerName(created.ID)
	guest := network.attached[name]
	machine := rig.hypervisor.machine(name)
	if machine.netMAC != guest.MAC || !machine.netTap || network.ports[name] != 40001 {
		t.Fatalf("the VM was not given its device: %q (open %t), port %d", machine.netMAC, machine.netTap, network.ports[name])
	}
	// Given to the running VM, before its guest was set up.
	if !slices.Equal(machine.events, []string{"add-net"}) || len(machine.setups) != 1 {
		t.Fatalf("events %v, setups %d", machine.events, len(machine.setups))
	}
	// The daemon does not keep the tap open: it must die with the VM.
	if _, err := guest.Tap.Stat(); err == nil {
		t.Fatal("the daemon still holds the tap after the hypervisor has it")
	}
	if extra, ok := egress.opened[created.ID]; !ok || len(extra) != 0 {
		t.Fatalf("an allowlist run without entries of its own still gets its own proxy: %v", egress.opened)
	}
	// The guest was told to bring its device up, once, and that is not
	// one of the run's own execs.
	if len(machine.setups) != 1 || !strings.Contains(machine.setups[0], "addr="+guest.Address.String()) || len(machine.execs) != 0 {
		t.Fatalf("guest setup: %q, execs %d", machine.setups, len(machine.execs))
	}
	must(t, func() error {
		_, _, err := rig.driver.Exec(bg, name, "true", "", nil, time.Second, io.Discard, io.Discard)
		return err
	}())
	env := machine.execs[0]
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if env[key] != "http://run:secret1@10.209.0.1:40001" {
			t.Errorf("%s = %q", key, env[key])
		}
	}
	if env["NO_PROXY"] != "internal.example" || env["no_proxy"] != "localhost,127.0.0.1" || env["TOKEN"] != "t" {
		t.Fatalf("the caller's env must override the proxy's defaults: %v", env)
	}

	// --- stop: device and proxy are given up; resume: new ones, same tier
	_, err = rig.manager.Stop(bg, created.ID)
	must(t, err)
	if len(network.attached) != 0 || !slices.Contains(egress.closed, created.ID) {
		t.Fatalf("a stopped run kept its device or proxy: %v %v", network.attached, egress.closed)
	}
	resumed, err := rig.manager.Resume(bg, created.ID, 0)
	must(t, err)
	if resumed.Network != run.NetworkAllowlist || network.ports[name] != 40002 || network.attached[name] == nil {
		t.Fatalf("resumed: %+v port %d", resumed, network.ports[name])
	}

	// --- fork: the tier and entries of the source, a device and a proxy
	// of its own
	forked, err := rig.manager.Fork(bg, created.ID, run.ForkRequest{})
	must(t, err)
	forkName := containerName(forked.ID)
	if forked.Network != run.NetworkAllowlist || network.attached[forkName] == nil || network.attached[forkName].Address == network.attached[name].Address {
		t.Fatalf("fork: %+v %v", forked, network.attached)
	}
	if network.ports[forkName] == network.ports[name] || network.ports[forkName] == 0 {
		t.Fatalf("the fork shares its source's proxy port: %v", network.ports)
	}

	// --- open: a device, no proxy, no proxy env
	open, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: "open"})
	must(t, err)
	openName := containerName(open.ID)
	if network.attached[openName].Tier != run.NetworkOpen || network.ports[openName] != 0 {
		t.Fatalf("open: %+v", network.attached[openName])
	}
	if _, ok := egress.opened[open.ID]; ok {
		t.Fatal("an open run was given a proxy")
	}
	must(t, func() error {
		_, _, err := rig.driver.Exec(bg, openName, "true", "", nil, time.Second, io.Discard, io.Discard)
		return err
	}())
	if openEnv := rig.hypervisor.machine(openName).execs[0]; len(openEnv) != 0 {
		t.Fatalf("an open run was given proxy env: %v", openEnv)
	}

	// --- none: no device at all
	none, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	must(t, err)
	if network.attached[containerName(none.ID)] != nil || rig.hypervisor.machine(containerName(none.ID)).netMAC != "" {
		t.Fatal("a run on \"none\" was given a network device")
	}
	// Its guest is still given the time, and nothing about a network.
	if setups := rig.hypervisor.machine(containerName(none.ID)).setups; len(setups) != 1 || !strings.Contains(setups[0], "date -u -s @") || strings.Contains(setups[0], "ip ") {
		t.Fatalf("guest setup of a run without a network: %q", setups)
	}

	for _, id := range []string{created.ID, forked.ID, open.ID, none.ID} {
		must(t, rig.manager.Destroy(bg, id))
	}
	if len(network.attached) != 0 {
		t.Fatalf("devices left after destroy: %v", network.attached)
	}
	for _, id := range []string{created.ID, forked.ID} {
		if !slices.Contains(egress.closed, id) {
			t.Errorf("the proxy of %s was not closed", id)
		}
	}
	assertPool(t, rig.zfs, pristine...)
}

func TestEgressAllowKeepsItsRules(t *testing.T) {
	rig, _, egress := newNetworkedRig(t)
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: "allowlist", EgressAllow: []string{"forge.example.com:49152"}})
	must(t, err)
	if got := egress.opened[created.ID]; !slices.Equal(got, []string{"forge.example.com:49152"}) {
		t.Fatalf("entries: %v", got)
	}
	for name, req := range map[string]run.CreateRequest{
		"on open":   {Image: GoldenImage, Network: "open", EgressAllow: []string{"example.com"}},
		"on none":   {Image: GoldenImage, EgressAllow: []string{"example.com"}},
		"malformed": {Image: GoldenImage, Network: "allowlist", EgressAllow: []string{"https://example.com/x"}},
	} {
		if _, err := rig.manager.Create(bg, req); !errors.Is(err, run.ErrBadRequest) {
			t.Errorf("egressAllow %s: %v", name, err)
		}
	}
}

func TestAnAllowlistRunNeedsAProxyAGuestCanReach(t *testing.T) {
	rig, network, _ := newNetworkedRig(t)
	base := run.CreateSpec{Name: runName(1), Image: GoldenImage, MemoryMB: 1024, CPUs: 1, Network: run.NetworkAllowlist}
	for name, proxy := range map[string]string{
		"no proxy":                "",
		"no port":                 "http://run:x@10.209.0.1",
		"a proxy on another host": "http://run:x@192.0.2.7:40001",
		"a proxy on loopback":     "http://run:x@127.0.0.1:40001",
	} {
		spec := base
		spec.ProxyURL = proxy
		if id, err := rig.driver.Create(bg, spec); err == nil || id != "" {
			t.Errorf("%s: id=%q err=%v", name, id, err)
		}
	}
	if len(network.history) != 0 || len(rig.hypervisor.started) != 0 {
		t.Fatalf("a refused run was given something: %v", network.history)
	}
	assertPool(t, rig.zfs, pristine...)
}

func TestNetworkFailuresRollBackCompletely(t *testing.T) {
	rig, network, egress := newNetworkedRig(t)

	// The device cannot be made: the VM (booted first, with none) is
	// killed, its volume goes, and the proxy is closed.
	network.attachErr = errors.New("no tap for you")
	if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: "allowlist"}); err == nil || !strings.Contains(err.Error(), "no tap for you") {
		t.Fatalf("create: %v", err)
	}
	if len(rig.hypervisor.running()) != 0 || len(egress.closed) != 1 {
		t.Fatalf("after a failed attach: running=%v closed=%v", rig.hypervisor.running(), egress.closed)
	}
	assertPool(t, rig.zfs, pristine...)
	network.attachErr = nil

	// The hypervisor refuses the device: the same, and the device is
	// given back.
	rig.hypervisor.onStart = func(machine *fakeMachine) { machine.addNetErr = errors.New("add-net: 500") }
	if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: "open"}); err == nil || !strings.Contains(err.Error(), "add-net: 500") {
		t.Fatalf("create with a hypervisor that refuses the device: %v", err)
	}
	rig.hypervisor.onStart = nil
	if len(network.attached) != 0 || len(rig.hypervisor.running()) != 0 {
		t.Fatalf("left behind: %v %v", network.attached, rig.hypervisor.running())
	}
	assertPool(t, rig.zfs, pristine...)

	// The guest cannot configure its device: the run is not handed over
	// with a network that does not work.
	rig.hypervisor.onStart = func(machine *fakeMachine) {
		machine.setupFunc = func(_ string, stderr io.Writer) (int, bool, error) {
			_, _ = io.WriteString(stderr, "sh: ip: not found")
			return 127, false, nil
		}
	}
	_, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: "open"})
	if err == nil || !strings.Contains(err.Error(), "ip: not found") || !strings.Contains(err.Error(), "iproute2") {
		t.Fatalf("create with a guest that cannot configure its device: %v", err)
	}
	rig.hypervisor.onStart = nil
	if len(network.attached) != 0 || len(rig.hypervisor.running()) != 0 {
		t.Fatalf("left behind: %v %v", network.attached, rig.hypervisor.running())
	}
	assertPool(t, rig.zfs, pristine...)

	// The hypervisor does not start: the device is given back.
	rig.hypervisor.startErr = errors.New("no kvm today")
	if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: "open"}); err == nil {
		t.Fatal("create succeeded")
	}
	rig.hypervisor.startErr = nil
	if len(network.attached) != 0 {
		t.Fatalf("device left after a failed start: %v", network.attached)
	}
	assertPool(t, rig.zfs, pristine...)
}

// A device that cannot be removed keeps the run: its volume is not
// destroyed and the removal is retried, as for a VM that cannot be killed.
func TestRemoveKeepsTheRunWhenItsDeviceCannotBeRemoved(t *testing.T) {
	rig, network, _ := newNetworkedRig(t)
	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: "open"})
	must(t, err)
	name := containerName(created.ID)
	network.detachErr = errors.New("device busy")
	if err := rig.driver.Remove(bg, name); err == nil || !strings.Contains(err.Error(), "device busy") {
		t.Fatalf("remove: %v", err)
	}
	if ok, _ := rig.zfs.Exists(bg, rig.volume(created.ID)); !ok {
		t.Fatal("the volume was destroyed while the run's device is still there")
	}
	network.detachErr = nil
	must(t, rig.driver.Remove(bg, name))
	if len(network.attached) != 0 {
		t.Fatal("device left")
	}
	assertPool(t, rig.zfs, pristine...)
}

func TestSweepRemovesDevicesAfterProcessesAndBeforeVolumes(t *testing.T) {
	rig, network, _ := newNetworkedRig(t)
	mustCreate(t, rig.driver.volumes, runName(1), "")
	if _, _, err := rig.driver.Sweep(bg); err != nil || network.swept != 1 || rig.hypervisor.swept != 1 {
		t.Fatalf("sweep: %v, network swept %d", err, network.swept)
	}
	// A process sweep that fails leaves the devices alone: a tap is only
	// removed once the VM behind it is dead.
	rig.hypervisor.sweepErr = errors.New("leftover hypervisor did not exit")
	if _, _, err := rig.driver.Sweep(bg); err == nil || network.swept != 1 {
		t.Fatalf("sweep: %v, network swept %d", err, network.swept)
	}
}

func TestForeignDropChainsAreNamed(t *testing.T) {
	listing := `table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
	}
	chain FORWARD {
		type filter hook forward priority filter; policy drop;
	}
	chain DOCKER-USER {
	}
}
table inet teploy_sbx_vm_01234567 {
	chain input {
		type filter hook input priority filter - 5; policy drop;
	}
}
table inet firewall {
	chain in {
		type filter hook input priority filter; policy drop;
	}
	chain out {
		type filter hook output priority filter; policy drop;
	}
}
`
	got := foreignDropChains(listing, "teploy_sbx_vm_01234567")
	// Only what is forwarded passes the host's firewall: an allowlist run
	// reaches its proxy inside its own namespace.
	want := []string{"table ip filter chain FORWARD (hook forward)"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The daemon's proxy pool listens through the driver: in the place of the
// VM the run will have, under the name the manager gives that VM.
func TestProxyListenerIsMadeInTheRunsOwnPlace(t *testing.T) {
	rig, network, _ := newNetworkedRig(t)
	listener, err := rig.driver.ProxyListener("01ABCDEFGHJKMNPQRSTVWXYZ00")
	must(t, err)
	defer listener.Close()
	if want := []string{"listen " + run.ContainerName("01ABCDEFGHJKMNPQRSTVWXYZ00")}; !slices.Equal(network.history, want) {
		t.Fatalf("history %v, want %v", network.history, want)
	}
	rig.driver.network = nil
	if _, err := rig.driver.ProxyListener("01ABCDEFGHJKMNPQRSTVWXYZ00"); !errors.Is(err, run.ErrBadRequest) {
		t.Fatalf("a driver without networking: %v", err)
	}
}
