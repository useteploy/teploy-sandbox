package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
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

// fakeNet is a host's network as hostNetwork drives it: interfaces, the
// two nftables tables as the scripts last applied left them, and a record
// of every step in order.
type fakeNet struct {
	t  *testing.T
	mu sync.Mutex
	// events is every step, in order.
	events []string
	links  map[string]bool
	// inet is the inet table as last applied ("" when there is none);
	// chains is the netdev table's chains, by name.
	inet   string
	chains map[string]string
	// fail makes the first step that contains the key fail, once.
	fail  map[string]error
	files []*os.File
}

func newFakeNet(t *testing.T) *fakeNet {
	return &fakeNet{t: t, links: map[string]bool{"lo": true, "eth0": true}, chains: map[string]string{}, fail: map[string]error{}}
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

var chainOf = regexp.MustCompile(`add chain netdev \S+ (\S+) `)

func (f *fakeNet) sys() netSys {
	gone := func(what string) error {
		return &CommandError{Command: what, Stderr: "Error: No such file or directory", Err: errors.New("exit status 1")}
	}
	return netSys{
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			event := name + " " + strings.Join(args, " ")
			query := name == "nft" && args[0] == "list"
			if !query {
				f.events = append(f.events, event)
			}
			if err := f.failing(event); err != nil {
				return nil, err
			}
			if len(args) < 3 {
				return nil, nil
			}
			switch {
			case name == "nft" && slices.Equal(args[:3], []string{"list", "chain", "inet"}):
				if !strings.Contains(f.inet, "chain "+args[4]+" {") {
					return nil, gone("nft list")
				}
			case name == "nft" && slices.Equal(args[:3], []string{"list", "table", "inet"}):
				if f.inet == "" {
					return nil, gone("nft list")
				}
			case name == "nft" && slices.Equal(args[:3], []string{"list", "table", "netdev"}):
				var out strings.Builder
				for chain := range f.chains {
					out.WriteString("chain " + chain + " {\n")
				}
				return []byte(out.String()), nil
			case name == "nft" && slices.Equal(args[:3], []string{"delete", "chain", "netdev"}):
				if _, ok := f.chains[args[4]]; !ok {
					return nil, gone("nft delete")
				}
				delete(f.chains, args[4])
			case name == "ip" && slices.Equal(args[:2], []string{"link", "del"}):
				if !f.links[args[2]] {
					return nil, &CommandError{Command: "ip link", Stderr: `Cannot find device "` + args[2] + `"`, Err: errors.New("exit status 1")}
				}
				delete(f.links, args[2])
			case name == "ip" && slices.Equal(args[:2], []string{"link", "add"}):
				f.links[args[2]] = true
			case name == "conntrack":
				return nil, &CommandError{Command: "conntrack -D", Stderr: "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.", Err: errors.New("exit status 1")}
			}
			return nil, nil
		},
		nft: func(_ context.Context, script string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			first, _, _ := strings.Cut(script, "\n")
			event := "nft -f: " + first
			if match := chainOf.FindStringSubmatch(script); match != nil {
				event = "nft -f: ingress " + match[1]
			} else if strings.Contains(script, "table inet") && strings.Contains(script, "chain input") {
				event = "nft -f: inet table"
			}
			f.events = append(f.events, event)
			if err := f.failing(event); err != nil {
				return err
			}
			switch {
			case strings.HasPrefix(event, "nft -f: ingress"):
				f.chains[chainOf.FindStringSubmatch(script)[1]] = script
			case event == "nft -f: inet table":
				f.inet = script
			default:
				if strings.Contains(script, "delete table netdev") {
					f.chains = map[string]string{}
				}
				if strings.Contains(script, "delete table inet") {
					f.inet = ""
				}
			}
			return nil
		},
		openTap: func(name string) (*os.File, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.events = append(f.events, "tap "+name)
			if err := f.failing("tap " + name); err != nil {
				return nil, err
			}
			file, err := os.CreateTemp(f.t.TempDir(), "tap")
			if err != nil {
				return nil, err
			}
			f.links[name] = true
			f.files = append(f.files, file)
			return file, nil
		},
		sysctl: func(key, value string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.events = append(f.events, "sysctl "+key+"="+value)
			return f.failing("sysctl " + key)
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
		linkMAC: func(string) (string, error) { return "fe:54:00:00:00:01", nil },
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

func startedNetwork(t *testing.T, change func(*Config)) (*hostNetwork, *fakeNet) {
	t.Helper()
	fake := newFakeNet(t)
	network := newHostNetwork(testPlan(t, change), fake.sys(), quietLog())
	must(t, network.start(bg))
	t.Cleanup(func() { _ = network.Close(bg) })
	return network, fake
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
	// Names carry the daemon identity, and a tap can never be taken for
	// the gateway device or the other way round.
	if plan.tapName(4095) != "tv012345-fff" || plan.gatewayDev != "tvg012345" || plan.table != "teploy_sbx_vm_01234567" {
		t.Fatalf("names: %s %s %s", plan.tapName(4095), plan.gatewayDev, plan.table)
	}
	if strings.HasPrefix(plan.gatewayDev, plan.tapPrefix) || len(plan.tapName(4095)) > 15 {
		t.Fatalf("interface names collide or do not fit: %s %s", plan.gatewayDev, plan.tapName(4095))
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

// The firewall is a function of the attached runs: each is admitted to
// exactly what its tier allows, and to nothing once it is detached.
func TestRulesAdmitExactlyTheAttachedRuns(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	rules := fake.inet
	for _, want := range []string{
		"set open { type ifname . ipv4_addr; }",
		"set proxy { type ifname . ipv4_addr . inet_service; }",
		// to the host: its own proxy port on the gateway, or dropped
		`iifname "tv012345-*" jump guest_input`,
		"meta nfproto ipv4 ip daddr 10.209.0.1 meta l4proto tcp iifname . ip saddr . tcp dport @proxy accept\n\t\tcounter drop",
		// through the host: never to another guest, only on the open
		// tier, never to what is not the public internet, never port 25
		"meta nfproto != ipv4 counter drop\n\t\toifname \"tv012345-*\" counter drop\n\t\tip daddr 10.209.0.0/16 counter drop\n\t\tiifname . ip saddr != @open counter drop",
		"ip daddr { 192.0.2.53 } meta l4proto { tcp, udp } th dport 53 accept",
		"10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12",
		"192.168.0.0/16",
		"tcp dport 25 counter drop\n\t\taccept",
		// to a guest: answers only
		"oifname \"tv012345-*\" jump to_guest",
		"ct state established,related accept\n\t\tcounter drop",
		// nothing outside reaches the gateway address or a guest's
		`iifname != "lo" ip daddr 10.209.0.0/16 counter drop`,
		`iifname "tv012345-*" oifname != "tv012345-*" ip saddr 10.209.0.0/16 masquerade`,
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("the base rules lack %q:\n%s", want, rules)
		}
	}
	// One transaction that replaces the table: no moment without it.
	if !strings.HasPrefix(rules, "add table inet teploy_sbx_vm_01234567\ndelete table inet teploy_sbx_vm_01234567\ntable inet teploy_sbx_vm_01234567 {") {
		t.Fatalf("not an atomic replace:\n%s", rules[:120])
	}

	allow, err := network.Attach(bg, "run-a", run.NetworkAllowlist, 40001)
	must(t, err)
	open, err := network.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	if allow.Address.String() != "10.209.0.2" || open.Address.String() != "10.209.0.3" || allow.MAC == open.MAC {
		t.Fatalf("addresses: %s %s, macs %s %s", allow.Address, open.Address, allow.MAC, open.MAC)
	}
	if len(allow.DNS) != 0 || fmt.Sprint(open.DNS) != "[192.0.2.53]" {
		t.Fatalf("resolvers are for the open tier only: %v %v", allow.DNS, open.DNS)
	}
	for _, want := range []string{
		`set open { type ifname . ipv4_addr; elements = { "tv012345-1" . 10.209.0.3 } }`,
		`set proxy { type ifname . ipv4_addr . inet_service; elements = { "tv012345-0" . 10.209.0.2 . 40001 } }`,
	} {
		if !strings.Contains(fake.inet, want) {
			t.Errorf("the rules lack %q:\n%s", want, fake.inet)
		}
	}
	// At the tap: this MAC, this address, IPv4 and a question to the
	// gateway. The policy drops the rest, IPv6 included.
	ingress := fake.chains["tap0"]
	for _, want := range []string{
		`add chain netdev teploy_sbx_vm_01234567 tap0 { type filter hook ingress device "tv012345-0" priority -300; policy drop; }`,
		"ether saddr 02:54:0a:d1:00:02 ether type arp arp htype 1 arp ptype ip arp hlen 6 arp plen 4 arp operation request arp saddr ether 02:54:0a:d1:00:02 arp saddr ip 10.209.0.2 arp daddr ip 10.209.0.1 accept",
		"ether saddr 02:54:0a:d1:00:02 ether type ip ip saddr 10.209.0.2 ip daddr != { 224.0.0.0/4, 255.255.255.255 } accept",
	} {
		if !strings.Contains(ingress, want) {
			t.Errorf("the ingress filter lacks %q:\n%s", want, ingress)
		}
	}
	if strings.Contains(ingress, "ip6") || strings.Count(ingress, " accept") != 2 {
		t.Fatalf("the ingress filter accepts more than ARP and IPv4:\n%s", ingress)
	}

	must(t, network.Detach(bg, "run-a"))
	must(t, network.Detach(bg, "run-b"))
	if strings.Contains(fake.inet, "elements") || len(fake.chains) != 0 || fake.links["tv012345-0"] || fake.links["tv012345-1"] {
		t.Fatalf("detached runs left something: chains=%v links=%v\n%s", fake.chains, fake.links, fake.inet)
	}
	must(t, network.Detach(bg, "run-a")) // again: nothing to do
}

func TestOpenPrivateStillBlocksLinkLocalAndLoopback(t *testing.T) {
	_, fake := startedNetwork(t, func(c *Config) { c.OpenPrivate = true })
	if !strings.Contains(fake.inet, "ip daddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } counter drop") {
		t.Fatalf("rules:\n%s", fake.inet)
	}
	for _, kept := range []string{"ip daddr 10.209.0.0/16 counter drop", "tcp dport 25 counter drop", "jump guest_input"} {
		if !strings.Contains(fake.inet, kept) {
			t.Errorf("opening the private ranges removed %q", kept)
		}
	}
}

// Everything that decides what a tap may do is in place before the tap is
// brought up: there is no instant in which a guest's frames are judged by
// less than its tier.
func TestAttachInstallsTheFirewallBeforeTheTapComesUp(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	guest, err := network.Attach(bg, "run-a", run.NetworkAllowlist, 40001)
	must(t, err)
	up := fake.index(t, "ip link set dev tv012345-0 up")
	for _, before := range []string{
		"tap tv012345-0",
		"sysctl net/ipv6/conf/tv012345-0/disable_ipv6=1",
		"sysctl net/ipv4/conf/tv012345-0/forwarding=0",
		"sysctl net/ipv4/conf/tv012345-0/proxy_arp=0",
		"conntrack -D -s 10.209.0.2",
		"nft -f: ingress tap0",
	} {
		if at := fake.index(t, before); at > up {
			t.Errorf("%q happened after the tap came up", before)
		}
	}
	// The admission that names this tap is the render after its ingress
	// filter, and it too precedes the link.
	fake.mu.Lock()
	events := slices.Clone(fake.events)
	fake.mu.Unlock()
	ingress := slices.Index(events, "nft -f: ingress tap0")
	if events[ingress+1] != "nft -f: inet table" || ingress+1 > up {
		t.Fatalf("order:\n%s", strings.Join(events, "\n"))
	}
	fake.index(t, "ip route replace 10.209.0.2/32 dev tv012345-0")
	fake.index(t, "ip neigh replace 10.209.0.2 lladdr 02:54:0a:d1:00:02 dev tv012345-0 nud permanent")
	if guest.HostMAC != "fe:54:00:00:00:01" || guest.Gateway.String() != "10.209.0.1" || guest.Tap == nil {
		t.Fatalf("guest network: %+v", guest)
	}

	// An open run's tap is one the kernel routes from.
	_, err = network.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	fake.index(t, "sysctl net/ipv4/conf/tv012345-1/forwarding=1")
}

func TestAttachRefusesWhatItCannotHonour(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	before := len(fake.events)
	for name, attach := range map[string]func() error{
		"allowlist without a port": func() error { _, err := network.Attach(bg, "x", run.NetworkAllowlist, 0); return err },
		"none":                     func() error { _, err := network.Attach(bg, "x", run.NetworkNone, 0); return err },
		"an unknown tier":          func() error { _, err := network.Attach(bg, "x", "bridge", 0); return err },
	} {
		if err := attach(); err == nil {
			t.Errorf("%s: attached", name)
		}
	}
	if len(fake.events) != before {
		t.Fatalf("a refused attach touched the host: %v", fake.events[before:])
	}
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	if _, err := network.Attach(bg, "run-a", run.NetworkOpen, 0); err == nil {
		t.Fatal("a second device for the same VM")
	}
	// No resolver, no open tier: a guest that cannot resolve a name is
	// not what the caller asked for.
	bare := newHostNetwork(testPlan(t, func(c *Config) { c.DNS = nil }), newFakeNet(t).sys(), quietLog())
	if _, err := bare.Attach(bg, "x", run.NetworkOpen, 0); err == nil || !strings.Contains(err.Error(), "DNS") {
		t.Fatalf("open without a resolver: %v", err)
	}
}

func TestAFailedAttachLeavesNothingBehind(t *testing.T) {
	for _, step := range []string{"tap tv012345-0", "sysctl net/ipv4/conf/tv012345-0/forwarding", "nft -f: ingress tap0", "ip link set dev tv012345-0 up", "ip neigh replace"} {
		network, fake := startedNetwork(t, nil)
		fake.fail[step] = errors.New("injected")
		if _, err := network.Attach(bg, "run-a", run.NetworkOpen, 0); err == nil {
			t.Fatalf("%s: attach succeeded", step)
		}
		if len(network.attached) != 0 || len(network.slots) != 0 || fake.links["tv012345-0"] || len(fake.chains) != 0 || strings.Contains(fake.inet, "elements") {
			t.Errorf("after a failure at %q: attached=%v links=%v chains=%v", step, network.attached, fake.links, fake.chains)
		}
		for _, file := range fake.files {
			if _, err := file.Stat(); err == nil {
				t.Errorf("after a failure at %q the tap is still open", step)
			}
		}
	}
}

// A detach that fails half way has already revoked the run's admission,
// keeps its address out of circulation, and can be repeated.
func TestDetachRevokesFirstAndCanBeRepeated(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	fake.fail["ip link del tv012345-0"] = &CommandError{Command: "ip link", Stderr: "RTNETLINK answers: Device or resource busy", Err: errors.New("exit status 2")}
	if err := network.Detach(bg, "run-a"); err == nil {
		t.Fatal("detach succeeded")
	}
	if strings.Contains(fake.inet, "elements") {
		t.Fatalf("a run whose detach failed is still admitted:\n%s", fake.inet)
	}
	other, err := network.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	if other.Address.String() == "10.209.0.2" {
		t.Fatal("the address of a tap that could not be removed was given to another VM")
	}
	if strings.Contains(fake.inet, "10.209.0.2") {
		t.Fatalf("admitting another run admitted the detaching one again:\n%s", fake.inet)
	}
	must(t, network.Detach(bg, "run-a"))
	if fake.links["tv012345-0"] || len(network.attached) != 1 {
		t.Fatalf("after the retry: links=%v attached=%v", fake.links, network.attached)
	}
	// And the connection tracker was told to forget the address.
	fake.mu.Lock()
	forgets := 0
	for _, event := range fake.events {
		if event == "conntrack -D -s 10.209.0.2" {
			forgets++
		}
	}
	fake.mu.Unlock()
	if forgets != 2 { // once before the address was used, once after
		t.Fatalf("conntrack was asked %d times to forget the address", forgets)
	}
}

func TestAnAddressIsNotReusedAtOnce(t *testing.T) {
	network, _ := startedNetwork(t, func(c *Config) { c.Subnet = "198.18.4.0/28" })
	var seen []string
	for i := 0; i < 13; i++ {
		guest, err := network.Attach(bg, "run", run.NetworkOpen, 0)
		must(t, err)
		seen = append(seen, guest.Address.String())
		must(t, network.Detach(bg, "run"))
	}
	if distinct := slices.Compact(slices.Sorted(slices.Values(seen))); len(distinct) != 13 {
		t.Fatalf("an address was reused before every other had been: %v", seen)
	}
	// Full: every address held.
	for i := 0; i < 13; i++ {
		_, err := network.Attach(bg, fmt.Sprintf("run-%d", i), run.NetworkOpen, 0)
		must(t, err)
	}
	if _, err := network.Attach(bg, "one-too-many", run.NetworkOpen, 0); err == nil || !strings.Contains(err.Error(), "all 13 guest addresses") {
		t.Fatalf("a fourteenth VM in a /28: %v", err)
	}
}

func TestSweepRemovesThisDaemonsTapsAndNoOthers(t *testing.T) {
	fake := newFakeNet(t)
	for _, name := range []string{"tv012345-0", "tv012345-2a", "tvabcdef-0", "tvg012345", "tap0", "docker0"} {
		fake.links[name] = true
	}
	fake.chains["tap0"] = "stale"
	network := newHostNetwork(testPlan(t, nil), fake.sys(), quietLog())
	must(t, network.start(bg))
	removed, err := network.Sweep(bg)
	if err != nil || removed != 2 {
		t.Fatalf("sweep: %d %v", removed, err)
	}
	names, _ := fake.sys().links()
	if got := strings.Join(names, " "); got != "docker0 eth0 lo tap0 tvabcdef-0 tvg012345" {
		t.Fatalf("interfaces after the sweep: %s", got)
	}
	if len(fake.chains) != 0 || !strings.Contains(fake.inet, "chain guest_input") {
		t.Fatalf("after the sweep: chains=%v inet=%q", fake.chains, fake.inet)
	}
	// Close with nothing attached removes the tables and the gateway.
	must(t, network.Close(bg))
	if fake.inet != "" || fake.links["tvg012345"] {
		t.Fatalf("close left the table or the gateway device: %q %v", fake.inet, fake.links)
	}
}

func TestCloseKeepsTheTablesWhileAVMIsAttached(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	must(t, network.Close(bg))
	if !strings.Contains(fake.inet, "chain guest_input") || len(fake.chains) != 1 {
		t.Fatal("close removed the firewall of a VM that is still attached")
	}
}

// Two instances of one daemon identity: the later one owns the tables,
// and the earlier one must not write its stale picture over them.
func TestASupersededInstanceLeavesTheTablesAlone(t *testing.T) {
	old, fake := startedNetwork(t, nil)
	_, err := old.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)

	current := newHostNetwork(testPlan(t, nil), fake.sys(), quietLog())
	must(t, current.start(bg))
	t.Cleanup(func() { _ = current.Close(bg) })
	_, err = current.Sweep(bg)
	must(t, err)
	_, err = current.Attach(bg, "run-b", run.NetworkAllowlist, 40002)
	must(t, err)
	tables := fake.inet

	if _, err := old.Attach(bg, "run-c", run.NetworkOpen, 0); !errors.Is(err, errSuperseded) {
		t.Fatalf("attach on a superseded instance: %v", err)
	}
	must(t, old.Detach(bg, "run-a"))
	if old.check(bg) {
		t.Fatal("a superseded instance keeps watching")
	}
	must(t, old.Close(bg))
	if fake.inet != tables || len(fake.chains) != 1 || !fake.links["tvg012345"] {
		t.Fatalf("the superseded instance changed the tables:\n%s", fake.inet)
	}
}

// The same across processes, where the only sign is in the tables: they
// carry another instance's mark.
func TestTablesWithAnotherInstancesMarkAreLeftAlone(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	foreign := strings.Replace(fake.inet, network.instance, "instance_of_another_process", 1)
	fake.mu.Lock()
	fake.inet = foreign
	fake.mu.Unlock()
	if network.check(bg) {
		t.Fatal("the watch goes on over tables that are another instance's")
	}
	if _, err := network.Attach(bg, "run-b", run.NetworkOpen, 0); !errors.Is(err, errSuperseded) {
		t.Fatalf("attach: %v", err)
	}
	must(t, network.Detach(bg, "run-a"))
	must(t, network.Close(bg))
	if fake.inet != foreign {
		t.Fatal("tables with another instance's mark were rewritten")
	}
}

// Something else on the host removed the tables (a firewall reload that
// begins with "flush ruleset"): they are put back as they were.
func TestCheckRestoresTablesSomethingElseRemoved(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, err := network.Attach(bg, "run-a", run.NetworkAllowlist, 40001)
	must(t, err)
	want, wantChain := fake.inet, fake.chains["tap0"]
	if !network.check(bg) || fake.inet != want {
		t.Fatal("a check of intact tables changed them")
	}
	fake.mu.Lock()
	fake.inet, fake.chains = "", map[string]string{}
	fake.mu.Unlock()
	if !network.check(bg) {
		t.Fatal("the watch gave up")
	}
	if fake.inet != want || fake.chains["tap0"] != wantChain {
		t.Fatalf("not restored:\n%s\n%v", fake.inet, fake.chains)
	}
}

// A guest that powers off takes its tap with it, and the kernel removes
// the tap's ingress filter with the device. That is not a filter that
// something else removed: nothing is restored, and nothing is attempted
// every two seconds until the run is removed.
func TestCheckLeavesAVMThatIsGoneAlone(t *testing.T) {
	network, fake := startedNetwork(t, nil)
	_, err := network.Attach(bg, "run-a", run.NetworkOpen, 0)
	must(t, err)
	_, err = network.Attach(bg, "run-b", run.NetworkOpen, 0)
	must(t, err)
	fake.mu.Lock()
	delete(fake.links, "tv012345-0")
	delete(fake.chains, "tap0")
	wantChain := fake.chains["tap1"]
	delete(fake.chains, "tap1")
	before := len(fake.events)
	fake.mu.Unlock()
	if !network.check(bg) {
		t.Fatal("the watch gave up")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if _, restored := fake.chains["tap0"]; restored {
		t.Fatal("a filter was installed for a tap that does not exist")
	}
	for _, event := range fake.events[before:] {
		if strings.Contains(event, "tv012345-0") {
			t.Fatalf("the check touched the tap of a VM that is gone: %s", event)
		}
	}
	// The VM that is still there has its filter back.
	if fake.chains["tap1"] != wantChain || wantChain == "" {
		t.Fatalf("the filter of a live tap was not restored: %v", fake.chains)
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
	attachErr error
	detachErr error
	swept     int
	dir       string
}

func newFakeNetwork(t *testing.T) *fakeNetwork {
	return &fakeNetwork{attached: map[string]*GuestNetwork{}, ports: map[string]int{}, dir: t.TempDir()}
}

func (n *fakeNetwork) Gateway() netip.Addr { return netip.MustParseAddr("10.209.0.1") }

func (n *fakeNetwork) Attach(_ context.Context, name, tier string, proxyPort int) (*GuestNetwork, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.attachErr != nil {
		return nil, n.attachErr
	}
	file, err := os.CreateTemp(n.dir, "tap")
	if err != nil {
		return nil, err
	}
	addr := netip.AddrFrom4([4]byte{10, 209, 0, byte(2 + len(n.history))})
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
	return nil
}

func (n *fakeNetwork) Sweep(context.Context) (int, error) { n.swept++; return 0, nil }
func (n *fakeNetwork) Close(context.Context) error        { return nil }

// fakeEgress is the daemon's proxy pool as the manager sees it.
type fakeEgress struct {
	mu     sync.Mutex
	opened map[string][]string
	closed []string
	next   int
}

func (e *fakeEgress) OpenFor(runID string, extra []string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.opened == nil {
		e.opened = map[string][]string{}
	}
	e.opened[runID] = extra
	e.next++
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
	started := rig.hypervisor.started[0]
	guest := network.attached[name]
	if started.Net == nil || started.Net.MAC != guest.MAC || network.ports[name] != 40001 {
		t.Fatalf("the VM was not started on its device: %+v, port %d", started.Net, network.ports[name])
	}
	// The daemon does not keep the tap open: it must die with the VM.
	if _, err := guest.Tap.Stat(); err == nil {
		t.Fatal("the daemon still holds the tap after the hypervisor started")
	}
	if extra, ok := egress.opened[created.ID]; !ok || len(extra) != 0 {
		t.Fatalf("an allowlist run without entries of its own still gets its own proxy: %v", egress.opened)
	}
	machine := rig.hypervisor.machine(name)
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
	if network.attached[containerName(none.ID)] != nil || rig.hypervisor.started[len(rig.hypervisor.started)-1].Net != nil {
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

	// The device cannot be made: no VM, no volume, and the proxy is closed.
	network.attachErr = errors.New("no tap for you")
	if _, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: "allowlist"}); err == nil || !strings.Contains(err.Error(), "no tap for you") {
		t.Fatalf("create: %v", err)
	}
	if len(rig.hypervisor.started) != 0 || len(egress.closed) != 1 {
		t.Fatalf("after a failed attach: started=%v closed=%v", rig.hypervisor.started, egress.closed)
	}
	assertPool(t, rig.zfs, pristine...)
	network.attachErr = nil

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
	want := []string{"table ip filter chain FORWARD (hook forward)", "table inet firewall chain in (hook input)"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
