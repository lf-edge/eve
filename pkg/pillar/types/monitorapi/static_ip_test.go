// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

import (
	"bytes"
	"encoding/json"
	"flag"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	uuid "github.com/satori/go.uuid"
)

// updateFixtures regenerates the golden JSON in testdata/ instead of comparing.
// Run `go test ./types/monitorapi/ -run TestFixtures -update` (or `go generate`)
// after changing the contract or sample data, then commit the result.
var updateFixtures = flag.Bool("update", false, "update golden fixtures in testdata/")

// fixtureDir holds canonical JSON emitted by Go and consumed by the Rust
// round-trip tests (the cross-language contract gate).
const fixtureDir = "testdata"

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func prefixPtr(p netip.Prefix) *netip.Prefix { return &p }

// networkStatusSample exercises the nested shape: a physical port with a nested
// VLAN, plus a cellular port.
func networkStatusSample() NetworkStatus {
	return NetworkStatus{
		DPCKey: "manual",
		Interfaces: []NetworkInterface{
			{
				Name: "eth0", Label: "uplink", Up: true, IsMgmt: true,
				MAC:   "00:11:22:33:44:55",
				Media: MediaEthernet{},
				Network: PortNetwork{
					IsDHCP:     true,
					IPv4:       []netip.Addr{mustAddr("192.0.2.10")},
					Subnet:     prefixPtr(netip.MustParsePrefix("192.0.2.0/24")),
					DNSServers: []netip.Addr{mustAddr("192.0.2.53")},
					Proxy: ProxyManual{Servers: []ProxyServer{
						{Scheme: ProxySchemeHTTP, Host: "proxy", Port: 8080}}},
				},
				VLANs: []VLAN{{
					ID: 100, Name: "eth0.100", Label: "office", Up: true,
					Network: PortNetwork{Proxy: ProxyNone{}},
				}},
			},
			{
				Name: "wwan0", Label: "cell", Up: true,
				Media: MediaCellular{
					Modem: "Quectel EM120", Operator: "Verizon", Roaming: false,
					RATs: []string{"LTE"},
					SIMs: []SIM{{Slot: 1, Activated: true, State: "present", APN: "vzwinternet"}},
				},
				Network: PortNetwork{Proxy: ProxyNone{}},
			},
		},
	}
}

func validSample() StaticIPConfig {
	gw := mustAddr("192.0.2.1")
	return StaticIPConfig{
		IP:         mustAddr("192.0.2.10"),
		Subnet:     netip.MustParsePrefix("192.0.2.0/24"),
		Gateway:    &gw,
		DNSServers: []netip.Addr{mustAddr("192.0.2.53"), mustAddr("2001:db8::53")},
	}
}

// TestCanonicalJSON pins the exact wire encoding netip produces, so we notice
// if the encoding ever drifts (the thing the Rust side is generated against).
func TestCanonicalJSON(t *testing.T) {
	got, err := json.Marshal(validSample())
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"ip":"192.0.2.10","subnet":"192.0.2.0/24","gateway":"192.0.2.1","dnsServers":["192.0.2.53","2001:db8::53"]}`
	if string(got) != want {
		t.Fatalf("canonical JSON drift:\n got: %s\nwant: %s", got, want)
	}
}

func TestValidate(t *testing.T) {
	if err := validSample().Validate(); err != nil {
		t.Fatalf("valid sample rejected: %v", err)
	}

	bad := validSample()
	bad.IP = mustAddr("10.0.0.5") // outside 192.0.2.0/24
	if err := bad.Validate(); err == nil {
		t.Fatal("expected out-of-subnet ip to fail validation")
	}

	badGw := validSample()
	g := mustAddr("10.0.0.1")
	badGw.Gateway = &g
	if err := badGw.Validate(); err == nil {
		t.Fatal("expected out-of-subnet gateway to fail validation")
	}
}

// TestFromLegacy proves the legacy net.IP / *net.IPNet -> contract conversion.
func TestFromLegacy(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("192.0.2.0/24")
	cfg, err := FromLegacy(
		net.ParseIP("192.0.2.10"),
		subnet,
		net.ParseIP("192.0.2.1"),
		[]net.IP{net.ParseIP("192.0.2.53")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("converted config invalid: %v", err)
	}
	if cfg.Subnet.String() != "192.0.2.0/24" || cfg.IP.String() != "192.0.2.10" {
		t.Fatalf("unexpected conversion: %+v", cfg)
	}
}

// TestUnionRoundTrip proves the generated Go codec round-trips through the
// interface field: marshal (tag injection) -> unmarshal (dispatch) -> equal.
func TestUnionRoundTrip(t *testing.T) {
	orig := NetworkProxy{Port: "eth0", Proxy: ProxyManual{
		Servers:    []ProxyServer{{Scheme: ProxySchemeHTTPS, Host: "p.example.com", Port: 8080}},
		Exceptions: []string{"localhost"},
	}}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"proxy":{"mode":"manual"`) {
		t.Fatalf("marshalled union missing tag: %s", b)
	}
	var got NetworkProxy
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Proxy.(ProxyManual); !ok {
		t.Fatalf("dispatch produced wrong variant: %T", got.Proxy)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("round-trip mismatch:\n orig: %+v\n got:  %+v", orig, got)
	}
	if _, err := UnmarshalProxySettings([]byte(`{"mode":"bogus"}`)); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

// fixtures is the canonical set of wire payloads the Rust side consumes. They
// are produced by Go (the source of truth for the wire format) — the proxy
// entries also exercise the generated Go union marshaller.
func fixtures() map[string]any {
	outOfSubnet := validSample()
	outOfSubnet.IP = mustAddr("10.0.0.5")
	return map[string]any{
		"static_ip_valid.json":         validSample(),
		"static_ip_out_of_subnet.json": outOfSubnet,
		"static_ip_minimal.json": StaticIPConfig{
			IP:     mustAddr("198.51.100.7"),
			Subnet: netip.MustParsePrefix("198.51.100.0/24"),
		},
		"proxy_none.json": ProxyNone{},
		"proxy_manual.json": ProxyManual{
			Servers: []ProxyServer{{Scheme: ProxySchemeHTTPS, Host: "proxy.example.com", Port: 8080}},
		},
		"proxy_pac.json": ProxyPac{PacFile: "https://example.com/wpad.dat"},
		"network_proxy.json": NetworkProxy{Port: "eth0", Proxy: ProxyManual{
			Servers: []ProxyServer{{Scheme: ProxySchemeHTTP, Host: "10.0.0.1", Port: 3128}},
		}},
		"onboarding_status.json": OnboardingStatus{
			DeviceUUID:    uuid.FromStringOrNil("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
			HardwareModel: "QEMU Standard PC",
		},
		"node_status.json": NodeStatus{
			Server:    "zedcloud.example.com:443",
			NodeUUID:  uuid.FromStringOrNil("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
			Onboarded: true,
			NodeName:  "edge-node-01",
			Serial:    "ABC123XYZ",
		},
		"network_status.json":    networkStatusSample(),
		"app_summary.json":       AppSummary{Starting: 1, Running: 5, Stopping: 0, Error: 2},
		"tui_config.json":        TUIConfig{LogLevel: "debug"},
		"led_blink_counter.json": LedBlinkCounter{BlinkCounter: 4},
	}
}

// TestFixtures is a golden-file gate: by default it verifies the committed
// testdata/ matches what Go produces; with -update it rewrites them. CI runs
// without -update, so a stale fixture fails the build.
func TestFixtures(t *testing.T) {
	if *updateFixtures {
		if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, v := range fixtures() {
		got, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(fixtureDir, name)
		if *updateFixtures {
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("missing fixture %s: %v (run with -update)", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("fixture %s is out of date; run "+
				"`go test ./types/monitorapi/ -run TestFixtures -update` and commit", name)
		}
	}
}
