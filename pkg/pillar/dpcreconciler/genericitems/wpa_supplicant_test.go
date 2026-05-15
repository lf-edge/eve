// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"path/filepath"
	"strings"
	"testing"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// mockAdapter implements depgraph.Item and wirelessTypeGetter for testing
// the MustSatisfy closure inside Dependencies().
type mockAdapter struct {
	ifName string
	wType  types.WirelessType
}

func (a mockAdapter) Name() string                        { return a.ifName }
func (a mockAdapter) Label() string                       { return a.ifName }
func (a mockAdapter) Type() string                        { return AdapterTypename }
func (a mockAdapter) Equal(dg.Item) bool                  { return false }
func (a mockAdapter) External() bool                      { return false }
func (a mockAdapter) String() string                      { return a.ifName }
func (a mockAdapter) Dependencies() []dg.Dependency       { return nil }
func (a mockAdapter) GetWirelessType() types.WirelessType { return a.wType }

func TestWifiConfigString(t *testing.T) {
	t.Parallel()
	cfg := WifiConfig{
		SSID:         "MyNetwork",
		KeyScheme:    types.KeySchemeWpaPsk,
		Identity:     "user@example.com",
		PasswordHash: "abc123",
		Priority:     5,
	}
	s := cfg.String()
	if !strings.Contains(s, "MyNetwork") {
		t.Errorf("String() missing SSID, got: %s", s)
	}
	if strings.Contains(s, "abc123") {
		t.Errorf("String() must not include password hash, got: %s", s)
	}
	if !strings.Contains(s, "5") {
		t.Errorf("String() missing priority, got: %s", s)
	}
}

func TestPNAC8021XConfigEqual(t *testing.T) {
	t.Parallel()
	base := &PNAC8021XConfig{
		EAPIdentity:      "device@corp",
		CACertBundlePath: "/certs/ca.pem",
		ClientCertPath:   "/certs/client.pem",
		ClientKeyPath:    "/certs/client.key",
	}
	type test struct {
		name     string
		a, b     *PNAC8021XConfig
		expEqual bool
	}
	tests := []test{
		{"both nil", nil, nil, true},
		{"nil vs non-nil", nil, base, false},
		{"non-nil vs nil", base, nil, false},
		{"identical", base, &PNAC8021XConfig{
			EAPIdentity:      "device@corp",
			CACertBundlePath: "/certs/ca.pem",
			ClientCertPath:   "/certs/client.pem",
			ClientKeyPath:    "/certs/client.key",
		}, true},
		{"different identity", base, &PNAC8021XConfig{
			EAPIdentity:      "other@corp",
			CACertBundlePath: "/certs/ca.pem",
			ClientCertPath:   "/certs/client.pem",
			ClientKeyPath:    "/certs/client.key",
		}, false},
		{"different CA cert", base, &PNAC8021XConfig{
			EAPIdentity:      "device@corp",
			CACertBundlePath: "/certs/other-ca.pem",
			ClientCertPath:   "/certs/client.pem",
			ClientKeyPath:    "/certs/client.key",
		}, false},
		{"different client cert", base, &PNAC8021XConfig{
			EAPIdentity:      "device@corp",
			CACertBundlePath: "/certs/ca.pem",
			ClientCertPath:   "/certs/other.pem",
			ClientKeyPath:    "/certs/client.key",
		}, false},
		{"different client key", base, &PNAC8021XConfig{
			EAPIdentity:      "device@corp",
			CACertBundlePath: "/certs/ca.pem",
			ClientCertPath:   "/certs/client.pem",
			ClientKeyPath:    "/certs/other.key",
		}, false},
	}
	for _, tc := range tests {
		got := tc.a.Equal(tc.b)
		if got != tc.expEqual {
			t.Errorf("TEST CASE %q: Equal() = %v, want %v", tc.name, got, tc.expEqual)
		}
	}
}

func TestPNAC8021XConfigString(t *testing.T) {
	t.Parallel()
	if got := (*PNAC8021XConfig)(nil).String(); got != "<nil>" {
		t.Errorf("nil.String() = %q, want \"<nil>\"", got)
	}
	cfg := &PNAC8021XConfig{
		EAPIdentity:      "device@corp",
		CACertBundlePath: "/certs/ca.pem",
		ClientCertPath:   "/certs/client.pem",
		ClientKeyPath:    "/certs/client.key",
	}
	s := cfg.String()
	for _, want := range []string{"device@corp", "/certs/ca.pem", "/certs/client.pem", "/certs/client.key"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() missing %q, got: %s", want, s)
		}
	}
}

func TestWpaSupplicantName(t *testing.T) {
	t.Parallel()
	s := WpaSupplicant{AdapterIfName: "wlan0"}
	if got := s.Name(); got != "wlan0" {
		t.Errorf("Name() = %q, want %q", got, "wlan0")
	}
}

func TestWpaSupplicantLabel(t *testing.T) {
	t.Parallel()
	s := WpaSupplicant{AdapterLL: "wifi-port", AdapterIfName: "wlan0"}
	label := s.Label()
	if !strings.Contains(label, "wifi-port") {
		t.Errorf("Label() = %q, want it to contain logical label", label)
	}
}

func TestWpaSupplicantType(t *testing.T) {
	t.Parallel()
	s := WpaSupplicant{}
	if got := s.Type(); got != WpaSupplicantTypename {
		t.Errorf("Type() = %q, want %q", got, WpaSupplicantTypename)
	}
}

func TestWpaSupplicantExternal(t *testing.T) {
	t.Parallel()
	s := WpaSupplicant{}
	if s.External() {
		t.Error("External() = true, want false")
	}
}

func TestWpaSupplicantEqual(t *testing.T) {
	t.Parallel()
	psk := WifiConfig{SSID: "net1", KeyScheme: types.KeySchemeWpaPsk, PasswordHash: "hash1"}
	eap := WifiConfig{SSID: "net2", KeyScheme: types.KeySchemeWpaEap, Identity: "u", PasswordHash: "hash2"}
	pnac := &PNAC8021XConfig{
		EAPIdentity:      "dev@corp",
		CACertBundlePath: "/ca.pem",
		ClientCertPath:   "/c.pem",
		ClientKeyPath:    "/k.key",
	}
	type test struct {
		name     string
		a, b     WpaSupplicant
		expEqual bool
	}
	tests := []test{
		{
			name:     "identical WiFi configs",
			a:        WpaSupplicant{WiFiConfigs: []WifiConfig{psk, eap}},
			b:        WpaSupplicant{WiFiConfigs: []WifiConfig{psk, eap}},
			expEqual: true,
		},
		{
			name:     "WiFi configs in different order (EqualSets)",
			a:        WpaSupplicant{WiFiConfigs: []WifiConfig{psk, eap}},
			b:        WpaSupplicant{WiFiConfigs: []WifiConfig{eap, psk}},
			expEqual: true,
		},
		{
			name:     "different WiFi SSID",
			a:        WpaSupplicant{WiFiConfigs: []WifiConfig{{SSID: "A"}}},
			b:        WpaSupplicant{WiFiConfigs: []WifiConfig{{SSID: "B"}}},
			expEqual: false,
		},
		{
			name:     "different number of WiFi configs",
			a:        WpaSupplicant{WiFiConfigs: []WifiConfig{psk}},
			b:        WpaSupplicant{WiFiConfigs: []WifiConfig{psk, eap}},
			expEqual: false,
		},
		{
			name:     "identical PNAC config",
			a:        WpaSupplicant{PNACConfig: pnac},
			b:        WpaSupplicant{PNACConfig: &PNAC8021XConfig{EAPIdentity: "dev@corp", CACertBundlePath: "/ca.pem", ClientCertPath: "/c.pem", ClientKeyPath: "/k.key"}},
			expEqual: true,
		},
		{
			name:     "different PNAC identity",
			a:        WpaSupplicant{PNACConfig: pnac},
			b:        WpaSupplicant{PNACConfig: &PNAC8021XConfig{EAPIdentity: "other@corp", CACertBundlePath: "/ca.pem", ClientCertPath: "/c.pem", ClientKeyPath: "/k.key"}},
			expEqual: false,
		},
		{
			name:     "one WiFi one PNAC",
			a:        WpaSupplicant{WiFiConfigs: []WifiConfig{psk}},
			b:        WpaSupplicant{PNACConfig: pnac},
			expEqual: false,
		},
		{
			name:     "wrong item type",
			a:        WpaSupplicant{WiFiConfigs: []WifiConfig{psk}},
			expEqual: false, // b is zero Resolvconf, not WpaSupplicant
		},
	}
	for _, tc := range tests {
		var other dg.Item
		if tc.name == "wrong item type" {
			other = ResolvConf{}
		} else {
			other = tc.b
		}
		got := tc.a.Equal(other)
		if got != tc.expEqual {
			t.Errorf("TEST CASE %q: Equal() = %v, want %v", tc.name, got, tc.expEqual)
		}
	}
}

func TestWpaSupplicantString(t *testing.T) {
	t.Parallel()
	wifi := WpaSupplicant{
		AdapterLL:     "wifi-port",
		AdapterIfName: "wlan0",
		WiFiConfigs: []WifiConfig{
			{SSID: "HomeNet", KeyScheme: types.KeySchemeWpaPsk},
		},
	}
	s := wifi.String()
	if !strings.Contains(s, "Wi-Fi") {
		t.Errorf("WiFi String() missing Wi-Fi, got: %s", s)
	}
	if !strings.Contains(s, "HomeNet") {
		t.Errorf("WiFi String() missing SSID, got: %s", s)
	}

	pnacS := WpaSupplicant{
		AdapterLL:     "eth-port",
		AdapterIfName: "eth0",
		PNACConfig:    &PNAC8021XConfig{EAPIdentity: "dev@corp"},
	}
	s2 := pnacS.String()
	if !strings.Contains(s2, "802.1X") {
		t.Errorf("PNAC String() missing 802.1X, got: %s", s2)
	}

	empty := WpaSupplicant{AdapterLL: "eth-port", AdapterIfName: "eth0"}
	s3 := empty.String()
	if !strings.Contains(s3, "no configuration") {
		t.Errorf("empty String() missing 'no configuration', got: %s", s3)
	}
}

func TestWpaSupplicantDependencies(t *testing.T) {
	t.Parallel()

	wifiSupplicant := WpaSupplicant{
		AdapterIfName: "wlan0",
		WiFiConfigs:   []WifiConfig{{SSID: "net"}},
	}
	deps := wifiSupplicant.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("Dependencies() returned %d deps, want 1", len(deps))
	}
	dep := deps[0]
	if dep.RequiredItem.ItemType != AdapterTypename {
		t.Errorf("dep.ItemType = %q, want %q", dep.RequiredItem.ItemType, AdapterTypename)
	}
	if dep.RequiredItem.ItemName != "wlan0" {
		t.Errorf("dep.ItemName = %q, want %q", dep.RequiredItem.ItemName, "wlan0")
	}

	// MustSatisfy: WiFi supplicant requires WirelessTypeWifi adapter.
	wifiAdapter := mockAdapter{ifName: "wlan0", wType: types.WirelessTypeWifi}
	ethAdapter := mockAdapter{ifName: "wlan0", wType: types.WirelessTypeNone}
	if !dep.MustSatisfy(wifiAdapter) {
		t.Error("MustSatisfy(WiFi adapter) = false for WiFi supplicant, want true")
	}
	if dep.MustSatisfy(ethAdapter) {
		t.Error("MustSatisfy(Ethernet adapter) = true for WiFi supplicant, want false")
	}

	// PNAC supplicant requires a wired (WirelessTypeNone) adapter.
	pnacSupplicant := WpaSupplicant{
		AdapterIfName: "eth0",
		PNACConfig:    &PNAC8021XConfig{},
	}
	pnacDeps := pnacSupplicant.Dependencies()
	if len(pnacDeps) != 1 {
		t.Fatalf("PNAC Dependencies() returned %d deps, want 1", len(pnacDeps))
	}
	ethAdapter2 := mockAdapter{ifName: "eth0", wType: types.WirelessTypeNone}
	wifiAdapter2 := mockAdapter{ifName: "eth0", wType: types.WirelessTypeWifi}
	if !pnacDeps[0].MustSatisfy(ethAdapter2) {
		t.Error("MustSatisfy(Ethernet adapter) = false for PNAC supplicant, want true")
	}
	if pnacDeps[0].MustSatisfy(wifiAdapter2) {
		t.Error("MustSatisfy(WiFi adapter) = true for PNAC supplicant, want false")
	}
	// Non-adapter item type-asserts to wirelessTypeGetter → fails → false.
	if pnacDeps[0].MustSatisfy(ResolvConf{}) {
		t.Error("MustSatisfy(non-adapter) = true, want false")
	}
}

func TestWpaSupplicantNeedsRecreate(t *testing.T) {
	t.Parallel()
	c := &WpaSupplicantConfigurator{}
	old := WpaSupplicant{AdapterIfName: "wlan0", WiFiConfigs: []WifiConfig{{SSID: "A"}}}
	updated := WpaSupplicant{AdapterIfName: "wlan0", WiFiConfigs: []WifiConfig{{SSID: "B"}}}
	if !c.NeedsRecreate(old, updated) {
		t.Error("NeedsRecreate() = false, want true (Modify is not implemented)")
	}
}

func TestWpaSupplicantConfiguratorPaths(t *testing.T) {
	t.Parallel()
	c := &WpaSupplicantConfigurator{}
	ifName := "wlan0"

	cfgPath := c.configPath(ifName)
	if !strings.HasSuffix(cfgPath, "wpa_supplicant-wlan0.conf") {
		t.Errorf("configPath() = %q, want suffix wpa_supplicant-wlan0.conf", cfgPath)
	}
	if filepath.Dir(cfgPath) != nimRunDir {
		t.Errorf("configPath() dir = %q, want %q", filepath.Dir(cfgPath), nimRunDir)
	}

	watcherPath := c.eventWatcherScriptPath(ifName)
	if !strings.HasSuffix(watcherPath, "wpa_supplicant-wlan0-watcher.sh") {
		t.Errorf("eventWatcherScriptPath() = %q, want suffix wpa_supplicant-wlan0-watcher.sh", watcherPath)
	}

	statePath := c.pnacStatePath(ifName)
	if !strings.HasSuffix(statePath, ifName) {
		t.Errorf("pnacStatePath() = %q, want suffix %q", statePath, ifName)
	}
	if filepath.Dir(statePath) != types.PNACStateDir {
		t.Errorf("pnacStatePath() dir = %q, want %q", filepath.Dir(statePath), types.PNACStateDir)
	}
}

func TestRenderWifiConfig(t *testing.T) {
	t.Parallel()
	c := &WpaSupplicantConfigurator{}

	t.Run("PSK network", func(t *testing.T) {
		t.Parallel()
		cfgs := []WifiConfig{
			{SSID: "MyHome", KeyScheme: types.KeySchemeWpaPsk, PasswordHash: "abc123hash"},
		}
		out := c.renderWifiConfig(cfgs)
		for _, want := range []string{
			"ctrl_interface=",
			"ap_scan=1",
			`ssid="MyHome"`,
			"key_mgmt=WPA-PSK",
			"psk=abc123hash",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("renderWifiConfig PSK: missing %q in output:\n%s", want, out)
			}
		}
		if strings.Contains(out, "WPA-EAP") {
			t.Errorf("renderWifiConfig PSK: unexpected WPA-EAP in output:\n%s", out)
		}
	})

	t.Run("PSK network without password hash", func(t *testing.T) {
		t.Parallel()
		cfgs := []WifiConfig{
			{SSID: "OpenNet", KeyScheme: types.KeySchemeWpaPsk},
		}
		out := c.renderWifiConfig(cfgs)
		if strings.Contains(out, "psk=") {
			t.Errorf("renderWifiConfig PSK no-password: unexpected psk= in output:\n%s", out)
		}
	})

	t.Run("EAP network", func(t *testing.T) {
		t.Parallel()
		cfgs := []WifiConfig{
			{
				SSID:         "CorpWifi",
				KeyScheme:    types.KeySchemeWpaEap,
				Identity:     "user@corp.com",
				PasswordHash: "eaphash",
			},
		}
		out := c.renderWifiConfig(cfgs)
		for _, want := range []string{
			"key_mgmt=WPA-EAP",
			"eap=PEAP",
			`identity="user@corp.com"`,
			"password=hash:eaphash",
			"phase1=",
			"phase2=",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("renderWifiConfig EAP: missing %q in output:\n%s", want, out)
			}
		}
	})

	t.Run("EAP network without identity or password", func(t *testing.T) {
		t.Parallel()
		cfgs := []WifiConfig{
			{SSID: "CorpWifi", KeyScheme: types.KeySchemeWpaEap},
		}
		out := c.renderWifiConfig(cfgs)
		if strings.Contains(out, "identity=") {
			t.Errorf("renderWifiConfig EAP no-identity: unexpected identity= in output:\n%s", out)
		}
		if strings.Contains(out, "password=") {
			t.Errorf("renderWifiConfig EAP no-password: unexpected password= in output:\n%s", out)
		}
	})

	t.Run("multiple networks with priority", func(t *testing.T) {
		t.Parallel()
		cfgs := []WifiConfig{
			{SSID: "Primary", KeyScheme: types.KeySchemeWpaPsk, Priority: 10},
			{SSID: "Backup", KeyScheme: types.KeySchemeWpaPsk, Priority: 0},
		}
		out := c.renderWifiConfig(cfgs)
		if !strings.Contains(out, `ssid="Primary"`) {
			t.Errorf("renderWifiConfig multi: missing Primary SSID:\n%s", out)
		}
		if !strings.Contains(out, `ssid="Backup"`) {
			t.Errorf("renderWifiConfig multi: missing Backup SSID:\n%s", out)
		}
		if !strings.Contains(out, "priority=10") {
			t.Errorf("renderWifiConfig multi: missing priority=10:\n%s", out)
		}
		// Priority 0 should not appear (zero means "don't set priority").
		if strings.Contains(out, "priority=0") {
			t.Errorf("renderWifiConfig multi: unexpected priority=0 in output:\n%s", out)
		}
	})
}

func TestRenderPNACConfig(t *testing.T) {
	t.Parallel()
	c := &WpaSupplicantConfigurator{}

	t.Run("full PNAC config", func(t *testing.T) {
		t.Parallel()
		cfg := PNAC8021XConfig{
			EAPIdentity:      "device@corp.com",
			CACertBundlePath: "/certs/ca-bundle.pem",
			ClientCertPath:   "/certs/device.pem",
			ClientKeyPath:    "/certs/device.key",
		}
		out := c.renderPNACConfig(cfg)
		for _, want := range []string{
			"ctrl_interface=",
			"ap_scan=0",
			"key_mgmt=IEEE8021X",
			"eap=TLS",
			"eapol_flags=0",
			`identity="device@corp.com"`,
			`ca_cert="/certs/ca-bundle.pem"`,
			`client_cert="/certs/device.pem"`,
			`private_key="/certs/device.key"`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("renderPNACConfig: missing %q in output:\n%s", want, out)
			}
		}
		// Must not contain ap_scan=1 (that's the WiFi path).
		if strings.Contains(out, "ap_scan=1") {
			t.Errorf("renderPNACConfig: unexpected ap_scan=1 in output:\n%s", out)
		}
	})

	t.Run("empty identity", func(t *testing.T) {
		t.Parallel()
		cfg := PNAC8021XConfig{
			CACertBundlePath: "/ca.pem",
			ClientCertPath:   "/c.pem",
			ClientKeyPath:    "/k.key",
		}
		out := c.renderPNACConfig(cfg)
		if !strings.Contains(out, `identity=""`) {
			t.Errorf("renderPNACConfig empty identity: missing empty identity field:\n%s", out)
		}
	})
}
