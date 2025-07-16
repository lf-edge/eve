// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	lastResortParamKey = "LAST_RESORT_ENABLED"
)

var (
	lastResortParam = evetest.TestParameterDefinition{
		Key:          lastResortParamKey,
		DefaultValue: false,
		Description: evetest.TestParameterDescription{
			Summary: "Explicitly enable last-resort (fallback) DPC in the device config",
			Default: "false",
		},
	}
)

func deviceRequirementsForBootstrap(devName string) evetest.RequireEdgeDevice {
	return evetest.RequireEdgeDevice{
		Name:           devName,
		WithHypervisor: evetest.HypervisorKVM,
		MinCPUs:        4,
		WithGrubOptions: []string{
			// No applications are deployed in network bootstrapping tests.
			// Focus on maximizing EVE performance and reducing device onboarding time.
			"set_global hv_dom0_cpu_settings \"dom0_max_vcpus=4\"",
			"set_global hv_eve_cpu_settings \"eve_max_vcpus=3\"",
			"set_global hv_ctrd_cpu_settings \"ctrd_max_vcpus=3\""},
		// We start from scratch to test device connectivity bootstrapping.
		DeviceReusePolicy: evetest.CreateFromScratchWithLiveImage,
	}
}

// TestBootstrapWithLastResort verifies that a freshly installed EVE device,
// shipped WITHOUT bootstrap config and without an override.json, can still
// reach the controller by falling back to the "last resort" DPC (a
// generated DHCP-on-every-Ethernet-port config). It also verifies the
// retention policy: by default last-resort disappears from the
// DevicePortConfigList once the device has working controller connectivity
// from a controller-supplied DPC, but if `network.fallback.any.eth` is
// explicitly enabled in the device config, the last-resort DPC stays
// persisted in the DPCL.
//
// See DEVICE-CONNECTIVITY.md "Last resort" for the underlying mechanism.
//
// Test parameters
// ---------------
//   - LAST_RESORT_ENABLED (bool, default false): when true, the device
//     config sets network.fallback.any.eth=ENABLED via SetConfigProperties.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one Ethernet port with a DHCP server
//     and SDN DNS + controller reachability. This is exactly the
//     environment where last-resort can succeed.
//
// Device configuration
// --------------------
//   - DeviceReusePolicy=CreateFromScratchWithLiveImage to actually exercise
//     the first-boot bootstrap path.
//   - WithHypervisor=HypervisorKVM, MinCPUs=4, vcpu grub options to
//     minimize onboarding time (no apps are deployed).
//   - Apply a "real" controller config after onboarding: DHCP NetworkConfig
//     on eth0, mgmt+app usage. If LAST_RESORT_ENABLED is set, additionally
//     enable `network.fallback.any.eth` as a global config property.
//
// Assertions
// ----------
//   - The fact that evetest.Setup returns is itself a positive assertion:
//     it means the device onboarded over Adam, which is only possible if
//     last-resort bootstrap worked.
//   - WatchDeviceInfo until SystemAdapterInfo.CurrentIndex=0 and the DPC
//     list matches:
//   - LAST_RESORT_ENABLED=false: exactly one entry, key="zedagent" --
//     the previous "lastresort" DPC has been pruned per the default
//     retention policy.
//   - LAST_RESORT_ENABLED=true:  two entries, ["zedagent","lastresort"]
//     -- last-resort is retained as a fallback.
//   - The assertion is implemented via the matchSystemAdapterInfo helper
//     defined at the bottom of this file.
//
// Hypervisor
// ----------
//   - Hardcoded HypervisorKVM (Bootstrap-suite test; not parameterized).
func TestBootstrapWithLastResort(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		lastResortParam,
	)

	// Get parameter values set for this test execution.
	lastResortExplicitlyEnabled := evetest.GetTestParameter[bool](lastResortParamKey)

	// Set up the test harness and specify the test prerequisites.
	devName := "edge-dev"
	requiredDevice := deviceRequirementsForBootstrap(devName)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCP,
	}
	evetest.Setup(requiredDevice, requiredNetModel)

	// If we got here, device was able to bootstrap controller connectivity using
	// the bootstrap config or override.json.
	device := evetest.GetEdgeDevice(devName)
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	evetest.Checkpoint("setup-done")

	// Apply the initial device configuration.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	if lastResortExplicitlyEnabled {
		cfgProps := pillartypes.NewConfigItemValueMap()
		cfgProps.SetGlobalValueTriState(
			pillartypes.NetworkFallbackAnyEth, pillartypes.TS_ENABLED)
		devConfig.SetConfigProperties(cfgProps)
	}
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "eth0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")

	// Wait for device info to report the expected DevicePortStatus list.
	var expectedKeys []string
	if lastResortExplicitlyEnabled {
		expectedKeys = []string{"zedagent", "lastresort"}
	} else {
		// Last-resort was used only initially and once controller connectivity
		// was working it got removed from DPCL.
		expectedKeys = []string{"zedagent"}
	}
	timeout := 3 * time.Minute
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Device has applied and reported expected network configuration",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			return matchSystemAdapterInfo(dinfo.GetSystemAdapter(), 0, expectedKeys)
		})))
}

const useOverrideJSONParamKey = "USE_OVERRIDE_JSON"

var (
	useOverrideJSONParam = evetest.TestParameterDefinition{
		Key:          useOverrideJSONParamKey,
		DefaultValue: false,
		Description: evetest.TestParameterDescription{
			Summary: "Inject static IP config via override.json instead of bootstrap config",
			Default: "false",
		},
	}
)

// TestBootstrapWithStaticIP verifies that an EVE device which cannot obtain
// an IP via DHCP (because the upstream network has no DHCP server) can
// still onboard when it is shipped with a pre-built network configuration
// that supplies a static IPv4 address. Both injection paths supported by
// EVE are covered: the modern "bootstrap config" (signed by the
// controller, baked into the installer) and the legacy "override.json"
// (raw DevicePortConfig JSON on the installer / USB stick). After
// onboarding, the same configuration is also pushed via the controller and
// the test confirms the device ends up on a single controller-supplied DPC
// with no leftover bootstrap/override entries in the DPCL.
//
// See DEVICE-CONNECTIVITY.md "Sources of configuration" + CONFIG.md
// "Bootstrap configuration".
//
// Test parameters
// ---------------
//   - USE_OVERRIDE_JSON (bool, default false):
//   - false: inject via RequireEdgeDevice.WithInjectedBootstrapConfig
//     (a fully-built EdgeDeviceConfig signed by the controller).
//   - true:  inject via WithInjectedNetworkOverride (a raw
//     pillartypes.DevicePortConfig blob, key="" -- the legacy path).
//
// Network model
// -------------
//   - netmodels.SingleEthWithoutDHCP -- one Ethernet port, SDN router with
//     no DHCP server. The static IP injected into the device
//     (172.20.20.10) matches the SDN's subnet.
//
// Device configuration
// --------------------
//   - DeviceReusePolicy=CreateFromScratchWithLiveImage (first-boot path).
//   - Injected config: SystemAdapter on eth0 (mgmt+app, static IP
//     172.20.20.10, gateway 172.20.20.1, DNS 10.16.16.25).
//   - After onboarding, push the same config through the controller via
//     device.ApplyConfig.
//
// Assertions
// ----------
//   - evetest.Setup succeeding implies the device onboarded via the
//     injected config (no DHCP path was available).
//   - WatchDeviceInfo until SystemAdapterInfo.CurrentIndex=0 and the DPC
//     list contains exactly one entry with key="zedagent" -- both
//     injection paths must not leave residual "bootstrap" or
//     "override"/"manual" DPCs in the list after controller config
//     takes over.
//
// Hypervisor
// ----------
//   - Hardcoded HypervisorKVM (Bootstrap-suite test; not parameterized).
func TestBootstrapWithStaticIP(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		useOverrideJSONParam,
	)

	// Get parameter values set for this test execution.
	useOverrideJSON := evetest.GetTestParameter[bool](useOverrideJSONParamKey)

	// Build bootstrap configuration.
	devName := "edge-dev"
	bootstrapConfig := evetest.NewEdgeDeviceConfig(devName)
	staticNet := bootstrapConfig.AddNetwork(
		// matches netmodels.SingleEthWithoutDHCP
		evetest.StaticNetworkConfig{
			NetworkType: evecommon.NetworkType_V4,
			Subnet:      evetest.IPSubnet("172.20.20.0/24"),
			Gateway:     evetest.IPAddress("172.20.20.1"),
			DNSServers:  []net.IP{evetest.IPAddress("10.16.16.25")},
		})
	bootstrapConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "eth0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   staticNet,
			// StaticIP matches netmodels.SingleEthWithoutDHCP
			StaticIP: evetest.IPAddress("172.20.20.10"),
			Usage:    evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})

	// Set up the test harness and specify test prerequisites.
	requiredDevice := deviceRequirementsForBootstrap(devName)
	if useOverrideJSON {
		requiredDevice.WithInjectedNetworkOverride = &pillartypes.DevicePortConfig{
			Version:      1,
			Key:          "",
			TimePriority: time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
			Ports: []pillartypes.NetworkPortConfig{
				{
					IfName: "eth0",
					IsMgmt: true,
					DhcpConfig: pillartypes.DhcpConfig{
						Dhcp: pillartypes.DhcpTypeStatic,
						// IP config matches netmodels.SingleEthWithoutDHCP
						AddrSubnet: "172.20.20.10/24",
						Gateway:    evetest.IPAddress("172.20.20.1"),
						DNSServers: []net.IP{evetest.IPAddress("10.16.16.25")},
						Type:       pillartypes.NetworkTypeIPv4,
					},
				},
			},
		}
	} else {
		requiredDevice.WithInjectedBootstrapConfig = bootstrapConfig
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithoutDHCP,
	}
	evetest.Setup(requiredDevice, requiredNetModel)

	// If we got here, device was able to bootstrap controller connectivity using
	// the bootstrap config or override.json.
	device := evetest.GetEdgeDevice(devName)
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	evetest.Checkpoint("setup-done")

	// Apply the same bootstrap configuration also through the controller.
	device.ApplyConfig(bootstrapConfig, true, true)
	evetest.Checkpoint("config-applied")

	// Neither bootstrap config nor override.json remain persisted after
	// the controller connectivity was established.
	timeout := 3 * time.Minute
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Device has applied and reported expected network configuration",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			return matchSystemAdapterInfo(dinfo.GetSystemAdapter(), 0, []string{"zedagent"})
		})))
}

// ProxyConfigType is used as a configurable parameter for TestBootstrapWithProxy.
type ProxyConfigType int

const (
	ProxyConfigUndefined ProxyConfigType = iota
	ProxyConfigManual
	ProxyConfigTransparent
	ProxyConfigAutoDiscovery
	ProxyConfigWPADURL
	ProxyConfigPACScript
)

func (pc ProxyConfigType) String() string {
	switch pc {
	case ProxyConfigManual:
		return "manual"
	case ProxyConfigTransparent:
		return "transparent"
	case ProxyConfigAutoDiscovery:
		return "autodiscovery"
	case ProxyConfigWPADURL:
		return "wpad-url"
	case ProxyConfigPACScript:
		return "pac-script"
	case ProxyConfigUndefined:
		fallthrough
	default:
		return "undefined"
	}
}

func (pc *ProxyConfigType) FromString(s string) error {
	switch strings.ToLower(s) {
	case "manual":
		*pc = ProxyConfigManual
	case "transparent":
		*pc = ProxyConfigTransparent
	case "autodiscovery":
		*pc = ProxyConfigAutoDiscovery
	case "wpad-url":
		*pc = ProxyConfigWPADURL
	case "pac-script":
		*pc = ProxyConfigPACScript
	case "", "undefined":
		*pc = ProxyConfigUndefined
	default:
		return fmt.Errorf("invalid PROXY_CONFIG_TYPE: %q", s)
	}
	return nil
}

const proxyConfigTypeParamKey = "PROXY_CONFIG_TYPE"

var (
	proxyConfigTypeParam = evetest.TestParameterDefinition{
		Key:          proxyConfigTypeParamKey,
		DefaultValue: ProxyConfigManual,
		Description: evetest.TestParameterDescription{
			Summary:       "HTTP proxy configuration type to deploy for the test",
			Default:       "manual",
			AllowedValues: "manual|transparent|wpad",
		},
	}
)

// TestBootstrapWithProxy verifies that an EVE device which can only reach
// the controller via an HTTP/HTTPS proxy can onboard when the proxy
// configuration is supplied at install time (either as bootstrap config or
// as override.json). Three proxy modes are exercised: a manually-configured
// explicit proxy, a transparent proxy (no client-side proxy URL, only the
// proxy CA cert), and an auto-discovered explicit proxy (WPAD).
//
// See DEVICE-CONNECTIVITY.md "Network Proxies".
//
// Test parameters
// ---------------
//   - USE_OVERRIDE_JSON (bool, default false): bootstrap config vs.
//     override.json injection path (same semantics as in
//     TestBootstrapWithStaticIP).
//   - PROXY_CONFIG_TYPE (enum, default "manual"): "manual" |
//     "transparent" | "autodiscovery". Other enum values are reserved for
//     future expansion and currently cause Skipf.
//
// Network model
// -------------
//   - PROXY_CONFIG_TYPE=manual:        netmodels.SingleEthWithDHCPAndExplicitProxy
//     -- SDN drops direct controller traffic; only proxy-mediated requests
//     succeed.
//   - PROXY_CONFIG_TYPE=transparent:   netmodels.SingleEthWithDHCPAndTransparentProxy
//     -- the SDN network has a transparent MITM proxy on the path; EVE
//     does not configure a proxy URL, only trusts the proxy CA.
//   - PROXY_CONFIG_TYPE=autodiscovery: netmodels.SingleEthWithDHCPAndAutoDiscoveredProxy
//     -- SDN has both an explicit proxy and a WPAD server; EVE discovers
//     the proxy URL via DHCP/DNS + PAC.
//
// Device configuration
// --------------------
//   - DeviceReusePolicy=CreateFromScratchWithLiveImage.
//   - Injected config (bootstrap or override.json) wires up eth0 (mgmt+app,
//     DHCP) with the matching ProxyConfig variant
//     (ManualProxyConfig / TransparentProxyConfig / ProxyAutoDiscoveryConfig).
//     ProxyCertsPEM always includes the SDN-side proxy CA (netmodels.ProxyCACertPEM)
//     so EVE trusts the MITM cert chain when applicable.
//   - The override.json variant builds the equivalent
//     pillartypes.ProxyConfig (with Exceptions="github.com" in the manual
//     case -- a known blocked target that demonstrates non-empty
//     exceptions handling).
//   - After onboarding, push the same config through the controller.
//
// Assertions
// ----------
//   - evetest.Setup completing means EVE reached Adam via the configured
//     proxy path (direct controller traffic is blocked or rewritten by the
//     SDN, so without proxy support the onboarding would fail).
//   - WatchDeviceInfo until SystemAdapterInfo.CurrentIndex=0 with exactly
//     one DPC entry "zedagent" -- bootstrap / override DPCs must not
//     remain persisted.
//
// Hypervisor
// ----------
//   - Hardcoded HypervisorKVM (Bootstrap-suite test).
func TestBootstrapWithProxy(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		useOverrideJSONParam,
		proxyConfigTypeParam,
	)

	// Get parameter values set for this test execution.
	useOverrideJSON := evetest.GetTestParameter[bool](useOverrideJSONParamKey)
	proxyConfigType := evetest.GetTestParameter[ProxyConfigType](proxyConfigTypeParamKey)

	// Build bootstrap configuration.
	devName := "edge-dev"
	bootstrapConfig := evetest.NewEdgeDeviceConfig(devName)
	var proxyConfig evetest.ProxyConfig
	switch proxyConfigType {
	case ProxyConfigManual:
		proxyConfig = evetest.ManualProxyConfig{
			Proxies: []evetest.ProxyServer{
				{
					Proto:   evecommon.ProxyProto_PROXY_HTTP,
					Address: "http://http-proxy.test",
					Port:    9090,
				},
				{
					Proto:   evecommon.ProxyProto_PROXY_HTTPS,
					Address: "http://http-proxy.test",
					Port:    9091,
				},
			},
			ProxyCertsPEM: []string{netmodels.ProxyCACertPEM},
		}
	case ProxyConfigTransparent:
		proxyConfig = evetest.TransparentProxyConfig{
			ProxyCertsPEM: []string{netmodels.ProxyCACertPEM},
		}
	case ProxyConfigAutoDiscovery:
		proxyConfig = evetest.ProxyAutoDiscoveryConfig{
			ProxyCertsPEM: []string{netmodels.ProxyCACertPEM},
		}
	default:
		evetestT.Skipf("PROXY_CONFIG_TYPE %s is not (yet) covered by the test",
			proxyConfigType)
	}
	dhcpNetWithProxy := bootstrapConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4,
			ProxyConfig: proxyConfig,
		})
	bootstrapConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "eth0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNetWithProxy,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})

	// Set up the test harness and specify test prerequisites.
	requiredDevice := deviceRequirementsForBootstrap(devName)
	if useOverrideJSON {
		var proxyConfig pillartypes.ProxyConfig
		switch proxyConfigType {
		case ProxyConfigManual:
			proxyConfig = pillartypes.ProxyConfig{
				Proxies: []pillartypes.ProxyEntry{
					{
						Type:   pillartypes.NetworkProxyTypeHTTP,
						Server: "http://http-proxy.test",
						Port:   9090,
					},
					{
						Type:   pillartypes.NetworkProxyTypeHTTPS,
						Server: "http://http-proxy.test",
						Port:   9091,
					},
				},
				Exceptions: "github.com", // this is blocked by the proxy
				ProxyCertPEM: [][]byte{
					[]byte(netmodels.ProxyCACertPEM),
				},
			}
		case ProxyConfigTransparent:
			proxyConfig = pillartypes.ProxyConfig{
				ProxyCertPEM: [][]byte{
					[]byte(netmodels.ProxyCACertPEM),
				},
			}
		case ProxyConfigAutoDiscovery:
			proxyConfig = pillartypes.ProxyConfig{
				NetworkProxyEnable: true,
				ProxyCertPEM: [][]byte{
					[]byte(netmodels.ProxyCACertPEM),
				},
			}
		default:
			evetestT.Skipf("PROXY_CONFIG_TYPE %s is not (yet) covered by the test",
				proxyConfigType)
		}
		requiredDevice.WithInjectedNetworkOverride = &pillartypes.DevicePortConfig{
			Version:      1,
			Key:          "",
			TimePriority: time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
			Ports: []pillartypes.NetworkPortConfig{
				{
					IfName: "eth0",
					IsMgmt: true,
					DhcpConfig: pillartypes.DhcpConfig{
						Dhcp: pillartypes.DhcpTypeClient,
						Type: pillartypes.NetworkTypeIPv4,
					},
					ProxyConfig: proxyConfig,
				},
			},
		}
	} else {
		requiredDevice.WithInjectedBootstrapConfig = bootstrapConfig
	}
	var requiredNetModel evetest.RequireNetworkModel
	switch proxyConfigType {
	case ProxyConfigManual:
		requiredNetModel = evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCPAndExplicitProxy,
		}
	case ProxyConfigTransparent:
		requiredNetModel = evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCPAndTransparentProxy,
		}
	case ProxyConfigAutoDiscovery:
		requiredNetModel = evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCPAndAutoDiscoveredProxy,
		}
	default:
		evetestT.Skipf("PROXY_CONFIG_TYPE %s is not (yet) covered by the test",
			proxyConfigType)
	}
	evetest.Setup(requiredDevice, requiredNetModel)

	// If we got here, device was able to bootstrap controller connectivity using
	// the bootstrap config or override.json.
	device := evetest.GetEdgeDevice(devName)
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	evetest.Checkpoint("setup-done")

	// Apply the same bootstrap configuration also through the controller.
	device.ApplyConfig(bootstrapConfig, true, true)
	evetest.Checkpoint("config-applied")

	// Neither bootstrap config nor override.json remain persisted after
	// the controller connectivity was established.
	timeout := 3 * time.Minute
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Device has applied and reported expected network configuration",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			return matchSystemAdapterInfo(dinfo.GetSystemAdapter(), 0, []string{"zedagent"})
		})))
}

// TestBootstrapWithMgmtVLAN verifies that an EVE device whose management
// traffic must traverse a tagged VLAN can onboard when the VLAN
// sub-interface is supplied at install time (via bootstrap config or
// override.json). The SDN network exposes two VLANs (100 for mgmt, 200 for
// apps) on a single physical port; without a VLAN sub-interface
// configured up-front, EVE has no path to the controller and cannot
// reach Adam.
//
// See DEVICE-CONNECTIVITY.md "L2 network adapters" and APP-CONNECTIVITY.md
// "VLAN-aware Switch Network Instance" for the underlying mechanism.
//
// Test parameters
// ---------------
//   - USE_OVERRIDE_JSON (bool, default false): bootstrap config vs.
//     override.json injection path.
//
// Network model
// -------------
//   - netmodels.SingleEthWithMgmtAndAppVLANs -- a single SDN port carrying
//     two tagged VLANs (mgmt VLAN 100, app VLAN 200) with their own
//     per-VLAN DHCP servers and routers. Controller is reachable only
//     through VLAN 100.
//
// Device configuration
// --------------------
//   - DeviceReusePolicy=CreateFromScratchWithLiveImage.
//   - Injected config:
//   - PhysicalIO eth0 (no SystemAdapter on the parent port -- it stays
//     L2-only).
//   - VLANSubinterfaceConfig "mgmt-vlan" (interface "vlan100",
//     ParentLogicalLabel="ethernet0", VlanID=100, mgmt+app usage,
//     DHCP on the resulting sub-interface).
//   - For the override.json variant, the equivalent is built with two
//     pillartypes.NetworkPortConfig entries: a non-mgmt L2-only parent
//     port and an L3 mgmt VLAN port with L2LinkConfig.VLAN.ParentPort
//     and VLAN.ID=100.
//   - After onboarding, push the same config through the controller.
//
// Assertions
// ----------
//   - evetest.Setup succeeding proves the device onboarded via vlan100.
//   - WatchDeviceInfo until SystemAdapterInfo.CurrentIndex=0 with exactly
//     one DPC entry "zedagent" (bootstrap / override pruned).
//
// Hypervisor
// ----------
//   - Hardcoded HypervisorKVM (Bootstrap-suite test).
func TestBootstrapWithMgmtVLAN(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		useOverrideJSONParam,
	)

	// Get parameter values set for this test execution.
	useOverrideJSON := evetest.GetTestParameter[bool](useOverrideJSONParamKey)

	// Build bootstrap configuration.
	devName := "edge-dev"
	bootstrapConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := bootstrapConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4,
		})
	bootstrapConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
		})
	bootstrapConfig.AddVLANSubinterface(
		evetest.VLANSubinterfaceConfig{
			LogicalLabel:       "mgmt-vlan",
			InterfaceName:      "vlan100",
			ParentLogicalLabel: "ethernet0",
			VlanID:             100,
			NetworkUUID:        dhcpNet,
			Usage:              evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})

	// Set up the test harness and specify test prerequisites.
	requiredDevice := deviceRequirementsForBootstrap(devName)
	if useOverrideJSON {
		requiredDevice.WithInjectedNetworkOverride = &pillartypes.DevicePortConfig{
			Version:      1,
			Key:          "",
			TimePriority: time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
			Ports: []pillartypes.NetworkPortConfig{
				{
					IfName:       "eth0",
					Logicallabel: "ethernet0",
					IsMgmt:       false,
					IsL3Port:     false,
				},
				{
					IfName:       "vlan100",
					Logicallabel: "mgmt-vlan",
					IsMgmt:       true,
					IsL3Port:     true,
					DhcpConfig: pillartypes.DhcpConfig{
						Dhcp: pillartypes.DhcpTypeClient,
						Type: pillartypes.NetworkTypeIPv4,
					},
					L2LinkConfig: pillartypes.L2LinkConfig{
						L2Type: pillartypes.L2LinkTypeVLAN,
						VLAN: pillartypes.VLANConfig{
							ParentPort: "ethernet0",
							ID:         100,
						},
					},
				},
			},
		}
	} else {
		requiredDevice.WithInjectedBootstrapConfig = bootstrapConfig
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithMgmtAndAppVLANs,
	}
	evetest.Setup(requiredDevice, requiredNetModel)

	// If we got here, device was able to bootstrap controller connectivity using
	// the bootstrap config or override.json.
	device := evetest.GetEdgeDevice(devName)
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	evetest.Checkpoint("setup-done")

	// Apply the same bootstrap configuration also through the controller.
	device.ApplyConfig(bootstrapConfig, true, true)
	evetest.Checkpoint("config-applied")

	// Neither bootstrap config nor override.json remain persisted after
	// the controller connectivity was established.
	timeout := 3 * time.Minute
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Device has applied and reported expected network configuration",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			return matchSystemAdapterInfo(dinfo.GetSystemAdapter(), 0, []string{"zedagent"})
		})))
}

// TestBootstrapWithLACPBond verifies that an EVE device whose management
// uplink is an LACP (802.3ad) bond can onboard when the bond is supplied
// at install time. This is the bootstrap-side analog of TestLACPBond: the
// SDN side runs an LACP partner from the start, so individual ports
// cannot pass traffic until LACP negotiation completes on EVE -- the
// bond must therefore exist before EVE first reaches for the controller.
// Without bootstrap, EVE would have no way to establish initial
// connectivity (chicken-and-egg with the SDN LACP peer); TestLACPBond
// avoids the problem by starting with individual ports and switching to
// LACP afterwards.
//
// Test parameters
// ---------------
//   - USE_OVERRIDE_JSON (bool, default false): bootstrap config vs.
//     override.json injection path.
//
// Network model
// -------------
//   - netmodels.TwoMgmtPortsWithLACPBond -- eth0 + eth1 aggregated on the
//     SDN side by a 802.3ad bond. Individual port traffic is dropped until
//     LACP completes.
//
// Device configuration
// --------------------
//   - DeviceReusePolicy=CreateFromScratchWithLiveImage.
//   - Injected config:
//   - PhysicalIO eth0 + eth1 (no SystemAdapter on the parent ports).
//   - BondConfig "lacp-bond" (interface "bond1") aggregating
//     ethernet0+ethernet1 in BOND_MODE_802_3AD, LACPRate=FAST,
//     MIIMonitor interval 100 ms. The bond gets the mgmt+app DHCP
//     NetworkConfig.
//   - For the override.json variant, the equivalent is built via three
//     pillartypes.NetworkPortConfig entries (two L2-only members + one
//     L3 mgmt bond port whose L2LinkConfig.Bond aggregates them).
//   - After onboarding, push the same config through the controller.
//
// Assertions
// ----------
//   - evetest.Setup succeeding proves LACP negotiated successfully at boot
//     and the device onboarded via the bond.
//   - WatchDeviceInfo until SystemAdapterInfo.CurrentIndex=0 with exactly
//     one DPC entry "zedagent".
//
// Hypervisor
// ----------
//   - Hardcoded HypervisorKVM (Bootstrap-suite test).
func TestBootstrapWithLACPBond(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		useOverrideJSONParam,
	)

	// Get parameter values set for this test execution.
	useOverrideJSON := evetest.GetTestParameter[bool](useOverrideJSONParamKey)

	// Build bootstrap configuration with an LACP bond.
	// With bootstrap config, EVE creates the bond at boot time, before
	// attempting to reach the controller. This avoids the chicken-and-egg
	// problem where individual ports cannot pass traffic through an SDN-side
	// LACP bond without LACP negotiation.
	devName := "edge-dev"
	bootstrapConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := bootstrapConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4,
		})
	bootstrapConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	bootstrapConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet1",
			PhysicalLabel: "eth1",
			InterfaceName: "eth1",
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	bootstrapConfig.AddBond(
		evetest.BondConfig{
			LogicalLabel:  "lacp-bond",
			InterfaceName: "bond1",
			MemberLabels:  []string{"ethernet0", "ethernet1"},
			BondMode:      evecommon.BondMode_BOND_MODE_802_3AD,
			LACPRate:      evecommon.LacpRate_LACP_RATE_FAST,
			MIIMonitor: &eveconfig.MIIMonitor{
				Interval: 100,
			},
			NetworkUUID: dhcpNet,
			Usage:       evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})

	// Set up the test harness and specify test prerequisites.
	requiredDevice := deviceRequirementsForBootstrap(devName)
	if useOverrideJSON {
		requiredDevice.WithInjectedNetworkOverride = &pillartypes.DevicePortConfig{
			Version:      1,
			Key:          "",
			TimePriority: time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
			Ports: []pillartypes.NetworkPortConfig{
				{
					IfName:       "eth0",
					Logicallabel: "ethernet0",
					IsMgmt:       false,
					IsL3Port:     false,
				},
				{
					IfName:       "eth1",
					Logicallabel: "ethernet1",
					IsMgmt:       false,
					IsL3Port:     false,
				},
				{
					IfName:       "bond1",
					Logicallabel: "lacp-bond",
					IsMgmt:       true,
					IsL3Port:     true,
					DhcpConfig: pillartypes.DhcpConfig{
						Dhcp: pillartypes.DhcpTypeClient,
						Type: pillartypes.NetworkTypeIPv4,
					},
					L2LinkConfig: pillartypes.L2LinkConfig{
						L2Type: pillartypes.L2LinkTypeBond,
						Bond: pillartypes.BondConfig{
							AggregatedPorts: []string{"ethernet0", "ethernet1"},
							Mode:            pillartypes.BondMode802Dot3AD,
							LacpRate:        pillartypes.LacpRateFast,
							MIIMonitor: pillartypes.BondMIIMonitor{
								Enabled:  true,
								Interval: 100,
							},
						},
					},
				},
			},
		}
	} else {
		requiredDevice.WithInjectedBootstrapConfig = bootstrapConfig
	}

	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.TwoMgmtPortsWithLACPBond,
	}
	evetest.Setup(requiredDevice, requiredNetModel)

	// If we got here, device was able to bootstrap controller connectivity using
	// the bootstrap config or override.json.
	device := evetest.GetEdgeDevice(devName)
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	evetest.Checkpoint("setup-done")

	// Apply the same bootstrap configuration also through the controller.
	device.ApplyConfig(bootstrapConfig, true, true)
	evetest.Checkpoint("config-applied")

	// Neither bootstrap config nor override.json remain persisted after
	// the controller connectivity was established.
	timeout := 3 * time.Minute
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Device has applied and reported expected network configuration",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			return matchSystemAdapterInfo(dinfo.GetSystemAdapter(), 0, []string{"zedagent"})
		})))
}

// matchSystemAdapterInfo checks that the SystemAdapterInfo has the expected
// currentIndex and that the DevicePortStatus entries match the expected keys
// (in order).
func matchSystemAdapterInfo(sa *eveinfo.SystemAdapterInfo,
	expectedIndex uint32, expectedKeys []string) bool {
	if sa == nil {
		return false
	}
	if sa.GetCurrentIndex() != expectedIndex {
		return false
	}
	status := sa.GetStatus()
	if len(status) != len(expectedKeys) {
		return false
	}
	for i, key := range expectedKeys {
		if status[i].GetKey() != key {
			return false
		}
	}
	return true
}
