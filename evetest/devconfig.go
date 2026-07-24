// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	evecerts "github.com/lf-edge/eve-api/go/certs"
	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/utils"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	_ = iota
	// KiB is the number of bytes in a kibibyte.
	KiB uint64 = 1 << (10 * iota)
	// MiB is the number of bytes in a mebibyte.
	MiB
	// GiB is the number of bytes in a gibibyte.
	GiB
	// TiB is the number of bytes in a tebibyte.
	TiB
)

// NilUUID is special form of UUID that is specified to have all
// 128 bits set to zero.
var NilUUID = uuid.UUID{}

// EdgeDeviceConfig allows to build EdgeDevConfig.
// It provides some helper functions, but it is also possible to access
// the EdgeDevConfig directly (to maybe create and test invalid device config).
type EdgeDeviceConfig struct {
	*eveconfig.EdgeDevConfig
	th  *TestHarness
	log *logrus.Entry
}

func (th *TestHarness) newUUID(label string) uuid.UUID {
	id, err := uuid.NewV4()
	if err != nil {
		th.t.Fatalf("Failed to generate UUID for %s: %v", label, err)
	}
	return id
}

// NewEdgeDeviceConfig constructs an EdgeDeviceConfig.
// When creating a configuration prior to Setup (e.g. for bootstrap),
// do not include secrets that require encryption in a CipherBlock
// (such as datastore credentials or application cloud-init metadata).
// These values must be added only after evetest.Setup completes and the
// device is onboarded, when cryptographic material for object-level
// encryption becomes available.
func NewEdgeDeviceConfig(devName string) *EdgeDeviceConfig {
	return &EdgeDeviceConfig{
		EdgeDevConfig: &eveconfig.EdgeDevConfig{DeviceName: devName},
		th:            getTestHarness(),
		log:           getTestHarness().log.WithField("component", "device-config"),
	}
}

// NetworkConfig defines a generic interface for converting a network config
// into its corresponding EVE protobuf representation.
type NetworkConfig interface {
	toProto(th *TestHarness, devName string, networkUUID uuid.UUID) *eveconfig.NetworkConfig
}

// NoIPNetworkConfig represents configuration for an Ethernet interface
// without assigning an IP address (no static IP and no DHCP client).
// It is typically used for L2-only setups (e.g., bridge members) or for
// cluster networks, where IP addresses are assigned from the cluster configuration.
type NoIPNetworkConfig struct {
	MTU uint16
}

func (config NoIPNetworkConfig) toProto(th *TestHarness, devName string,
	networkUUID uuid.UUID) *eveconfig.NetworkConfig {
	return &eveconfig.NetworkConfig{
		Id: networkUUID.String(),
		Ip: &evecommon.Ipspec{
			Dhcp: evecommon.DHCPType_DHCPNone,
		},
		Mtu: uint32(config.MTU),
	}
}

// DHCPNetworkConfig represents a network configuration for Ethernet interface,
// with DHCP used for IP assignment.
type DHCPNetworkConfig struct {
	NetworkType       evecommon.NetworkType
	MTU               uint16
	NTPServers        []string
	IgnoreNTPFromDHCP bool
	// DNSServers are static DNS server IPs to configure in addition to (or
	// instead of) the DHCP-provided DNS servers. When IgnoreDNSFromDHCP is
	// false (the default), these are appended to the DHCP-provided servers.
	// When IgnoreDNSFromDHCP is true, only these are used.
	DNSServers []net.IP
	// IgnoreDNSFromDHCP controls whether DHCP-provided DNS servers are ignored.
	// When true, only the statically configured DNSServers are used.
	// Corresponds to DhcpOptionsIgnore.DnsConfigExclusively in the EVE API.
	IgnoreDNSFromDHCP bool
	ProxyConfig       ProxyConfig
}

func (config DHCPNetworkConfig) toProto(th *TestHarness, devName string,
	networkUUID uuid.UUID) *eveconfig.NetworkConfig {
	netConfigProto := &eveconfig.NetworkConfig{
		Id:   networkUUID.String(),
		Type: config.NetworkType,
		Ip: &evecommon.Ipspec{
			Dhcp: evecommon.DHCPType_Client,
		},
		Mtu: uint32(config.MTU),
	}
	for i, ntpServer := range config.NTPServers {
		if i == 0 {
			netConfigProto.Ip.Ntp = ntpServer
		} else {
			netConfigProto.Ip.MoreNtp = append(netConfigProto.Ip.MoreNtp, ntpServer)
		}
	}
	for _, dnsServer := range config.DNSServers {
		netConfigProto.Ip.Dns = append(netConfigProto.Ip.Dns, dnsServer.String())
	}
	if config.IgnoreNTPFromDHCP || config.IgnoreDNSFromDHCP {
		netConfigProto.Ip.DhcpOptionsIgnore = &evecommon.DhcpOptionsIgnore{
			NtpServerExclusively: config.IgnoreNTPFromDHCP,
			DnsConfigExclusively: config.IgnoreDNSFromDHCP,
		}
	}
	if config.ProxyConfig != nil {
		netConfigProto.EntProxy = config.ProxyConfig.toProto(th)
	}
	return netConfigProto
}

// StaticNetworkConfig represents a statically assigned IP configuration to an Ethernet
// interface.
type StaticNetworkConfig struct {
	NetworkType evecommon.NetworkType
	MTU         uint16
	Subnet      *net.IPNet
	Gateway     net.IP
	Domain      string
	NTPServers  []string
	DNSServers  []net.IP
	ProxyConfig ProxyConfig
}

func (config StaticNetworkConfig) toProto(th *TestHarness, devName string,
	networkUUID uuid.UUID) *eveconfig.NetworkConfig {
	netConfigProto := &eveconfig.NetworkConfig{
		Id:   networkUUID.String(),
		Type: config.NetworkType,
		Ip: &evecommon.Ipspec{
			Dhcp:    evecommon.DHCPType_Static,
			Subnet:  config.Subnet.String(),
			Gateway: config.Gateway.String(),
			Domain:  config.Domain,
		},
		Mtu: uint32(config.MTU),
	}
	for i, ntpServer := range config.NTPServers {
		if i == 0 {
			netConfigProto.Ip.Ntp = ntpServer
		} else {
			netConfigProto.Ip.MoreNtp = append(netConfigProto.Ip.MoreNtp, ntpServer)
		}
	}
	for _, dnsServer := range config.DNSServers {
		netConfigProto.Ip.Dns = append(netConfigProto.Ip.Dns, dnsServer.String())
	}
	if config.ProxyConfig != nil {
		netConfigProto.EntProxy = config.ProxyConfig.toProto(th)
	}
	return netConfigProto
}

// WiFiNetworkConfig represents a Wi-Fi configuration.
type WiFiNetworkConfig struct {
	// WiFi with static IP config is rather uncommon
	DHCPNetworkConfig
	SSID      string
	KeyScheme evecommon.WiFiKeyScheme
	Identity  string
	// The password must be supplied in pre-hashed form, as generated by `wpa_passphrase`.
	// (`PBKDF2-HMAC-SHA1` hash derived from the plaintext password and the SSID).
	Password string
	Priority int32
}

func (config WiFiNetworkConfig) toProto(th *TestHarness, devName string,
	networkUUID uuid.UUID) *eveconfig.NetworkConfig {
	netConfigProto := config.DHCPNetworkConfig.toProto(th, devName, networkUUID)
	var (
		cipherData        *evecommon.CipherBlock
		plainTextIdentity string
		plainTextPassword string
	)
	if config.Identity != "" {
		if th.isDeviceOnboarded(devName) {
			var err error
			cipherData, err = th.encryptCipherData(devName,
				&evecommon.EncryptionBlock{
					WifiUserName: config.Identity,
					WifiPassword: config.Password,
				})
			if err != nil {
				th.t.Fatalf("Failed to encrypt WiFi credentials for network %v: %v",
					networkUUID, err)
			}
		} else {
			// This is bootstrap configuration.
			// We do not yet have cryptographic material for object-level encryption.
			// Store identity and password in plaintext.
			plainTextIdentity = config.Identity
			plainTextPassword = config.Password
		}
	}
	netConfigProto.Wireless = &eveconfig.WirelessConfig{
		Type: evecommon.WirelessType_WiFi,
		WifiCfg: []*eveconfig.WifiConfig{
			{
				WifiSSID:   config.SSID,
				KeyScheme:  config.KeyScheme,
				Identity:   plainTextIdentity,
				Password:   plainTextPassword,
				Priority:   config.Priority,
				CipherData: cipherData,
			},
		},
	}
	return netConfigProto
}

// CellularNetworkConfig represents a cellular network configuration.
type CellularNetworkConfig struct {
	// "DHCP" is not quite accurate here since most of the time we get IP configuration
	// from the cellular network via PDP context activation, not traditional DHCP.
	// But other than that, all the configuration parameters are the same, so we reuse
	// DHCPNetworkConfig
	DHCPNetworkConfig
	// SIM card slot to which this configuration applies.
	// 0 - unspecified (apply to currently activated or the only available)
	// 1 - config for SIM card in the first slot
	// 2 - config for SIM card in the second slot
	// etc.
	SIMSlot uint8
	// Access Point Network for the default bearer.
	APN string
	// The IP addressing type to use for the default bearer.
	IPType evecommon.CellularIPType
	// Authentication protocol used for the default bearer.
	AuthProtocol evecommon.CellularAuthProtocol
	// User credentials for the default bearer (when required).
	UserCredentials UsernamePasswordAuth
	// The set of cellular network operators that modem should preferably try to register
	// and connect into.
	// Network operator should be referenced by PLMN (Public Land Mobile Network) code.
	PreferredPLMNs []string
	// The list of preferred Radio Access Technologies (RATs) to use for connecting
	// to the network.
	PreferredRATs []evecommon.RadioAccessTechnology
	// If true, then modem will avoid connecting to networks with roaming.
	ForbidRoaming bool
	// Access Point Network for the attach (aka initial) bearer.
	AttachAPN string
	// The IP addressing type to use for the attach bearer.
	AttachIPType evecommon.CellularIPType
	// Authentication protocol used for the attach bearer.
	AttachAuthProtocol evecommon.CellularAuthProtocol
	// User credentials for the attach bearer (when required).
	AttachUserCredentials UsernamePasswordAuth
	// Enable probing to detect broken connection.
	EnableProbing bool
	// User-defined connectivity probing method.
	UserDefinedProbe pillartypes.ConnectivityProbe
	// Some LTE modems have GNSS receiver integrated and can be used
	// for device location tracking.
	// Enable this option to have location info periodically obtained
	// from this modem and published by wwan microservice via topic WwanLocationInfo.
	LocationTracking bool
}

func (config CellularNetworkConfig) toProto(th *TestHarness, devName string,
	networkUUID uuid.UUID) *eveconfig.NetworkConfig {
	netConfigProto := config.DHCPNetworkConfig.toProto(th, devName, networkUUID)
	probe := &eveconfig.CellularConnectivityProbe{
		Disable: !config.EnableProbing,
	}
	switch config.UserDefinedProbe.Method {
	case pillartypes.ConnectivityProbeMethodICMP:
		probe.CustomProbe = &evecommon.ConnectivityProbe{
			ProbeMethod: evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_ICMP,
			ProbeEndpoint: &evecommon.ProbeEndpoint{
				Host: config.UserDefinedProbe.ProbeHost,
			},
		}
	case pillartypes.ConnectivityProbeMethodTCP:
		probe.CustomProbe = &evecommon.ConnectivityProbe{
			ProbeMethod: evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_TCP,
			ProbeEndpoint: &evecommon.ProbeEndpoint{
				Host: config.UserDefinedProbe.ProbeHost,
				Port: uint32(config.UserDefinedProbe.ProbePort),
			},
		}
	}
	var cipherData *evecommon.CipherBlock
	if config.UserCredentials.Username != "" || config.AttachUserCredentials.Username != "" {
		var err error
		cipherData, err = th.encryptCipherData(devName,
			&evecommon.EncryptionBlock{
				CellularNetUsername:       config.UserCredentials.Username,
				CellularNetPassword:       config.UserCredentials.Password,
				CellularNetAttachUsername: config.AttachUserCredentials.Username,
				CellularNetAttachPassword: config.AttachUserCredentials.Password,
			})
		if err != nil {
			th.t.Fatalf("Failed to encrypt cellular credentials for network %v: %v",
				networkUUID, err)
		}
	}
	netConfigProto.Wireless = &eveconfig.WirelessConfig{
		Type: evecommon.WirelessType_Cellular,
		CellularCfg: []*eveconfig.CellularConfig{
			{
				ActivatedSimSlot: uint32(config.SIMSlot),
				AccessPoints: []*eveconfig.CellularAccessPoint{
					{
						SimSlot:            uint32(config.SIMSlot),
						Apn:                config.APN,
						AuthProtocol:       config.AuthProtocol,
						CipherData:         cipherData,
						PreferredPlmns:     config.PreferredPLMNs,
						ForbidRoaming:      config.ForbidRoaming,
						PreferredRats:      config.PreferredRATs,
						IpType:             config.IPType,
						AttachApn:          config.AttachAPN,
						AttachIpType:       config.AttachIPType,
						AttachAuthProtocol: config.AttachAuthProtocol,
					},
				},
				Probe:            probe,
				LocationTracking: config.LocationTracking,
			},
		},
	}
	return netConfigProto
}

// ProxyConfig defines a generic interface for proxy configuration types
// that can be converted into EVE protobuf representation.
type ProxyConfig interface {
	toProto(th *TestHarness) *evecommon.ProxyConfig
}

// ManualProxyConfig represents a manually specified proxy configuration.
type ManualProxyConfig struct {
	Proxies       []ProxyServer
	ProxyCertsPEM []string
	Exceptions    []string // IP address or hostname or wildcard domain (e.g. *.local)
}

// ProxyServer defines a single proxy server with protocol, address, and port.
type ProxyServer struct {
	Proto   evecommon.ProxyProto
	Address string // IP or hostname
	Port    uint16
}

func (config ManualProxyConfig) toProto(th *TestHarness) *evecommon.ProxyConfig {
	proxyConfigProto := &evecommon.ProxyConfig{
		Exceptions: strings.Join(config.Exceptions, ","),
	}
	for _, proxy := range config.Proxies {
		proxyConfigProto.Proxies = append(proxyConfigProto.Proxies,
			&evecommon.ProxyServer{
				Proto:  proxy.Proto,
				Server: proxy.Address,
				Port:   uint32(proxy.Port),
			})
	}
	for _, cert := range config.ProxyCertsPEM {
		proxyConfigProto.ProxyCertPEM = append(proxyConfigProto.ProxyCertPEM,
			[]byte(cert))
	}
	return proxyConfigProto
}

// TransparentProxyConfig represents configuration for transparent proxying.
type TransparentProxyConfig struct {
	ProxyCertsPEM []string
}

func (config TransparentProxyConfig) toProto(th *TestHarness) *evecommon.ProxyConfig {
	proxyConfigProto := &evecommon.ProxyConfig{}
	for _, cert := range config.ProxyCertsPEM {
		proxyConfigProto.ProxyCertPEM = append(proxyConfigProto.ProxyCertPEM,
			[]byte(cert))
	}
	return proxyConfigProto
}

// ProxyAutoDiscoveryConfig represents a proxy configuration that enables
// automatic discovery of network proxy settings using WPAD & PAC.
type ProxyAutoDiscoveryConfig struct {
	ProxyCertsPEM []string
}

func (config ProxyAutoDiscoveryConfig) toProto(th *TestHarness) *evecommon.ProxyConfig {
	proxyConfigProto := &evecommon.ProxyConfig{
		NetworkProxyEnable: true,
	}
	for _, cert := range config.ProxyCertsPEM {
		proxyConfigProto.ProxyCertPEM = append(proxyConfigProto.ProxyCertPEM,
			[]byte(cert))
	}
	return proxyConfigProto
}

// NetworkAdapterConfig represents configuration for NIC (ethernet or wireless)
type NetworkAdapterConfig struct {
	LogicalLabel  string
	PhysicalLabel string
	InterfaceName string
	PCIAddress    string
	USBAddress    string
	WirelessType  evecommon.WirelessType
	Usage         evecommon.PhyIoMemberUsage
	PNAC          PNAC

	// AssignmentGroup overrides the PhysicalIO assignment group. Defaults to
	// LogicalLabel when empty.
	AssignmentGroup string
	// ParentAssignmentGroup sets the parent assignment group (empty if none).
	ParentAssignmentGroup string

	// AllowLocalModifications enables the Local Profile Server (LPS) to modify
	// the network configuration of this adapter.
	AllowLocalModifications bool

	// Parameters below should be left empty if:
	//   - Usage is PhyIoUsageDedicated or PhyIoUsageDisabled, or
	//   - the (ethernet) adapter is used in VLANs-only mode
	//   - the (ethernet) adapter is a member of a bond
	Cost         uint8
	NetworkUUID  uuid.UUID
	StaticIP     net.IP // use only in combination with StaticNetworkConfig
	SharedLabels []string
}

// PNAC : configuration for Port-based Network Access Control.
type PNAC struct {
	Enable      bool
	EAPIdentity string
	EAPMethod   eveconfig.EAPMethod
	// Name of the certificate enrollment profile used for authentication
	// (for example, a SCEP profile). Applicable only if the selected EAP
	// method requires a client certificate (e.g., EAP-TLS).
	CertEnrollmentProfileName string
}

// toPhysicalIOProto returns EVE protobuf PhysicalIO for this adapter.
func (config NetworkAdapterConfig) toPhysicalIOProto() *eveconfig.PhysicalIO {
	physAddrs := map[string]string{}
	if config.InterfaceName != "" {
		physAddrs["ifname"] = config.InterfaceName
	}
	if config.PCIAddress != "" {
		physAddrs["pcilong"] = config.PCIAddress
	}
	if config.USBAddress != "" {
		physAddrs["usbaddr"] = config.USBAddress
	}
	var phyIoType evecommon.PhyIoType
	switch config.WirelessType {
	case evecommon.WirelessType_WiFi:
		phyIoType = evecommon.PhyIoType_PhyIoNetWLAN
	case evecommon.WirelessType_Cellular:
		phyIoType = evecommon.PhyIoType_PhyIoNetWWAN
	default:
		phyIoType = evecommon.PhyIoType_PhyIoNetEth
	}
	assigngrp := config.AssignmentGroup
	if assigngrp == "" {
		assigngrp = config.LogicalLabel
	}
	return &eveconfig.PhysicalIO{
		Ptype:           phyIoType,
		Logicallabel:    config.LogicalLabel,
		Assigngrp:       assigngrp,
		Parentassigngrp: config.ParentAssignmentGroup,
		Phylabel:        config.PhysicalLabel,
		Phyaddrs:        physAddrs,
		Usage:           config.Usage,
	}
}

// PhysicalIOConfig represents a raw PhysicalIO (assignable I/O) device in the
// device model. Use it for non-network devices and for deliberately
// inconsistent device models that AddNetworkAdapter cannot express (a specific
// Ptype, a phantom device at a chosen PCI address, a custom assignment group,
// etc.). A given logical label is owned by exactly one of AddNetworkAdapter or
// AddPhysicalIO.
type PhysicalIOConfig struct {
	LogicalLabel  string
	PhysicalLabel string
	Type          evecommon.PhyIoType
	// AssignmentGroup defaults to LogicalLabel when empty.
	AssignmentGroup       string
	ParentAssignmentGroup string
	Usage                 evecommon.PhyIoMemberUsage
	// Physical addresses; every non-empty field is written into Phyaddrs.
	PCIAddress    string
	USBAddress    string
	InterfaceName string
	Serial        string
}

// toPhysicalIOProto returns the EVE protobuf PhysicalIO for this device.
func (config PhysicalIOConfig) toPhysicalIOProto() *eveconfig.PhysicalIO {
	physAddrs := map[string]string{}
	if config.PCIAddress != "" {
		physAddrs["pcilong"] = config.PCIAddress
	}
	if config.USBAddress != "" {
		physAddrs["usbaddr"] = config.USBAddress
	}
	if config.InterfaceName != "" {
		physAddrs["ifname"] = config.InterfaceName
	}
	if config.Serial != "" {
		physAddrs["serial"] = config.Serial
	}
	assigngrp := config.AssignmentGroup
	if assigngrp == "" {
		assigngrp = config.LogicalLabel
	}
	return &eveconfig.PhysicalIO{
		Ptype:           config.Type,
		Logicallabel:    config.LogicalLabel,
		Assigngrp:       assigngrp,
		Parentassigngrp: config.ParentAssignmentGroup,
		Phylabel:        config.PhysicalLabel,
		Phyaddrs:        physAddrs,
		Usage:           config.Usage,
	}
}

// toSystemAdapterProto returns EVE protobuf SystemAdapter for this adapter.
func (config NetworkAdapterConfig) toSystemAdapterProto() *eveconfig.SystemAdapter {
	var ipAddr string
	if config.StaticIP != nil {
		ipAddr = config.StaticIP.String()
	}
	isUplink := config.Usage == evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps ||
		config.Usage == evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly
	return &eveconfig.SystemAdapter{
		Name:                    config.LogicalLabel,
		Uplink:                  isUplink,
		NetworkUUID:             config.NetworkUUID.String(),
		Addr:                    ipAddr,
		LowerLayerName:          config.LogicalLabel,
		Cost:                    uint32(config.Cost),
		SharedLabels:            config.SharedLabels,
		AllowLocalModifications: config.AllowLocalModifications,
	}
}

// toPhysicalIOProto returns EVE protobuf PNAC for this adapter.
func (config NetworkAdapterConfig) toPNACProto() *eveconfig.PNAC {
	if !config.PNAC.Enable {
		return nil
	}
	return &eveconfig.PNAC{
		Logicallabel:              config.LogicalLabel,
		EapIdentity:               config.PNAC.EAPIdentity,
		EapMethod:                 config.PNAC.EAPMethod,
		CertEnrollmentProfileName: config.PNAC.CertEnrollmentProfileName,
	}
}

// BondConfig represents a bond (link aggregation) interface.
type BondConfig struct {
	LogicalLabel  string
	InterfaceName string
	MemberLabels  []string // Logical labels of aggregated PhysicalIO adapters.
	BondMode      evecommon.BondMode
	MIIMonitor    *eveconfig.MIIMonitor
	ARPMonitor    *eveconfig.ArpMonitor
	LACPRate      evecommon.LacpRate
	Cost          uint8
	NetworkUUID   uuid.UUID
	StaticIP      net.IP // use only in combination with StaticNetworkConfig
	SharedLabels  []string
	Usage         evecommon.PhyIoMemberUsage
}

// toBondAdapterProto returns EVE protobuf BondAdapter for this bond.
func (config BondConfig) toBondAdapterProto() *eveconfig.BondAdapter {
	bond := &eveconfig.BondAdapter{
		Logicallabel:    config.LogicalLabel,
		InterfaceName:   config.InterfaceName,
		LowerLayerNames: config.MemberLabels,
		BondMode:        config.BondMode,
		LacpRate:        config.LACPRate,
	}
	if config.MIIMonitor != nil {
		bond.Monitoring = &eveconfig.BondAdapter_Mii{Mii: config.MIIMonitor}
	} else if config.ARPMonitor != nil {
		bond.Monitoring = &eveconfig.BondAdapter_Arp{Arp: config.ARPMonitor}
	}
	return bond
}

// toSystemAdapterProto returns EVE protobuf SystemAdapter for this bond.
func (config BondConfig) toSystemAdapterProto() *eveconfig.SystemAdapter {
	var netID string
	if config.NetworkUUID != NilUUID {
		netID = config.NetworkUUID.String()
	}
	var ipAddr string
	if config.StaticIP != nil {
		ipAddr = config.StaticIP.String()
	}
	return &eveconfig.SystemAdapter{
		Name:           config.LogicalLabel,
		Uplink:         config.Usage == evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		NetworkUUID:    netID,
		Addr:           ipAddr,
		LowerLayerName: config.LogicalLabel,
		Cost:           uint32(config.Cost),
		SharedLabels:   config.SharedLabels,
	}
}

// VLANSubinterfaceConfig represents a single VLAN sub-interface.
type VLANSubinterfaceConfig struct {
	LogicalLabel       string
	InterfaceName      string
	ParentLogicalLabel string
	VlanID             uint16
	Cost               uint8
	NetworkUUID        uuid.UUID
	StaticIP           net.IP // use only in combination with StaticNetworkConfig
	SharedLabels       []string
	Usage              evecommon.PhyIoMemberUsage
}

// toVlanAdapterProto returns EVE protobuf VlanAdapter for this VLAN sub-interface.
func (config VLANSubinterfaceConfig) toVlanAdapterProto() *eveconfig.VlanAdapter {
	return &eveconfig.VlanAdapter{
		Logicallabel:   config.LogicalLabel,
		InterfaceName:  config.InterfaceName,
		LowerLayerName: config.ParentLogicalLabel,
		VlanId:         uint32(config.VlanID),
	}
}

// toSystemAdapterProto returns EVE protobuf SystemAdapter for this VLAN sub-interface.
func (config VLANSubinterfaceConfig) toSystemAdapterProto() *eveconfig.SystemAdapter {
	var netID string
	if config.NetworkUUID != NilUUID {
		netID = config.NetworkUUID.String()
	}
	var ipAddr string
	if config.StaticIP != nil {
		ipAddr = config.StaticIP.String()
	}
	return &eveconfig.SystemAdapter{
		Name:           config.LogicalLabel,
		Uplink:         config.Usage == evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		NetworkUUID:    netID,
		Addr:           ipAddr,
		LowerLayerName: config.LogicalLabel,
		Cost:           uint32(config.Cost),
		SharedLabels:   config.SharedLabels,
	}
}

// NetworkInstanceConfig defines a generic interface for network-instance configurations
// that can be converted into EVE protobuf representation.
type NetworkInstanceConfig interface {
	toProto(th *TestHarness, niUUID uuid.UUID) *eveconfig.NetworkInstanceConfig
}

// LocalNetworkInstanceConfig represents Local (L3, NAT-ed) Network Instance.
type LocalNetworkInstanceConfig struct {
	DisplayName              string
	Port                     string // logical label or shared label
	Subnet                   *net.IPNet
	DHCPRange                pillartypes.IPRange
	Gateway                  net.IP
	Domain                   string
	NTPServers               []string
	DNSServers               []net.IP
	StaticDNSEntries         []pillartypes.DNSNameToIP
	PropagateConnectedRoutes bool
	StaticRoutes             []pillartypes.IPRouteConfig
	EnableFlowlog            bool
	MTU                      uint16
	ForwardLLDP              bool
}

func (config LocalNetworkInstanceConfig) toProto(th *TestHarness,
	niUUID uuid.UUID) *eveconfig.NetworkInstanceConfig {
	var port *eveconfig.Adapter
	if config.Port != "" {
		port = &eveconfig.Adapter{
			Type: evecommon.PhyIoType_PhyIoNetEth,
			Name: config.Port,
		}
	}
	ipSpec := &evecommon.Ipspec{
		Domain: config.Domain,
	}
	if config.Subnet != nil {
		ipSpec.Subnet = config.Subnet.String()
		if config.DHCPRange.Start != nil && config.DHCPRange.End != nil {
			ipSpec.DhcpRange = &evecommon.IpRange{
				Start: config.DHCPRange.Start.String(),
				End:   config.DHCPRange.End.String(),
			}
		}
		if config.Gateway != nil {
			ipSpec.Gateway = config.Gateway.String()
		}
	}
	for _, dnsServer := range config.DNSServers {
		ipSpec.Dns = append(ipSpec.Dns, dnsServer.String())
	}
	for i, ntpServer := range config.NTPServers {
		if i == 0 {
			ipSpec.Ntp = ntpServer
		} else {
			ipSpec.MoreNtp = append(ipSpec.MoreNtp, ntpServer)
		}
	}
	var staticDNSEntries []*evecommon.ZnetStaticDNSEntry
	for _, entry := range config.StaticDNSEntries {
		var ips []string
		for _, ip := range entry.IPs {
			ips = append(ips, ip.String())
		}
		staticDNSEntries = append(staticDNSEntries, &evecommon.ZnetStaticDNSEntry{
			HostName: entry.HostName,
			Address:  ips,
		})
	}
	var staticRoutes []*eveconfig.IPRoute
	for _, route := range config.StaticRoutes {
		if route.DstNetwork == nil {
			th.t.Fatalf("IP route with undefined destinatio network: %+v", route)
		}
		if route.Gateway == nil && route.OutputPortLabel == "" {
			th.t.Fatalf("IP route with undefined next hop: %+v", route)
		}
		var gateway string
		if route.Gateway != nil {
			gateway = route.Gateway.String()
		}
		var customProbe *evecommon.ConnectivityProbe
		switch route.PortProbe.UserDefinedProbe.Method {
		case pillartypes.ConnectivityProbeMethodICMP:
			customProbe = &evecommon.ConnectivityProbe{
				ProbeMethod: evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_ICMP,
				ProbeEndpoint: &evecommon.ProbeEndpoint{
					Host: route.PortProbe.UserDefinedProbe.ProbeHost,
				},
			}
		case pillartypes.ConnectivityProbeMethodTCP:
			customProbe = &evecommon.ConnectivityProbe{
				ProbeMethod: evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_TCP,
				ProbeEndpoint: &evecommon.ProbeEndpoint{
					Host: route.PortProbe.UserDefinedProbe.ProbeHost,
					Port: uint32(route.PortProbe.UserDefinedProbe.ProbePort),
				},
			}
		}
		staticRoutes = append(staticRoutes, &eveconfig.IPRoute{
			DestinationNetwork: route.DstNetwork.String(),
			Gateway:            gateway,
			Port:               route.OutputPortLabel,
			Probe: &eveconfig.PortProbe{
				EnableGwPing:  route.PortProbe.EnabledGwPing,
				GwPingMaxCost: uint32(route.PortProbe.GwPingMaxCost),
				CustomProbe:   customProbe,
			},
			PreferLowerCost:          route.PreferLowerCost,
			PreferStrongerWwanSignal: route.PreferStrongerWwanSignal,
		})
	}
	return &eveconfig.NetworkInstanceConfig{
		Uuidandversion: &eveconfig.UUIDandVersion{
			Uuid:    niUUID.String(),
			Version: "1",
		},
		Displayname:              config.DisplayName,
		InstType:                 eveconfig.ZNetworkInstType_ZnetInstLocal,
		Activate:                 true,
		Port:                     port,
		IpType:                   eveconfig.AddressType_IPV4,
		Ip:                       ipSpec,
		Dns:                      staticDNSEntries,
		PropagateConnectedRoutes: config.PropagateConnectedRoutes,
		StaticRoutes:             staticRoutes,
		Mtu:                      uint32(config.MTU),
		DisableFlowlog:           !config.EnableFlowlog,
		ForwardLldp:              config.ForwardLLDP,
	}
}

// SwitchNetworkInstanceConfig represents Switch (L2, bridged) Network Instance.
type SwitchNetworkInstanceConfig struct {
	DisplayName     string
	Port            string // logical label or shared label
	EnableFlowlog   bool
	STPConfig       pillartypes.STPConfig // only applied for Switch NI with multiple ports
	MTU             uint16                // used only for airgap switch NI
	ForwardLLDP     bool
	VlanAccessPorts []pillartypes.VlanAccessPort // VLAN access port assignments; empty = no VLAN filtering
}

func (config SwitchNetworkInstanceConfig) toProto(th *TestHarness,
	niUUID uuid.UUID) *eveconfig.NetworkInstanceConfig {
	var port *eveconfig.Adapter
	if config.Port != "" {
		port = &eveconfig.Adapter{
			Type: evecommon.PhyIoType_PhyIoNetEth,
			Name: config.Port,
		}
	}
	var vlanAccessPorts []*eveconfig.VlanAccessPort
	for _, vap := range config.VlanAccessPorts {
		vlanAccessPorts = append(vlanAccessPorts, &eveconfig.VlanAccessPort{
			VlanId:     uint32(vap.VlanID),
			AccessPort: vap.PortLabel,
		})
	}
	return &eveconfig.NetworkInstanceConfig{
		Uuidandversion: &eveconfig.UUIDandVersion{
			Uuid:    niUUID.String(),
			Version: "1",
		},
		Displayname: config.DisplayName,
		InstType:    eveconfig.ZNetworkInstType_ZnetInstSwitch,
		Activate:    true,
		Port:        port,
		Stp: &eveconfig.SpanningTreeProtocol{
			PortsWithBpduGuard: config.STPConfig.PortsWithBpduGuard,
		},
		Mtu:             uint32(config.MTU),
		DisableFlowlog:  !config.EnableFlowlog,
		ForwardLldp:     config.ForwardLLDP,
		VlanAccessPorts: vlanAccessPorts,
	}
}

// ApplicationInstanceConfig wraps configuration for a single application deployed on EVE.
type ApplicationInstanceConfig struct {
	DisplayName         string
	Activate            bool
	ProfileList         []string
	Image               ApplicationImageStorage
	VirtualizationMode  eveconfig.VmMode
	CPUs                uint
	MemoryBytes         uint64
	DiskBytes           uint64
	EnableVNC           bool
	VNCDisplay          uint
	VNCPassword         string
	DisableLogs         bool
	UserData            string
	NetworkAdapters     []AppNetworkAdapter
	EnforceNetIntfOrder bool
	// Many more parameters can be configured; they will be added later as needed.
}

func (config ApplicationInstanceConfig) toProto(th *TestHarness, devName string,
	appUUID, volumeUUID uuid.UUID) *eveconfig.AppInstanceConfig {
	vmConfig := &eveconfig.VmConfig{
		Vcpus:                        uint32(config.CPUs),
		VirtualizationMode:           config.VirtualizationMode,
		EnableVnc:                    config.EnableVNC,
		VncDisplay:                   uint32(config.VNCDisplay),
		VncPasswd:                    config.VNCPassword,
		DisableLogs:                  config.DisableLogs,
		EnforceNetworkInterfaceOrder: config.EnforceNetIntfOrder,
	}
	if config.MemoryBytes != 0 {
		vmConfig.Memory = uint32(config.MemoryBytes / KiB)
	}
	appInstConfig := &eveconfig.AppInstanceConfig{
		Uuidandversion: &eveconfig.UUIDandVersion{
			Uuid:    appUUID.String(),
			Version: "1",
		},
		Displayname:    config.DisplayName,
		Fixedresources: vmConfig,
		Activate:       config.Activate,
		ProfileList:    config.ProfileList,
	}
	if volumeUUID != NilUUID {
		appInstConfig.VolumeRefList = append(appInstConfig.VolumeRefList,
			&eveconfig.VolumeRef{
				Uuid:     volumeUUID.String(),
				MountDir: "/",
			})
	}
	for i, netAdapter := range config.NetworkAdapters {
		switch adapter := netAdapter.(type) {
		case DirectlyAssignedNetworkAdapter:
			appInstConfig.Adapters = append(appInstConfig.Adapters, &eveconfig.Adapter{
				Type:           evecommon.PhyIoType_PhyIoNetEth,
				Name:           adapter.LogicalLabel,
				InterfaceOrder: uint32(i),
			})
		case VirtualNetworkAdapter:
			var ipAddr string
			if adapter.StaticIP != nil {
				ipAddr = adapter.StaticIP.String()
			}
			if adapter.NetworkInstanceUUID == NilUUID {
				th.t.Fatalf("Application virtual network adapter %q "+
					"with undefined Network Instance reference", adapter.LogicalLabel)
			}
			var acls []*eveconfig.ACE
			var aclID int32
			for _, portFwdRule := range adapter.PortFwdRules {
				aclID++ // start with 1
				matches := []*eveconfig.ACEMatch{
					{
						Type:  "protocol",
						Value: portFwdRule.Protocol.String(),
					},
					{
						Type:  "lport",
						Value: strconv.Itoa(int(portFwdRule.EdgeNodePort)),
					},
				}
				if portFwdRule.AdapterLabel != "" {
					matches = append(matches, &eveconfig.ACEMatch{
						Type:  "adapter",
						Value: portFwdRule.AdapterLabel,
					})
				}
				acls = append(acls, &eveconfig.ACE{
					Matches: matches,
					Actions: []*eveconfig.ACEAction{
						{
							Portmap: true,
							AppPort: uint32(portFwdRule.AppPort),
						},
					},
					Id: aclID,
				})
			}
			for _, allowRule := range adapter.ACLAllowRules {
				aclID++
				var matches []*eveconfig.ACEMatch
				matches = append(matches, &eveconfig.ACEMatch{
					Type:  "protocol",
					Value: allowRule.Protocol.String(),
				})
				if allowRule.RemoteSubnet != nil {
					matches = append(matches, &eveconfig.ACEMatch{
						Type:  "ip",
						Value: allowRule.RemoteSubnet.String(),
					})
				}
				if allowRule.RemoteHostname != "" {
					matches = append(matches, &eveconfig.ACEMatch{
						Type:  "host",
						Value: allowRule.RemoteHostname,
					})
				}
				if allowRule.RemotePort != 0 {
					matches = append(matches, &eveconfig.ACEMatch{
						Type:  "fport",
						Value: strconv.Itoa(int(allowRule.RemotePort)),
					})
				}
				acls = append(acls, &eveconfig.ACE{
					Matches: matches,
					Actions: []*eveconfig.ACEAction{
						{
							Drop: false,
						},
					},
					Id: aclID,
				})
			}
			appInstConfig.Interfaces = append(appInstConfig.Interfaces,
				&eveconfig.NetworkAdapter{
					Name:           adapter.LogicalLabel,
					NetworkId:      adapter.NetworkInstanceUUID.String(),
					Addr:           ipAddr,
					MacAddress:     adapter.MAC.String(),
					Acls:           acls,
					AccessVlanId:   uint32(adapter.AccessVLAN),
					InterfaceOrder: uint32(i),
				})
		}
	}
	if config.UserData != "" {
		if th.isDeviceOnboarded(devName) {
			cipherData, err := th.encryptCipherData(devName,
				&evecommon.EncryptionBlock{
					ProtectedUserData: config.UserData,
				})
			if err != nil {
				th.t.Fatalf("Failed to encrypt user data for application %v: %v",
					config.DisplayName, err)
			}
			appInstConfig.CipherData = cipherData
		} else {
			// This is initial device configuration.
			// We do not yet have cryptographic material for object-level encryption.
			// Store user data in plaintext.
			appInstConfig.UserData = config.UserData
		}
	}
	return appInstConfig
}

// ApplicationImageStorage defines a generic interface for datastore configurations
// that can be converted into EVE protobuf representation.
type ApplicationImageStorage interface {
	toProto(th *TestHarness, log *logrus.Entry, devName string,
		contentTreeUUID, datastoreUUID uuid.UUID,
		appName string) (*eveconfig.ContentTree, *eveconfig.DatastoreConfig)
}

// DockerContainer defines path to application image stored inside a docker image registry.
type DockerContainer struct {
	Domain    string // default: "index.docker.io"
	ImageName string
	Tag       string
	// Username and password are not configurable here.
	// Instead, evetest pulls credentials from the docker client running on the host
	// (docker socket will be mounted to evetest container).
}

func (container DockerContainer) toProto(th *TestHarness, log *logrus.Entry,
	devName string, contentTreeUUID, datastoreUUID uuid.UUID,
	appName string) (*eveconfig.ContentTree, *eveconfig.DatastoreConfig) {
	contentTree := &eveconfig.ContentTree{
		Uuid:        contentTreeUUID.String(),
		DisplayName: appName + "-image",
		URL:         fmt.Sprintf("%s:%s", container.ImageName, container.Tag),
		Iformat:     eveconfig.Format_CONTAINER,
		DsIdsList:   []string{datastoreUUID.String()},
	}
	dsConfig := &eveconfig.DatastoreConfig{
		Id:    datastoreUUID.String(),
		DType: eveconfig.DsType_DsContainerRegistry,
	}
	// Normalize domain: empty and "index.docker.io" are both docker.io.
	domain := container.Domain
	if domain == "" || domain == "index.docker.io" {
		domain = "docker.io"
	}
	mirrors := constants.LoadRegistryMirrors()
	var mirrorURL string
	if addrs, ok := mirrors[domain]; ok {
		// If th.ipv6OnlyRegistryMirrors is set but this registry has no IPv6
		// mirror address, mirrorURL stays empty and we fall through below —
		// the app is simply pulled from the real, un-mirrored registry.
		mirrorURL, _ = constants.SelectRegistryMirror(addrs, th.ipv6OnlyRegistryMirrors)
	}
	if mirrorURL != "" {
		// Strip transport scheme — EVE's datastore FQDN uses docker:// as a
		// registry-type marker, not a transport scheme.
		bare := mirrorURL
		if idx := strings.Index(mirrorURL, "://"); idx != -1 {
			bare = mirrorURL[idx+3:]
		}
		dsConfig.Fqdn = fmt.Sprintf("docker://%s", bare)
	} else if domain == "docker.io" {
		dsConfig.Fqdn = "docker://index.docker.io"
	} else {
		dsConfig.Fqdn = fmt.Sprintf("docker://%s", domain)
	}
	username, password, err := utils.GetDockerAuthPlain(log, dsConfig.Fqdn)
	if err != nil {
		// Just log warning, container will be pulled without authentication.
		log.Warnf("failed to get docker username/password: %v", err)
	} else {
		dsConfig.ApiKey = username
		dsConfig.Password = password
	}
	return contentTree, dsConfig
}

// AwsS3Bucket defines path to application image stored inside AWS S3.
// https://<Bucket>.s3.<Region>.amazonaws.com/<ImageRelativePath>
type AwsS3Bucket struct {
	ImageFormat       eveconfig.Format
	ImageSHA256       string
	MaxDownloadBytes  uint64
	ImageRelativePath string
	Region            string
	Bucket            string
	AccessKeyID       string
	SecretAccessKey   string
}

func (s3 AwsS3Bucket) toProto(th *TestHarness, log *logrus.Entry, devName string,
	contentTreeUUID, datastoreUUID uuid.UUID,
	appName string) (*eveconfig.ContentTree, *eveconfig.DatastoreConfig) {
	contentTree := &eveconfig.ContentTree{
		Uuid:         contentTreeUUID.String(),
		DisplayName:  appName + "-image",
		URL:          s3.ImageRelativePath,
		Iformat:      s3.ImageFormat,
		Sha256:       s3.ImageSHA256,
		MaxSizeBytes: s3.MaxDownloadBytes,
		DsIdsList:    []string{datastoreUUID.String()},
	}
	dsConfig := &eveconfig.DatastoreConfig{
		Id:     datastoreUUID.String(),
		Region: s3.Region,
		Dpath:  s3.Bucket,
		Fqdn:   fmt.Sprintf("https://%s.s3.%s.amazonaws.com", s3.Bucket, s3.Region),
		DType:  eveconfig.DsType_DsS3,
	}
	if th.isDeviceOnboarded(devName) {
		var err error
		cipherData, err := th.encryptCipherData(devName,
			&evecommon.EncryptionBlock{
				DsAPIKey:   s3.AccessKeyID,
				DsPassword: s3.SecretAccessKey,
			})
		if err != nil {
			th.t.Fatalf(
				"Failed to encrypt Azure datastore credentials: %v", err)
		}
		dsConfig.CipherData = cipherData
	} else {
		// This is initial device configuration.
		// We do not yet have cryptographic material for object-level encryption.
		// Store the access key ID and the secret key in plaintext.
		dsConfig.ApiKey = s3.AccessKeyID
		dsConfig.Password = s3.SecretAccessKey
	}
	return contentTree, dsConfig
}

// AzureBlob defines path to application image stored inside Azure Blob.
// https://<AccountName>.blob.core.windows.net/<Container>/<ImageRelativePath>
type AzureBlob struct {
	ImageFormat       eveconfig.Format
	ImageSHA256       string
	MaxDownloadBytes  uint64
	ImageRelativePath string
	AccountName       string
	AccountKey        string
	Container         string
}

func (azure AzureBlob) toProto(th *TestHarness, log *logrus.Entry, devName string,
	contentTreeUUID, datastoreUUID uuid.UUID,
	appName string) (*eveconfig.ContentTree, *eveconfig.DatastoreConfig) {
	contentTree := &eveconfig.ContentTree{
		Uuid:         contentTreeUUID.String(),
		DisplayName:  appName + "-image",
		URL:          azure.ImageRelativePath,
		Iformat:      azure.ImageFormat,
		Sha256:       azure.ImageSHA256,
		MaxSizeBytes: azure.MaxDownloadBytes,
		DsIdsList:    []string{datastoreUUID.String()},
	}
	dsConfig := &eveconfig.DatastoreConfig{
		Id:    datastoreUUID.String(),
		Fqdn:  fmt.Sprintf("https://%s.blob.core.windows.net", azure.AccountName),
		Dpath: azure.Container,
		DType: eveconfig.DsType_DsAzureBlob,
	}
	if th.isDeviceOnboarded(devName) {
		var err error
		cipherData, err := th.encryptCipherData(devName,
			&evecommon.EncryptionBlock{
				DsAPIKey:   azure.AccountName,
				DsPassword: azure.AccountKey,
			})
		if err != nil {
			th.t.Fatalf(
				"Failed to encrypt Azure datastore credentials: %v", err)
		}
		dsConfig.CipherData = cipherData
	} else {
		// This is initial device configuration.
		// We do not yet have cryptographic material for object-level encryption.
		// Store the account name and the account key in plaintext.
		dsConfig.ApiKey = azure.AccountName
		dsConfig.Password = azure.AccountKey
	}
	return contentTree, dsConfig
}

// HTTPStorage defines the location of an application image stored on an HTTP datastore.
type HTTPStorage struct {
	ImageFormat            eveconfig.Format
	ImageSHA256            string
	MaxDownloadBytes       uint64
	ImageRelativePath      string
	ServerAddress          string
	ServerPort             uint16 // if not defined, we assume port 80 (HTTP) / 443 (HTTPS)
	UseHTTPS               bool   // true = HTTPS, false = HTTP
	HTTPSTrustedCACertsPEM []string
}

// toProto converts an HTTPStorage into EVE protobuf ContentTree + DatastoreConfig.
func (storage HTTPStorage) toProto(th *TestHarness, log *logrus.Entry, devName string,
	contentTreeUUID, datastoreUUID uuid.UUID,
	appName string) (*eveconfig.ContentTree, *eveconfig.DatastoreConfig) {
	contentTree := &eveconfig.ContentTree{
		Uuid:         contentTreeUUID.String(),
		DisplayName:  appName + "-image",
		URL:          storage.ImageRelativePath,
		Iformat:      storage.ImageFormat,
		Sha256:       storage.ImageSHA256,
		MaxSizeBytes: storage.MaxDownloadBytes,
		DsIdsList:    []string{datastoreUUID.String()},
	}
	dsConfig := &eveconfig.DatastoreConfig{
		Id: datastoreUUID.String(),
	}
	if storage.UseHTTPS {
		port := "443"
		if storage.ServerPort != 0 {
			port = strconv.Itoa(int(storage.ServerPort))
		}
		dsConfig.Fqdn = "https://" + net.JoinHostPort(
			storage.ServerAddress, port)
		for _, cert := range storage.HTTPSTrustedCACertsPEM {
			dsConfig.DsCertPEM = append(dsConfig.DsCertPEM, []byte(cert))
		}
		dsConfig.DType = eveconfig.DsType_DsHttps
	} else {
		port := "80"
		if storage.ServerPort != 0 {
			port = strconv.Itoa(int(storage.ServerPort))
		}
		dsConfig.Fqdn = "http://" + net.JoinHostPort(storage.ServerAddress, port)
		dsConfig.DType = eveconfig.DsType_DsHttp
	}
	return contentTree, dsConfig
}

// SFTPStorage defines the location and access parameters for an application
// image stored on an SFTP datastore
type SFTPStorage struct {
	ImageFormat       eveconfig.Format
	ImageSHA256       string
	MaxDownloadBytes  uint64
	ImageRelativePath string
	ServerAddress     string
	ServerPort        uint16 // if not defined, we assume port 22
	Username          string
	Password          string
}

func (storage SFTPStorage) toProto(th *TestHarness, log *logrus.Entry, devName string,
	contentTreeUUID, datastoreUUID uuid.UUID,
	appName string) (*eveconfig.ContentTree, *eveconfig.DatastoreConfig) {
	contentTree := &eveconfig.ContentTree{
		Uuid:         contentTreeUUID.String(),
		DisplayName:  appName + "-image",
		URL:          storage.ImageRelativePath,
		Iformat:      storage.ImageFormat,
		Sha256:       storage.ImageSHA256,
		MaxSizeBytes: storage.MaxDownloadBytes,
		DsIdsList:    []string{datastoreUUID.String()},
	}
	dsConfig := &eveconfig.DatastoreConfig{
		Id:    datastoreUUID.String(),
		DType: eveconfig.DsType_DsSFTP,
	}
	port := "22"
	if storage.ServerPort != 0 {
		port = strconv.Itoa(int(storage.ServerPort))
	}
	dsConfig.Fqdn = "sftp://" + net.JoinHostPort(storage.ServerAddress, port)
	if th.isDeviceOnboarded(devName) {
		var err error
		cipherData, err := th.encryptCipherData(devName,
			&evecommon.EncryptionBlock{
				DsAPIKey:   storage.Username,
				DsPassword: storage.Password,
			})
		if err != nil {
			th.t.Fatalf(
				"Failed to encrypt SFTP datastore credentials: %v", err)
		}
		dsConfig.CipherData = cipherData
	} else {
		// This is initial device configuration.
		// We do not yet have cryptographic material for object-level encryption.
		// Store the username and the password in plaintext.
		dsConfig.ApiKey = storage.Username
		dsConfig.Password = storage.Password
	}
	return contentTree, dsConfig
}

// AppNetworkAdapter identifies types that represent application network
// adapter configurations.
type AppNetworkAdapter interface {
	isAppNetworkAdapter()
}

// DirectlyAssignedNetworkAdapter represents network adapter directly assigned
// to an application (e.g. using PCI passthrough).
type DirectlyAssignedNetworkAdapter struct {
	LogicalLabel string
}

func (DirectlyAssignedNetworkAdapter) isAppNetworkAdapter() {}

// VirtualNetworkAdapter represents application virtual network adapters
// (e.g., virtio, e1000).
type VirtualNetworkAdapter struct {
	LogicalLabel        string
	NetworkInstanceUUID uuid.UUID
	StaticIP            net.IP
	MAC                 net.HardwareAddr
	AccessVLAN          uint16
	PortFwdRules        []PortFwdRule
	ACLAllowRules       []ACLAllowRule
}

func (VirtualNetworkAdapter) isAppNetworkAdapter() {}

// NetworkProtocol defined for ACL rules.
type NetworkProtocol uint8

const (
	// NetworkProtocolAny indicates that an ACL rule matches any network protocol.
	NetworkProtocolAny NetworkProtocol = iota
	// NetworkProtocolICMP indicates that an ACL rule matches ICMP traffic.
	NetworkProtocolICMP
	// NetworkProtocolTCP indicates that an ACL rule matches TCP traffic.
	NetworkProtocolTCP
	// NetworkProtocolUDP indicates that an ACL rule matches UDP traffic.
	NetworkProtocolUDP
)

// String returns string representation of the network protocol.
func (p NetworkProtocol) String() string {
	switch p {
	case NetworkProtocolAny:
		return "all"
	case NetworkProtocolICMP:
		return "icmp"
	case NetworkProtocolTCP:
		return "tcp"
	case NetworkProtocolUDP:
		return "udp"
	}
	return ""
}

// PortFwdRule is a port forwarding rule.
type PortFwdRule struct {
	Protocol     NetworkProtocol
	EdgeNodePort uint16
	AppPort      uint16
	// AdapterLabel, when non-empty, restricts this port-forwarding rule to
	// ports that carry this shared label (generates an "adapter" ACE match).
	AdapterLabel string
}

// ACLAllowRule is a ACL ALLOW rule.
type ACLAllowRule struct {
	Protocol NetworkProtocol
	// Specify either remote subnet or hostname, not both.
	RemoteSubnet   *net.IPNet
	RemoteHostname string
	RemotePort     uint16 // 0 means any
}

// LPSConfig contains configuration for the Local Profile Server.
type LPSConfig struct {
	GlobalProfile string
	Address       string // IP[:port] or hostname[:port]
	AuthToken     string
}

// SCEPProfile : SCEP (Simple Certificate Enrollment Protocol) configuration profile.
// Defines how a device enrolls for X.509 certificates using SCEP,
// including server connectivity, trust anchors, and CSR parameters.
type SCEPProfile struct {
	Name string
	// Full SCEP server URL, including scheme, host, and path.
	// Example: https://ca.example.com/scep
	SCEPServerURL string
	// If true, SCEP requests are sent via the controller-provided SCEP proxy.
	// If false, the device connects directly to the SCEP server.
	UseControllerProxy bool
	ChallengePassword  string
	CACertsPEM         []string
	CSR                CSRProfile
}

// CSRProfile : Certificate Signing Request (CSR) configuration profile.
// Defines subject identity, extensions, cryptographic parameters,
// and renewal behavior for certificate enrollment.
type CSRProfile struct {
	// X.509 Distinguished Name (DN) attributes.
	CommonName         string // CN
	Organization       string // O
	OrganizationalUnit string // OU
	Country            string // C
	State              string // ST
	Locality           string // L

	// X.509 Subject Alternative Name (SAN) attributes.
	SanDNS    []string
	SanIPs    []net.IP
	SanURIs   []string
	SANEmails []string

	// Certificate renewal settings.
	// Percentage of the certificate validity period after which
	// the device should attempt renewal (e.g., 80 = renew after 80%).
	RenewPeriodPercent uint8

	KeyType       eveconfig.KeyType
	HashAlgorithm eveconfig.HashAlgorithm
}

func (profile CSRProfile) toProto() *eveconfig.CSRProfile {
	profileProto := &eveconfig.CSRProfile{
		CommonName:         profile.CommonName,
		Organization:       profile.Organization,
		OrganizationalUnit: profile.OrganizationalUnit,
		Country:            profile.Country,
		State:              profile.State,
		Locality:           profile.Locality,
		SanDns:             profile.SanDNS,
		SanUri:             profile.SanURIs,
		SanEmail:           profile.SANEmails,
		RenewPeriodPercent: uint32(profile.RenewPeriodPercent),
		KeyType:            profile.KeyType,
		HashAlgorithm:      profile.HashAlgorithm,
	}
	for _, sanIP := range profile.SanIPs {
		profileProto.SanIp = append(profileProto.SanIp, sanIP.String())
	}
	return profileProto
}

func (profile SCEPProfile) toProto(th *TestHarness, devName string) *eveconfig.SCEPProfile {
	profileProto := &eveconfig.SCEPProfile{
		ProfileName:        profile.Name,
		ScepUrl:            profile.SCEPServerURL,
		UseControllerProxy: profile.UseControllerProxy,
		CsrProfile:         profile.CSR.toProto(),
	}
	for _, cert := range profile.CACertsPEM {
		profileProto.CaCertPem = append(profileProto.CaCertPem, []byte(cert))
	}
	if profile.ChallengePassword == "" {
		return profileProto
	}
	if th.isDeviceOnboarded(devName) {
		var err error
		cipherData, err := th.encryptCipherData(devName,
			&evecommon.EncryptionBlock{
				ScepChallengePassword: profile.ChallengePassword,
			})
		if err != nil {
			th.t.Fatalf("Failed to encrypt SCEP server challenge password: %v", err)
		}
		profileProto.ScepChallengePassword = cipherData
	} else {
		th.t.Fatalf("Cannot encrypt SCEP server challenge password: " +
			"device must be onboarded to derive the required encryption key")
	}
	return profileProto
}

// IPAddress converts IP address from string to net.IP
func IPAddress(ipAddr string) net.IP {
	th := getTestHarness()
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		th.t.Fatalf("Invalid IP address: %s", ipAddr)
	}
	return ip
}

// IPAddressWithPrefix parses an IP address with a prefix length (e.g.
// "172.22.12.10/24") and returns it as *net.IPNet, preserving the host
// address. Unlike IPSubnet, the host bits are not masked.
func IPAddressWithPrefix(cidr string) *net.IPNet {
	th := getTestHarness()
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		th.t.Fatalf("Invalid IP address with prefix %s: %v", cidr, err)
	}
	subnet.IP = ip
	return subnet
}

// IPSubnet converts IP subnet from string to *net.IPNet
func IPSubnet(ipSubnet string) *net.IPNet {
	th := getTestHarness()
	_, subnet, err := net.ParseCIDR(ipSubnet)
	if err != nil {
		th.t.Fatalf("Invalid IP subnet %s: %v", ipSubnet, err)
	}
	return subnet
}

// MACAddress converts MAC address from string to net.HardwareAddr
func MACAddress(macAddr string) net.HardwareAddr {
	th := getTestHarness()
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		th.t.Fatalf("Invalid MAC address %s: %v", macAddr, err)
	}
	return mac
}

// Clone creates a deep copy of the EdgeDeviceConfig.
func (dc *EdgeDeviceConfig) Clone() *EdgeDeviceConfig {
	return &EdgeDeviceConfig{
		EdgeDevConfig: proto.CloneOf(dc.EdgeDevConfig),
		th:            dc.th,
		log:           dc.log,
	}
}

// MakeBootstrapConfig : wrap device configuration into BootstrapConfig, which is used
// to carry the initial device configuration and gets installed into the /config partition.
func (dc *EdgeDeviceConfig) MakeBootstrapConfig() *eveconfig.BootstrapConfig {
	devConf := dc.Clone()
	devConf.setDefaultConfigProperties()
	devConf.ConfigTimestamp = timestamppb.New(time.Now())
	devConfPbuf, err := proto.Marshal(devConf)
	if err != nil {
		dc.th.t.Fatalf("Failed to marshal device config to protobuf: %v", err)
	}
	signingCert, signingKey := dc.th.adamClient.GetSigningCertAndKey()
	signedDevConf, err := utils.PrepareAuthContainer(devConfPbuf, signingCert, signingKey)
	if err != nil {
		dc.th.t.Fatalf("Failed to wrap bootstrap with auth envelope: %v", err)
	}
	bootstrapConf := &eveconfig.BootstrapConfig{
		SignedConfig: signedDevConf,
		ControllerCerts: []*evecerts.ZCert{
			utils.ConvertToZCert(signingCert,
				evecerts.ZCertType_CERT_TYPE_CONTROLLER_SIGNING),
		},
	}
	return bootstrapConf
}

// SetConfigProperties : add configuration properties into the device configuration.
func (dc *EdgeDeviceConfig) SetConfigProperties(configProps *pillartypes.ConfigItemValueMap) {
	for key, gcp := range configProps.GlobalSettings {
		dc.ConfigItems = append(dc.ConfigItems, &eveconfig.ConfigItem{
			Key:   string(key),
			Value: gcp.StringValue(),
		})
	}
	for agent, agentConfigProps := range configProps.AgentSettings {
		for key, acp := range agentConfigProps {
			dc.ConfigItems = append(dc.ConfigItems, &eveconfig.ConfigItem{
				Key:   fmt.Sprintf("agent.%s.%s", agent, key),
				Value: acp.StringValue(),
			})
		}
	}
}

// AddNetwork : add new network configuration.
// This can be then referenced from NetworkAdapterConfig.
func (dc *EdgeDeviceConfig) AddNetwork(netConfig NetworkConfig) uuid.UUID {
	networkUUID := dc.th.newUUID("network")
	dc.addNetworkWithUUID(netConfig, networkUUID)
	return networkUUID
}

// addNetworkWithUUID adds a network using a pre-generated UUID.
func (dc *EdgeDeviceConfig) addNetworkWithUUID(netConfig NetworkConfig, networkUUID uuid.UUID) {
	if netConfig == nil {
		dc.th.t.Fatalf("Undefined network configuration")
	}
	dc.Networks = append(dc.Networks, netConfig.toProto(dc.th, dc.DeviceName, networkUUID))
}

// UpdateNetwork : update already added network configuration.
func (dc *EdgeDeviceConfig) UpdateNetwork(networkUUID uuid.UUID, newConfig NetworkConfig) {
	if newConfig == nil {
		dc.th.t.Fatalf("Undefined network configuration")
	}
	netID := networkUUID.String()
	newProtoConfig := newConfig.toProto(dc.th, dc.DeviceName, networkUUID)
	for i, network := range dc.Networks {
		if network.Id == netID {
			if network.Wireless.GetType() != newProtoConfig.Wireless.GetType() {
				// Changing the wireless type would require updating all associated adapters
				// and their underlying physical I/O types. It would also require validating
				// compatibility with any VLAN sub-interfaces that use this network.
				// To avoid this complexity and potential misconfiguration, such changes
				// are disallowed.
				dc.th.t.Fatalf("Changing network wireless type is not supported")
			}
			dc.Networks[i] = newProtoConfig
			return
		}
	}
	dc.th.t.Fatalf("Network with UUID %q was not found", netID)
}

// DeleteNetwork : remove previously added network configuration.
func (dc *EdgeDeviceConfig) DeleteNetwork(networkUUID uuid.UUID) {
	netID := networkUUID.String()
	for _, adapter := range dc.SystemAdapterList {
		if adapter.NetworkUUID == netID {
			dc.th.t.Fatalf(
				"Cannot delete network %q: it is currently in use by system adapter %q",
				netID, adapter.Name)
		}
	}
	for i, network := range dc.Networks {
		if network.Id == netID {
			// Remove the network from the slice
			dc.Networks = append(dc.Networks[:i], dc.Networks[i+1:]...)
			return
		}
	}
	dc.th.t.Fatalf("Network with UUID %q was not found", netID)
}

func (dc *EdgeDeviceConfig) checkAdapterNetwork(config NetworkAdapterConfig) {
	if config.NetworkUUID == NilUUID {
		return
	}
	netID := config.NetworkUUID.String()
	var netconfig *eveconfig.NetworkConfig
	for _, network := range dc.Networks {
		if network.Id == netID {
			netconfig = network
			break
		}
	}
	if netconfig == nil {
		dc.th.t.Fatalf(
			"Network %q referenced by network adapter %q does not exist",
			netID, config.LogicalLabel)
	}
	if netconfig.Wireless.GetType() != config.WirelessType {
		dc.th.t.Fatalf(
			"WirelessType of network %q and network adapter %q do not match",
			netID, config.LogicalLabel)
	}
	return
}

// AddNetworkAdapter adds a new physical network adapter to the device
// configuration.
func (dc *EdgeDeviceConfig) AddNetworkAdapter(config NetworkAdapterConfig) {
	for _, adapter := range dc.SystemAdapterList {
		if adapter.Name == config.LogicalLabel {
			dc.th.t.Fatalf("Network adapter %q already exist", config.LogicalLabel)
		}
	}
	for _, vlan := range dc.Vlans {
		if vlan.Logicallabel == config.LogicalLabel {
			dc.th.t.Fatalf("Network adapter logical label %q is already in use "+
				"by a VLAN adapter", config.LogicalLabel)
		}
	}
	for _, bond := range dc.Bonds {
		if bond.Logicallabel == config.LogicalLabel {
			dc.th.t.Fatalf("Network adapter logical label %q is already in use "+
				"by a bond adapter", config.LogicalLabel)
		}
	}
	for _, physIO := range dc.DeviceIoList {
		if physIO.Logicallabel == config.LogicalLabel {
			dc.th.t.Fatalf("Network adapter logical label %q is already in use "+
				"by an I/O device", config.LogicalLabel)
		}
	}
	dc.checkAdapterNetwork(config)
	dc.DeviceIoList = append(dc.DeviceIoList, config.toPhysicalIOProto())
	if config.PNAC.Enable {
		dc.Pnacs = append(dc.Pnacs, config.toPNACProto())
	}
	if config.NetworkUUID != NilUUID {
		dc.SystemAdapterList = append(dc.SystemAdapterList, config.toSystemAdapterProto())
	}
}

// AddPhysicalIO adds a raw PhysicalIO (assignable I/O) device to the device
// configuration. Use it for non-network devices and for device-model
// inconsistencies that AddNetworkAdapter cannot express. A given logical label
// is owned by exactly one of AddNetworkAdapter or AddPhysicalIO.
func (dc *EdgeDeviceConfig) AddPhysicalIO(config PhysicalIOConfig) {
	dc.checkIOLogicalLabelFree(config.LogicalLabel)
	dc.DeviceIoList = append(dc.DeviceIoList, config.toPhysicalIOProto())
}

// checkIOLogicalLabelFree fails the test if logicalLabel is already used by any
// I/O device, system adapter, VLAN or bond adapter.
func (dc *EdgeDeviceConfig) checkIOLogicalLabelFree(logicalLabel string) {
	for _, physIO := range dc.DeviceIoList {
		if physIO.Logicallabel == logicalLabel {
			dc.th.t.Fatalf("I/O device with logical label %q already exists",
				logicalLabel)
		}
	}
	for _, adapter := range dc.SystemAdapterList {
		if adapter.Name == logicalLabel {
			dc.th.t.Fatalf("logical label %q is already in use by a system adapter",
				logicalLabel)
		}
	}
	for _, vlan := range dc.Vlans {
		if vlan.Logicallabel == logicalLabel {
			dc.th.t.Fatalf("logical label %q is already in use by a VLAN adapter",
				logicalLabel)
		}
	}
	for _, bond := range dc.Bonds {
		if bond.Logicallabel == logicalLabel {
			dc.th.t.Fatalf("logical label %q is already in use by a bond adapter",
				logicalLabel)
		}
	}
}

// UpdateNetworkAdapter updates an existing network adapter identified by
// its logical label.
func (dc *EdgeDeviceConfig) UpdateNetworkAdapter(config NetworkAdapterConfig) {
	dc.checkAdapterNetwork(config)

	// Update or remove SystemAdapter.
	sysAdapterIdx := -1
	for i, adapter := range dc.SystemAdapterList {
		if adapter.Name == config.LogicalLabel {
			sysAdapterIdx = i
			break
		}
	}
	if config.NetworkUUID != NilUUID {
		if sysAdapterIdx >= 0 {
			dc.SystemAdapterList[sysAdapterIdx] = config.toSystemAdapterProto()
		} else {
			dc.SystemAdapterList = append(dc.SystemAdapterList,
				config.toSystemAdapterProto())
		}
	} else if sysAdapterIdx >= 0 {
		dc.SystemAdapterList = append(
			dc.SystemAdapterList[:sysAdapterIdx],
			dc.SystemAdapterList[sysAdapterIdx+1:]...)
	}

	// Update PNAC config.
	pnacFound := false
	for i, pnac := range dc.Pnacs {
		if pnac.Logicallabel == config.LogicalLabel {
			pnacFound = true
			if config.PNAC.Enable {
				dc.Pnacs[i] = config.toPNACProto()
			} else {
				dc.Pnacs = append(dc.Pnacs[:i], dc.Pnacs[i+1:]...)
			}
			break
		}
	}
	if !pnacFound && config.PNAC.Enable {
		dc.Pnacs = append(dc.Pnacs, config.toPNACProto())
	}

	// Update PhysicalIO config.
	for i, physIO := range dc.DeviceIoList {
		if physIO.Logicallabel == config.LogicalLabel {
			dc.DeviceIoList[i] = config.toPhysicalIOProto()
			break
		}
	}
}

// DeleteNetworkAdapter removes a network adapter identified by its
// logical label from the device configuration.
func (dc *EdgeDeviceConfig) DeleteNetworkAdapter(logicalLabel string) {
	for i, adapter := range dc.SystemAdapterList {
		if adapter.Name == logicalLabel {
			dc.SystemAdapterList = append(
				dc.SystemAdapterList[:i], dc.SystemAdapterList[i+1:]...)
			break
		}
	}
	for i, pnac := range dc.Pnacs {
		if pnac.Logicallabel == logicalLabel {
			dc.Pnacs = append(dc.Pnacs[:i], dc.Pnacs[i+1:]...)
			break
		}
	}
	found := false
	for i, physIO := range dc.DeviceIoList {
		if physIO.Logicallabel == logicalLabel {
			switch physIO.Ptype {
			case evecommon.PhyIoType_PhyIoNetWLAN,
				evecommon.PhyIoType_PhyIoNetWWAN,
				evecommon.PhyIoType_PhyIoNetEth:
				// OK, it is network adapter.
			default:
				dc.th.t.Fatalf("IO device with logical label %q is not a network adapter",
					logicalLabel)
			}
			dc.DeviceIoList = append(dc.DeviceIoList[:i], dc.DeviceIoList[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		dc.th.t.Fatalf("Network adapter with logical label %q was not found",
			logicalLabel)
	}
}

// setDefaultConfigProperties appends a predefined set of default EVE configuration
// properties used for test execution, without overriding any test-defined values.
func (dc *EdgeDeviceConfig) setDefaultConfigProperties() {
	// helper function to check if a config key already exists
	hasConfigKey := func(configItems []*eveconfig.ConfigItem, key string) bool {
		for _, item := range configItems {
			if item.Key == key {
				return true
			}
		}
		return false
	}

	// Predefined config items to add.
	defaultConfigItems := []*eveconfig.ConfigItem{
		// Increase log verbosity to aid investigation of test failures.
		{Key: string(pillartypes.DefaultLogLevel), Value: "debug"},
		{Key: string(pillartypes.DefaultRemoteLogLevel), Value: "debug"},

		// Ensure access to EVE and applications.
		{Key: string(pillartypes.SSHAuthorizedKeys), Value: constants.EVESSHPublickKey},
		{Key: string(pillartypes.AllowAppVnc), Value: "true"},
		{Key: string(pillartypes.ConsoleAccess), Value: "true"},

		// The configuration options below reduce polling intervals
		// to speed up test execution.
		{Key: string(pillartypes.ConfigInterval), Value: "5"},
		{Key: string(pillartypes.MetricInterval), Value: "20"},
		{Key: string(pillartypes.DevInfoInterval), Value: "30"},
		{Key: string(pillartypes.LocationAppInterval), Value: "20"},
		{Key: string(pillartypes.LocationCloudInterval), Value: "300"},
		{Key: string(pillartypes.AllowLogFastupload), Value: "true"},
		{Key: string(pillartypes.DownloadRetryTime), Value: "60"},

		// Reduce the post-upgrade testing period so upgrades complete faster in tests.
		{Key: string(pillartypes.MintimeUpdateSuccess), Value: "60"},
	}

	// Do not overwrite test-defined values.
	for _, item := range defaultConfigItems {
		if !hasConfigKey(dc.ConfigItems, item.Key) {
			dc.ConfigItems = append(dc.ConfigItems, item)
		}
	}
}

func (dc *EdgeDeviceConfig) checkVLANNetwork(th *TestHarness,
	config VLANSubinterfaceConfig) {
	if config.NetworkUUID == NilUUID {
		return
	}
	netID := config.NetworkUUID.String()
	var netconfig *eveconfig.NetworkConfig
	for _, network := range dc.Networks {
		if network.Id == netID {
			netconfig = network
			break
		}
	}
	if netconfig == nil {
		th.t.Fatalf(
			"Network %q referenced by VLAN subinterface %q does not exist",
			netID, config.LogicalLabel)
	}
	return
}

func (dc *EdgeDeviceConfig) checkVLANParent(
	th *TestHarness, config VLANSubinterfaceConfig) {
	if config.ParentLogicalLabel == "" {
		th.t.Fatalf("VLAN subinterface %q with empty parent logical label",
			config.LogicalLabel)
	}
	// Parent can be a PhysicalIO (ethernet NIC).
	for _, physIO := range dc.DeviceIoList {
		if physIO.Logicallabel == config.ParentLogicalLabel {
			if physIO.Ptype != evecommon.PhyIoType_PhyIoNetEth {
				th.t.Fatalf("VLAN %q parent adapter with logical label %q "+
					"is not ethernet NIC (instead it is %s)",
					config.LogicalLabel, config.ParentLogicalLabel, physIO.Ptype.String())
			}
			return
		}
	}
	// Parent can also be a BondAdapter.
	for _, bond := range dc.Bonds {
		if bond.Logicallabel == config.ParentLogicalLabel {
			return
		}
	}
	th.t.Fatalf("VLAN %q parent adapter with logical label %q was not found",
		config.LogicalLabel, config.ParentLogicalLabel)
}

// AddVLANSubinterface adds a VLAN subinterface to the device configuration.
func (dc *EdgeDeviceConfig) AddVLANSubinterface(config VLANSubinterfaceConfig) {
	for _, vlan := range dc.Vlans {
		if vlan.Logicallabel == config.LogicalLabel {
			dc.th.t.Fatalf("VLAN subinterface %q already exist", config.LogicalLabel)
		}
	}
	for _, adapter := range dc.SystemAdapterList {
		if adapter.Name == config.LogicalLabel {
			dc.th.t.Fatalf("VLAN subinterface logical label %q is already in use "+
				"by a network adapter", config.LogicalLabel)
		}
	}
	for _, bond := range dc.Bonds {
		if bond.Logicallabel == config.LogicalLabel {
			dc.th.t.Fatalf("VLAN subinterface logical label %q is already in use "+
				"by a bond adapter", config.LogicalLabel)
		}
	}
	dc.checkVLANNetwork(dc.th, config)
	dc.checkVLANParent(dc.th, config)
	dc.Vlans = append(dc.Vlans, config.toVlanAdapterProto())
	if config.NetworkUUID != NilUUID {
		dc.SystemAdapterList = append(dc.SystemAdapterList, config.toSystemAdapterProto())
	}
}

// UpdateVLANSubinterface updates an existing VLAN subinterface identified
// by its logical label.
func (dc *EdgeDeviceConfig) UpdateVLANSubinterface(config VLANSubinterfaceConfig) {
	dc.checkVLANNetwork(dc.th, config)
	dc.checkVLANParent(dc.th, config)
	var found bool
	for i, vlan := range dc.Vlans {
		if vlan.Logicallabel == config.LogicalLabel {
			dc.Vlans[i] = config.toVlanAdapterProto()
			found = true
			break
		}
	}
	if !found {
		dc.th.t.Fatalf("VLAN subinterface with logical label %q was not found",
			config.LogicalLabel)
	}

	// Update or remove SystemAdapter.
	sysAdapterIdx := -1
	for i, adapter := range dc.SystemAdapterList {
		if adapter.Name == config.LogicalLabel {
			sysAdapterIdx = i
			break
		}
	}
	if config.NetworkUUID != NilUUID {
		if sysAdapterIdx >= 0 {
			dc.SystemAdapterList[sysAdapterIdx] = config.toSystemAdapterProto()
		} else {
			dc.SystemAdapterList = append(dc.SystemAdapterList,
				config.toSystemAdapterProto())
		}
	} else if sysAdapterIdx >= 0 {
		dc.SystemAdapterList = append(
			dc.SystemAdapterList[:sysAdapterIdx],
			dc.SystemAdapterList[sysAdapterIdx+1:]...)
	}
}

// DeleteVLANSubinterface removes a VLAN subinterface identified by its
// logical label from the device configuration.
func (dc *EdgeDeviceConfig) DeleteVLANSubinterface(logicalLabel string) {
	found := false
	for i, vlan := range dc.Vlans {
		if vlan.Logicallabel == logicalLabel {
			dc.Vlans = append(dc.Vlans[:i], dc.Vlans[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		dc.th.t.Fatalf("VLAN subinterface with logical label %q was not found",
			logicalLabel)
	}
	for i, adapter := range dc.SystemAdapterList {
		if adapter.Name == logicalLabel {
			dc.SystemAdapterList = append(
				dc.SystemAdapterList[:i], dc.SystemAdapterList[i+1:]...)
			break
		}
	}
}

// checkBondMembers validates that all member logical labels refer to
// existing PhysicalIO entries of type PhyIoNetEth and that no member
// is already used by another bond.
func (dc *EdgeDeviceConfig) checkBondMembers(config BondConfig) {
	if len(config.MemberLabels) < 2 {
		dc.th.t.Fatalf("Bond %q must have at least 2 members, got %d",
			config.LogicalLabel, len(config.MemberLabels))
	}
	for _, memberLL := range config.MemberLabels {
		found := false
		for _, physIO := range dc.DeviceIoList {
			if physIO.Logicallabel == memberLL {
				if physIO.Ptype != evecommon.PhyIoType_PhyIoNetEth {
					dc.th.t.Fatalf("Bond %q member %q is not ethernet NIC (it is %s)",
						config.LogicalLabel, memberLL, physIO.Ptype.String())
				}
				found = true
				break
			}
		}
		if !found {
			dc.th.t.Fatalf("Bond %q member %q was not found in DeviceIoList",
				config.LogicalLabel, memberLL)
		}
		for _, bond := range dc.Bonds {
			if bond.Logicallabel == config.LogicalLabel {
				continue
			}
			for _, existing := range bond.LowerLayerNames {
				if existing == memberLL {
					dc.th.t.Fatalf("Bond %q member %q is already used by bond %q",
						config.LogicalLabel, memberLL, bond.Logicallabel)
				}
			}
		}
	}
}

// checkBondNetwork validates that the network referenced by the bond exists.
func (dc *EdgeDeviceConfig) checkBondNetwork(config BondConfig) {
	if config.NetworkUUID == NilUUID {
		return
	}
	netID := config.NetworkUUID.String()
	for _, network := range dc.Networks {
		if network.Id == netID {
			return
		}
	}
	dc.th.t.Fatalf("Network %q referenced by bond %q does not exist",
		netID, config.LogicalLabel)
}

// AddBond adds a bond (link aggregation) interface to the device configuration.
func (dc *EdgeDeviceConfig) AddBond(config BondConfig) {
	for _, bond := range dc.Bonds {
		if bond.Logicallabel == config.LogicalLabel {
			dc.th.t.Fatalf("Bond %q already exists", config.LogicalLabel)
		}
	}
	for _, adapter := range dc.SystemAdapterList {
		if adapter.Name == config.LogicalLabel {
			dc.th.t.Fatalf("Bond logical label %q is already in use "+
				"by a network adapter", config.LogicalLabel)
		}
	}
	for _, vlan := range dc.Vlans {
		if vlan.Logicallabel == config.LogicalLabel {
			dc.th.t.Fatalf("Bond logical label %q is already in use "+
				"by a VLAN adapter", config.LogicalLabel)
		}
	}
	dc.checkBondMembers(config)
	dc.checkBondNetwork(config)
	dc.Bonds = append(dc.Bonds, config.toBondAdapterProto())
	if config.NetworkUUID != NilUUID {
		dc.SystemAdapterList = append(dc.SystemAdapterList, config.toSystemAdapterProto())
	}
}

// UpdateBond updates an existing bond identified by its logical label.
func (dc *EdgeDeviceConfig) UpdateBond(config BondConfig) {
	dc.checkBondMembers(config)
	dc.checkBondNetwork(config)
	var found bool
	for i, bond := range dc.Bonds {
		if bond.Logicallabel == config.LogicalLabel {
			dc.Bonds[i] = config.toBondAdapterProto()
			found = true
			break
		}
	}
	if !found {
		dc.th.t.Fatalf("Bond with logical label %q was not found",
			config.LogicalLabel)
	}

	// Update or remove SystemAdapter.
	sysAdapterIdx := -1
	for i, adapter := range dc.SystemAdapterList {
		if adapter.Name == config.LogicalLabel {
			sysAdapterIdx = i
			break
		}
	}
	if config.NetworkUUID != NilUUID {
		if sysAdapterIdx >= 0 {
			dc.SystemAdapterList[sysAdapterIdx] = config.toSystemAdapterProto()
		} else {
			dc.SystemAdapterList = append(dc.SystemAdapterList,
				config.toSystemAdapterProto())
		}
	} else if sysAdapterIdx >= 0 {
		dc.SystemAdapterList = append(
			dc.SystemAdapterList[:sysAdapterIdx],
			dc.SystemAdapterList[sysAdapterIdx+1:]...)
	}
}

// DeleteBond removes a bond identified by its logical label from the
// device configuration.
func (dc *EdgeDeviceConfig) DeleteBond(logicalLabel string) {
	found := false
	for i, bond := range dc.Bonds {
		if bond.Logicallabel == logicalLabel {
			dc.Bonds = append(dc.Bonds[:i], dc.Bonds[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		dc.th.t.Fatalf("Bond with logical label %q was not found",
			logicalLabel)
	}
	for i, adapter := range dc.SystemAdapterList {
		if adapter.Name == logicalLabel {
			dc.SystemAdapterList = append(
				dc.SystemAdapterList[:i], dc.SystemAdapterList[i+1:]...)
			break
		}
	}
}

// AddNetworkInstance adds a new network instance to the device configuration
// and returns its generated UUID.
func (dc *EdgeDeviceConfig) AddNetworkInstance(config NetworkInstanceConfig) uuid.UUID {
	niUUID := dc.th.newUUID("network instance")
	dc.addNetworkInstanceWithUUID(config, niUUID)
	return niUUID
}

// addNetworkInstanceWithUUID adds a network instance using a pre-generated UUID.
func (dc *EdgeDeviceConfig) addNetworkInstanceWithUUID(
	config NetworkInstanceConfig, niUUID uuid.UUID) {
	if config == nil {
		dc.th.t.Fatalf("Undefined network instance configuration")
	}
	protoConfig := config.toProto(dc.th, niUUID)
	dc.NetworkInstances = append(dc.NetworkInstances, protoConfig)
}

// UpdateNetworkInstance updates an existing network instance identified
// by its UUID.
func (dc *EdgeDeviceConfig) UpdateNetworkInstance(
	niUUID uuid.UUID, newConfig NetworkInstanceConfig) {
	if newConfig == nil {
		dc.th.t.Fatalf("Undefined network instance configuration")
	}
	uuidStr := niUUID.String()
	newProtoConfig := newConfig.toProto(dc.th, niUUID)
	for i, ni := range dc.NetworkInstances {
		if ni.Uuidandversion.Uuid == uuidStr {
			if ni.InstType != newProtoConfig.InstType {
				// Changing network instance type is not supported by EVE.
				dc.th.t.Fatalf("Changing network instance type is not supported")
			}
			dc.NetworkInstances[i] = newProtoConfig
			return
		}
	}
	dc.th.t.Fatalf("Network instance with UUID %q was not found", uuidStr)
}

// DeleteNetworkInstance removes a network instance identified by its UUID
// from the device configuration.
func (dc *EdgeDeviceConfig) DeleteNetworkInstance(niUUID uuid.UUID) {
	uuidStr := niUUID.String()
	for _, app := range dc.Apps {
		for _, intf := range app.Interfaces {
			if intf.NetworkId == uuidStr {
				dc.th.t.Fatalf("Cannot delete network instance %q: "+
					"it is currently in use by application %q",
					uuidStr, app.Displayname)
			}
		}
	}
	for i, ni := range dc.NetworkInstances {
		if ni.Uuidandversion.Uuid == uuidStr {
			// Remove the network instance from the slice
			dc.NetworkInstances = append(
				dc.NetworkInstances[:i], dc.NetworkInstances[i+1:]...)
			return
		}
	}
	dc.th.t.Fatalf("Network instance with UUID %q was not found", uuidStr)
}

// AddApplication adds a new application instance to the device configuration
// and returns its generated UUID.
func (dc *EdgeDeviceConfig) AddApplication(config ApplicationInstanceConfig) uuid.UUID {
	appUUID := dc.th.newUUID("application")
	volumeUUID := dc.th.newUUID("application volume")
	contentTreeUUID := dc.th.newUUID("application image content tree")
	datastoreUUID := dc.th.newUUID("application image datastore")
	dc.addApplicationWithUUIDs(config, appUUID, volumeUUID, contentTreeUUID, datastoreUUID)
	return appUUID
}

func (dc *EdgeDeviceConfig) addApplicationWithUUIDs(
	config ApplicationInstanceConfig,
	appUUID, volumeUUID, contentTreeUUID, datastoreUUID uuid.UUID) {
	for _, app2 := range dc.Apps {
		if app2.Displayname == config.DisplayName {
			dc.th.t.Fatalf("Application with DisplayName %q already exists",
				config.DisplayName)
		}
	}
	appInstConfig := config.toProto(dc.th, dc.DeviceName, appUUID, volumeUUID)
	dc.Apps = append(dc.Apps, appInstConfig)

	// Create Volume, ContentTree and Datastore configs for the application image.
	if config.Image == nil {
		dc.th.t.Fatalf("Application %q is missing image definition",
			config.DisplayName)
	}
	dc.Volumes = append(dc.Volumes, &eveconfig.Volume{
		Uuid: volumeUUID.String(),
		Origin: &eveconfig.VolumeContentOrigin{
			Type:                  eveconfig.VolumeContentOriginType_VCOT_DOWNLOAD,
			DownloadContentTreeID: contentTreeUUID.String(),
		},
		Maxsizebytes: int64(config.DiskBytes),
		DisplayName:  config.DisplayName + "-root",
	})
	contentTree, dsConfig := config.Image.toProto(dc.th, dc.log, dc.DeviceName,
		contentTreeUUID, datastoreUUID, config.DisplayName)
	dc.ContentInfo = append(dc.ContentInfo, contentTree)
	dc.Datastores = append(dc.Datastores, dsConfig)
}

// UpdateApplication updates an existing application instance identified
// by its UUID.
func (dc *EdgeDeviceConfig) UpdateApplication(
	appUUID uuid.UUID, newConfig ApplicationInstanceConfig) {
	// For now, we will only allow to change Activation flag, profile list and adapters.
	for i, app := range dc.Apps {
		if app.Uuidandversion.Uuid == appUUID.String() {
			newProtoConfig := newConfig.toProto(dc.th, dc.DeviceName, appUUID, NilUUID)
			if app.Displayname != newProtoConfig.Displayname {
				dc.th.t.Fatalf("It is not allowed to change application DisplayName")
			}
			if !proto.Equal(app.Fixedresources, newProtoConfig.Fixedresources) {
				dc.th.t.Fatalf("It is not allowed to change application Fixedresources")
			}
			var needRestart bool
			equalAdapter := func(a1, a2 *eveconfig.Adapter) bool {
				return proto.Equal(a1, a2)
			}
			if !generics.EqualSetsFn(app.Adapters, newProtoConfig.Adapters, equalAdapter) {
				needRestart = true
			}
			equalNetAdapter := func(a1, a2 *eveconfig.NetworkAdapter) bool {
				return proto.Equal(a1, a2)
			}
			if !generics.EqualSetsFn(app.Interfaces, newProtoConfig.Interfaces, equalNetAdapter) {
				needRestart = true
			}
			if needRestart {
				if app.Restart == nil {
					app.Restart = &eveconfig.InstanceOpsCmd{Counter: 0}
				}
				app.Restart.Counter++
			}
			dc.Apps[i].Activate = newProtoConfig.Activate
			dc.Apps[i].ProfileList = newProtoConfig.ProfileList
			dc.Apps[i].Adapters = newProtoConfig.Adapters
			dc.Apps[i].Interfaces = newProtoConfig.Interfaces
			return
		}
	}
	dc.th.t.Fatalf("Application instance with UUID %q was not found",
		appUUID.String())
}

// DeleteApplication removes an application instance identified by its UUID
// and cleans up all associated resources.
func (dc *EdgeDeviceConfig) DeleteApplication(appUUID uuid.UUID) {
	var found bool
	var volumeRefs []*eveconfig.VolumeRef
	uuidStr := appUUID.String()
	for i, app := range dc.Apps {
		if app.Uuidandversion.Uuid == uuidStr {
			volumeRefs = app.VolumeRefList
			// Remove the application instance from the slice.
			dc.Apps = append(dc.Apps[:i], dc.Apps[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		dc.th.t.Fatalf("Application instance with UUID %q was not found", uuidStr)
	}

	// Remove volumes for the app.
	var contentTreeIDs []string
	for _, volumeRef := range volumeRefs {
		for i, volume := range dc.Volumes {
			if volume.Uuid == volumeRef.Uuid {
				if volume.Origin.Type == eveconfig.VolumeContentOriginType_VCOT_DOWNLOAD {
					contentTreeIDs = append(contentTreeIDs,
						volume.Origin.DownloadContentTreeID)
				}
				// Remove the volume from the slice.
				dc.Volumes = append(dc.Volumes[:i], dc.Volumes[i+1:]...)
				break
			}
		}
	}

	// Remove content trees created for the app.
	var datastoreIDs []string
	for _, contentTreeID := range contentTreeIDs {
		for i, contentTree := range dc.ContentInfo {
			if contentTree.Uuid == contentTreeID {
				datastoreIDs = append(datastoreIDs, contentTree.DsIdsList...)
				// Remove the content tree from the slice.
				dc.ContentInfo = append(dc.ContentInfo[:i], dc.ContentInfo[i+1:]...)
				break
			}
		}
	}

	// Remove datastore configs created for the app.
	for _, datastoreID := range datastoreIDs {
		for i, datastore := range dc.Datastores {
			if datastore.Id == datastoreID {
				// Remove the datastore config from the slice.
				dc.Datastores = append(dc.Datastores[:i], dc.Datastores[i+1:]...)
				break
			}
		}
	}
}

// AddBlankVolume adds a standalone empty (VCOT_BLANK) volume of the requested
// size to the device configuration and returns its UUID.
//
// A blank volume is created by volumemgr as an empty block device of the given
// size, with no content downloaded into it and no application reference
// required (volumemgr creates standalone volumes; see the
// VolumeConfig.HasNoAppReferences handling in volumemgr). On a device whose
// /persist is ZFS, a non-container, non-ISO volume is backed by a ZFS zvol
// whose "volsize" property equals sizeBytes (rounded up to the ZFS
// volblocksize). That volsize is the provisioned size volumemgr reports in
// AppDiskMetric.ProvisionedBytes, which zedagent surfaces to the controller as
// ZMetricVolume.TotalBytes and VolumeResources.MaxSizeBytes.
//
// The volume is created in clear text so that it does not depend on the vault
// being unlocked, keeping the volume-creation path independent of vault
// readiness.
func (dc *EdgeDeviceConfig) AddBlankVolume(
	displayName string, sizeBytes uint64) uuid.UUID {
	volumeUUID := dc.th.newUUID("blank volume")
	dc.Volumes = append(dc.Volumes, &eveconfig.Volume{
		Uuid: volumeUUID.String(),
		Origin: &eveconfig.VolumeContentOrigin{
			Type: eveconfig.VolumeContentOriginType_VCOT_BLANK,
		},
		Maxsizebytes: int64(sizeBytes),
		DisplayName:  displayName,
		ClearText:    true,
	})
	return volumeUUID
}

// SetLPS configures the Local Profile Server (LPS) settings for the device.
func (dc *EdgeDeviceConfig) SetLPS(config LPSConfig) {
	dc.GlobalProfile = config.GlobalProfile
	dc.LocalProfileServer = config.Address
	dc.ProfileServerToken = config.AuthToken
}

// AddSCEPProfile adds a new SCEP profile into the device configuration.
func (dc *EdgeDeviceConfig) AddSCEPProfile(profile SCEPProfile) {
	for _, existingProfile := range dc.ScepProfiles {
		if existingProfile.ProfileName == profile.Name {
			dc.th.t.Fatalf("SCEP profile with name %q already exists",
				profile.Name)
		}
	}
	dc.ScepProfiles = append(dc.ScepProfiles, profile.toProto(dc.th, dc.DeviceName))
}

// UpdateSCEPProfile updates an existing SCEP profile.
func (dc *EdgeDeviceConfig) UpdateSCEPProfile(profile SCEPProfile) {
	var found bool
	for i, existingProfile := range dc.ScepProfiles {
		if existingProfile.ProfileName == profile.Name {
			dc.ScepProfiles[i] = profile.toProto(dc.th, dc.DeviceName)
			found = true
			break
		}
	}
	if !found {
		dc.th.t.Fatalf("SCEP profile with name %q was not found", profile.Name)
	}
}

// DeleteSCEPProfile removes SCEP profile from the device configuration.
func (dc *EdgeDeviceConfig) DeleteSCEPProfile(profileName string) {
	var found bool
	for i, profile := range dc.ScepProfiles {
		if profile.ProfileName == profileName {
			dc.ScepProfiles = append(dc.ScepProfiles[:i], dc.ScepProfiles[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		dc.th.t.Fatalf("SCEP profile with name %q was not found", profileName)
	}
}

// SetBaseOS configures an EVE OS upgrade from the given image storage source.
// shortVersion is the full EVE short version string (e.g. "12.1.0-kvm-amd64")
// that EVE will report in ZInfoDevSW.ShortVersion after the upgrade.
// Calling this again on the same config replaces the previously set BaseOS entry.
func (dc *EdgeDeviceConfig) SetBaseOS(storage ApplicationImageStorage, shortVersion string) {
	// Remove content tree and datastores from any previous SetBaseOS call.
	if dc.Baseos != nil {
		prevContentTreeUUID := dc.Baseos.ContentTreeUuid
		var prevDsUUIDs []string
		dc.ContentInfo = generics.FilterList(dc.ContentInfo,
			func(ct *eveconfig.ContentTree) bool {
				if ct.Uuid == prevContentTreeUUID {
					prevDsUUIDs = ct.DsIdsList
					return false
				}
				return true
			})
		dc.Datastores = generics.FilterList(dc.Datastores,
			func(ds *eveconfig.DatastoreConfig) bool {
				return !generics.ContainsItem(prevDsUUIDs, ds.Id)
			})
	}
	contentTreeUUID := dc.th.newUUID("baseos content tree")
	datastoreUUID := dc.th.newUUID("baseos datastore")
	contentTree, dsConfig := storage.toProto(dc.th, dc.log, dc.DeviceName,
		contentTreeUUID, datastoreUUID, "eve baseos")
	dc.ContentInfo = append(dc.ContentInfo, contentTree)
	dc.Datastores = append(dc.Datastores, dsConfig)
	dc.Baseos = &eveconfig.BaseOS{
		ContentTreeUuid: contentTreeUUID.String(),
		Activate:        true,
		BaseOsVersion:   shortVersion,
	}
}
