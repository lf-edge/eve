// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

import "net/netip"

// NetworkStatus is the current device network state shown by the TUI. Physical
// ports are top-level; VLAN sub-interfaces are nested under their parent so the
// TUI never has to correlate them by name (the Go mapper builds the tree).
//
// This reflects status (DeviceNetworkStatus), not configuration — DevicePortConfig
// is only used for the write path (changing the network config).
type NetworkStatus struct {
	// DPCKey identifies the active device port configuration ("manual" for a
	// locally-applied config). The TUI uses it to tell apart controller vs
	// manual configuration.
	DPCKey     string             `json:"dpcKey"`
	Interfaces []NetworkInterface `json:"interfaces,omitempty"`
}

// NetworkInterface is a physical network port.
type NetworkInterface struct {
	Name   string `json:"name"`  // kernel interface name, e.g. "eth0"
	Label  string `json:"label"` // logical (human) label
	MAC    string `json:"mac"`   // "aa:bb:cc:dd:ee:ff" or empty
	Up     bool   `json:"up"`
	IsMgmt bool   `json:"isMgmt"`
	Cost   uint8  `json:"cost"`

	Media   NetworkMedia `json:"media"`
	Network PortNetwork  `json:"network"`
	// VLANs are the VLAN sub-interfaces attached to this port.
	VLANs []VLAN `json:"vlans,omitempty"`
}

// VLAN is a VLAN sub-interface attached to a NetworkInterface.
type VLAN struct {
	ID     uint16 `json:"id"`
	Name   string `json:"name"`  // kernel interface name, e.g. "eth0.100"
	Label  string `json:"label"` // logical (human) label
	Up     bool   `json:"up"`
	IsMgmt bool   `json:"isMgmt"`

	Network PortNetwork `json:"network"`
}

// PortNetwork is the L3 state shared by physical ports and VLAN sub-interfaces.
type PortNetwork struct {
	IsDHCP     bool          `json:"isDhcp"`
	IPv4       []netip.Addr  `json:"ipv4,omitempty"`
	IPv6       []netip.Addr  `json:"ipv6,omitempty"`
	Subnet     *netip.Prefix `json:"subnet,omitempty"`
	Routes     []netip.Addr  `json:"routes,omitempty"`
	DNSServers []netip.Addr  `json:"dnsServers,omitempty"`
	// NTPServers combines DHCP-provided and configured servers; each may be an
	// IP or a hostname, so they are carried as strings.
	NTPServers []string      `json:"ntpServers,omitempty"`
	Domain     string        `json:"domain"`
	Proxy      ProxySettings `json:"proxy"`
	Errors     []string      `json:"errors,omitempty"`
}

// NetworkMedia is a tagged union describing the physical medium of a port.
//
//monitorapi:union tag=kind
type NetworkMedia interface{ isNetworkMedia() }

// MediaEthernet is a wired port.
type MediaEthernet struct{}

// MediaWifi is a Wi-Fi port.
type MediaWifi struct {
	SSID string `json:"ssid"`
}

// MediaCellular is a cellular modem port. Most fields reflect live modem
// status; APN comes from the applied access-point config.
type MediaCellular struct {
	Modem    string `json:"modem"` // model or module name
	IMEI     string `json:"imei"`
	Operator string `json:"operator"` // currently-serving provider
	Roaming  bool   `json:"roaming"`
	// RATs are the radio access technologies currently in use, e.g. ["LTE"].
	RATs []string `json:"rats,omitempty"`
	// SIMs has one entry per SIM slot.
	SIMs []SIM `json:"sims,omitempty"`
	// VisibleProviders are all operators the modem can currently detect.
	VisibleProviders []CellProvider `json:"visibleProviders,omitempty"`
}

// SIM describes one cellular SIM slot.
type SIM struct {
	Slot      uint32 `json:"slot"`
	Activated bool   `json:"activated"`
	State     string `json:"state"`
	APN       string `json:"apn"`
	ICCID     string `json:"iccid"`
	IMSI      string `json:"imsi"`
}

// CellProvider is a detectable cellular network operator.
type CellProvider struct {
	PLMN        string `json:"plmn"`
	Description string `json:"description"`
	Forbidden   bool   `json:"forbidden"`
}

func (MediaEthernet) isNetworkMedia() {}
func (MediaWifi) isNetworkMedia()     {}
func (MediaCellular) isNetworkMedia() {}
