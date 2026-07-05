// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

// This file models the TUI->device write path. The TUI sends a small, well
// typed intent describing what one interface should look like; the device-side
// mapper merges it into the live port config. The TUI never reconstructs the
// whole (branch-variant) DevicePortConfig.

// IPMode is how an interface obtains its IP configuration. It replaces EVE's
// uint8 Dhcp field with a tagged union so the static parameters only exist when
// they are meaningful.
//
//monitorapi:union tag=mode
type IPMode interface{ isIPMode() }

// IPDhcp — obtain configuration via DHCP. Serializes as {"mode":"dhcp"}.
type IPDhcp struct{}

// IPStatic — static configuration carried as the validated StaticIPConfig.
type IPStatic struct {
	Config StaticIPConfig `json:"config"`
}

func (IPDhcp) isIPMode()   {}
func (IPStatic) isIPMode() {}

// SetInterfaceConfig asks the device to change one interface's IP and proxy
// configuration. The device merges it into the current port config for the
// named interface and applies it as the manual DPC.
type SetInterfaceConfig struct {
	Iface  string        `json:"iface"`
	IP     IPMode        `json:"ip"`
	Proxy  ProxySettings `json:"proxy"`
	NTP    []string      `json:"ntp,omitempty"`
	Domain string        `json:"domain,omitempty"`
}

// RevertManualConfig asks the device to discard the "manual" (TUI-submitted)
// DevicePortConfig, falling back to the next-highest-priority one. It has no
// fields of its own; it exists only so the request carries a well-typed
// (empty) payload, consistent with every other request in this package.
type RevertManualConfig struct{}
