// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"net"
)

// Indexed by UUID
// If IsZedmanager is set we do not create boN but instead configure the EID
// locally. This will go away once ZedManager runs in a domU like any
// application.
type AppNetworkConfig struct {
	UUIDandVersion      UUIDandVersion
	DisplayName         string
	IsZedmanager        bool
	OverlayNetworkList  []OverlayNetworkConfig
	UnderlayNetworkList []UnderlayNetworkConfig
}

// Indexed by UUID
type AppNetworkStatus struct {
	UUIDandVersion UUIDandVersion
	AppNum         int
	PendingAdd     bool
	PendingModify  bool
	PendingDelete  bool
	UlNum          int // Number of underlay interfaces
	OlNum          int // Number of overlay interfaces
	DisplayName    string
	// Copy from the AppNetworkConfig; used to delete when config is gone.
	IsZedmanager        bool
	OverlayNetworkList  []OverlayNetworkStatus
	UnderlayNetworkList []UnderlayNetworkStatus
}

// Do we want a DeviceNetworkStatus? DeviceNetworkConfig with the underlay
// interfaces?
type DeviceNetworkConfig struct {
	Uplink string // ifname; should have multiple
	// XXX WiFi credentials?? Should already be set?
}

type DeviceNetworkStatus struct {
	Uplink          string // ifname; should have multiple
	// XXX add all the uplink ifaddrs?
	// XXX uplink publicAddr to determine NATed?
}

type OverlayNetworkConfig struct {
	IID		uint32
	EID		net.IP
	LispSignature	string
	// Any additional LISP parameters?
	ACLs		[]ACE
	NameToEidList	[]NameToEid	// Used to populate DNS for the overlay
	// Optional additional informat
	AdditionalInfoDevice	*AdditionalInfoDevice
}

type OverlayNetworkStatus struct {
	OverlayNetworkConfig
	VifInfo
}

type UnderlayNetworkConfig struct {
	ACLs		[]ACE
}

type UnderlayNetworkStatus struct {
	UnderlayNetworkConfig
	VifInfo
}

// Similar support as in draft-ietf-netmod-acl-model
type ACE struct {
	Matches []ACEMatch
	Actions []ACEAction
}

// The Type can be "ip" or "host" (aka domain name) for now. Matches remote.
// For now these are bidirectional.
// The host matching is suffix-matching thus zededa.net matches *.zededa.net.
// Can envision adding "protocol", "fport", "lport", and directionality at least
// Value is always a string.
// There is an implicit reject rule at the end.
// The "eidset" type is special for the overlay. Matches all the EID which
// are part of the NameToEidList.
type ACEMatch struct {
	Type string
	Value string     	
}

type ACEAction struct {
	Drop		bool	// Otherwise accept
	Limit		bool	// Is limiter enabled?
	LimitRate	int	// Packets per unit
	LimitUnit	string	// "s", "m", "h", for second, minute, hour
	LimitBurst	int	// Packets
}

// Retrieved from geolocation service for device underlay connectivity
// XXX separate out lat/long as floats to be able to use GPS?
// XXX feed back to zedcloud in HwStatus
type AdditionalInfoDevice struct {
	UnderlayIP	string
	Hostname	string	`json:",omitempty"` // From reverse DNS
	City		string	`json:",omitempty"`
	Region		string	`json:",omitempty"`
	Country		string	`json:",omitempty"`
	Loc		string	`json:",omitempty"` // Lat and long as string
	Org		string	`json:",omitempty"` // From AS number
}

// Tie the Application EID back to the device
type AdditionalInfoApp struct {
	DisplayName	string
	DeviceEID	net.IP
	DeviceIID	uint32
	UnderlayIP	string
	Hostname	string	`json:",omitempty"` // From reverse DNS
}
