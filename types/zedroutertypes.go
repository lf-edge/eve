// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"io/ioutil"
	"log"
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

func (config AppNetworkConfig) VerifyFilename(fileName string) bool {
	uuid := config.UUIDandVersion.UUID
	ret := uuid.String()+".json" == fileName
	if !ret {
		log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, uuid.String())
	}
	return ret
}

func (status AppNetworkStatus) CheckPendingAdd() bool {
	return status.PendingAdd
}

func (status AppNetworkStatus) CheckPendingModify() bool {
	return status.PendingModify
}

func (status AppNetworkStatus) CheckPendingDelete() bool {
	return status.PendingDelete
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

func (status AppNetworkStatus) VerifyFilename(fileName string) bool {
	uuid := status.UUIDandVersion.UUID
	ret := uuid.String()+".json" == fileName
	if !ret {
		log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, uuid.String())
	}
	return ret
}

// Global network config and status
type DeviceNetworkConfig struct {
	Uplink      []string // ifname; all uplinks
	FreeUplinks []string // subset used for image downloads
}

type NetworkUplink struct {
	IfName string
	Addrs  []net.IP
}

type DeviceNetworkStatus struct {
	UplinkStatus []NetworkUplink
}

// Parse the file with DeviceNetworkConfig
func GetGlobalNetworkConfig(configFilename string) (DeviceNetworkConfig, error) {
	var globalConfig DeviceNetworkConfig
	cb, err := ioutil.ReadFile(configFilename)
	if err != nil {
		return DeviceNetworkConfig{}, err
	}
	if err := json.Unmarshal(cb, &globalConfig); err != nil {
		return DeviceNetworkConfig{}, err
	}
	// Workaround for old config with FreeUplinks not set
	if len(globalConfig.FreeUplinks) == 0 {
		fmt.Printf("Setting FreeUplinks from Uplink: %v\n",
				globalConfig.Uplink)
		globalConfig.FreeUplinks = globalConfig.Uplink
	}
	return globalConfig, nil
}

// Calculate local IP addresses to make a DeviceNetworkStatus
func MakeGlobalNetworkStatus(globalConfig DeviceNetworkConfig) (DeviceNetworkStatus, error) {
	var globalStatus DeviceNetworkStatus
	globalStatus.UplinkStatus = make([]NetworkUplink,
		len(globalConfig.Uplink))
	for ix, u := range globalConfig.Uplink {
		globalStatus.UplinkStatus[ix].IfName = u
		link, err := netlink.LinkByName(u)
		if err != nil {
			return DeviceNetworkStatus{}, errors.New(fmt.Sprintf("Uplink in config/global does not exist: %v", u))
		}
		addrs4, err := netlink.AddrList(link, netlink.FAMILY_V4)
		addrs6, err := netlink.AddrList(link, netlink.FAMILY_V6)
		globalStatus.UplinkStatus[ix].Addrs = make([]net.IP,
			len(addrs4)+len(addrs6))
		for i, addr := range addrs4 {
			fmt.Printf("UplinkAddrs(%s) found IPv4 %v\n",
				u, addr.IP)
			globalStatus.UplinkStatus[ix].Addrs[i] = addr.IP
		}
		for i, addr := range addrs6 {
			// We include link-locals since they can be used for LISP behind nats
			fmt.Printf("UplinkAddrs(%s) found IPv6 %v\n",
				u, addr.IP)
			globalStatus.UplinkStatus[ix].Addrs[i+len(addrs4)] = addr.IP
		}
	}
	return globalStatus, nil
}

// Pick from one of the uplinks
func GetLocalAddrAny(globalConfig DeviceNetworkConfig, globalStatus DeviceNetworkStatus, pickNum int) (net.IP, error) {
	// Count the number of addresses which apply
	numAddrs := 0
	for _, u := range globalConfig.Uplink {
		addrs, _ := getInterfaceAddr(globalStatus, u)
		numAddrs += len(addrs)
	}
	// fmt.Printf("GetLocalAddrAny pick %d have %d\n", pickNum, numAddrs)
	pickNum = pickNum % numAddrs
	for _, u := range globalConfig.Uplink {
		addrs, _ := getInterfaceAddr(globalStatus, u)
		for _, a := range addrs {
			if pickNum == 0 {
				// fmt.Printf("GetLocalAddrAny returning %v\n", a)
				return a, nil
			}
			pickNum -= 1
		}
	}
	return net.IP{}, errors.New("GetLocalAddrAny fell off end")
}

// Pick from one of the free uplinks
func GetLocalAddrFree(globalConfig DeviceNetworkConfig, globalStatus DeviceNetworkStatus, pickNum int) (net.IP, error) {
	// Count the number of addresses which apply
	numAddrs := 0
	for _, u := range globalConfig.FreeUplinks {
		addrs, _ := getInterfaceAddr(globalStatus, u)
		numAddrs += len(addrs)
	}
	// fmt.Printf("GetLocalAddrFree pick %d have %d\n", pickNum, numAddrs)
	pickNum = pickNum % numAddrs
	for _, u := range globalConfig.FreeUplinks {
		addrs, _ := getInterfaceAddr(globalStatus, u)
		for _, a := range addrs {
			if pickNum == 0 {
				// fmt.Printf("GetLocalAddrFree returning %v\n", a)
				return a, nil
			}
			pickNum -= 1
		}
	}
	return net.IP{}, errors.New("GetLocalAddrFree fell off end")
}

func getInterfaceAddr(globalStatus DeviceNetworkStatus, ifname string) ([]net.IP, error) {
	// fmt.Printf("getInterfaceAddr(%s)\n", ifname)
	for _, u := range globalStatus.UplinkStatus {
		if u.IfName == ifname {
			// fmt.Printf("getInterfaceAddr(%s) returning %v\n",
			//	ifname, u.Addrs)
			return u.Addrs, nil
		}
	}
	return []net.IP{}, errors.New("No good IP address")
}

type OverlayNetworkConfig struct {
	IID           uint32
	EID           net.IP
	LispSignature string
	// Any additional LISP parameters?
	ACLs          []ACE
	NameToEidList []NameToEid // Used to populate DNS for the overlay
	LispServers   []LispServerInfo
	// Optional additional informat
	AdditionalInfoDevice *AdditionalInfoDevice
}

type OverlayNetworkStatus struct {
	OverlayNetworkConfig
	VifInfo
}

type UnderlayNetworkConfig struct {
	ACLs []ACE
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
	Type  string
	Value string
}

type ACEAction struct {
	Drop       bool   // Otherwise accept
	Limit      bool   // Is limiter enabled?
	LimitRate  int    // Packets per unit
	LimitUnit  string // "s", "m", "h", for second, minute, hour
	LimitBurst int    // Packets
}

// Retrieved from geolocation service for device underlay connectivity
// XXX separate out lat/long as floats to be able to use GPS?
// XXX feed back to zedcloud in HwStatus
type AdditionalInfoDevice struct {
	UnderlayIP string
	Hostname   string `json:",omitempty"` // From reverse DNS
	City       string `json:",omitempty"`
	Region     string `json:",omitempty"`
	Country    string `json:",omitempty"`
	Loc        string `json:",omitempty"` // Lat and long as string
	Org        string `json:",omitempty"` // From AS number
}

// Tie the Application EID back to the device
type AdditionalInfoApp struct {
	DisplayName string
	DeviceEID   net.IP
	DeviceIID   uint32
	UnderlayIP  string
	Hostname    string `json:",omitempty"` // From reverse DNS
}
