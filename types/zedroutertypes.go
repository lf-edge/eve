// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"encoding/json"
	"errors"
	"github.com/eriknordmark/ipinfo"
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
	SeparateDataPlane   bool
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
	SeparateDataPlane     bool
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
	IfName       string
	Free         bool
	AddrInfoList []AddrInfo
}

type AddrInfo struct {
	Addr net.IP
	Geo  ipinfo.IPInfo
}

type DeviceNetworkStatus struct {
	UplinkStatus []NetworkUplink
}

// Pick one of the uplinks
func GetUplinkAny(globalStatus DeviceNetworkStatus, pickNum int) (string, error) {
	if len(globalStatus.UplinkStatus) == 0 {
		return "", errors.New("GetUplinkAny has no uplink")
	}
	pickNum = pickNum % len(globalStatus.UplinkStatus)
	return globalStatus.UplinkStatus[pickNum].IfName, nil
}

// Pick one of the free uplinks
func GetUplinkFree(globalStatus DeviceNetworkStatus, pickNum int) (string, error) {
	count := 0
	for _, us := range globalStatus.UplinkStatus {
		if us.Free {
			count += 1
		}
	}
	if count == 0 {
		return "", errors.New("GetUplinkFree has no uplink")
	}
	pickNum = pickNum % count
	for _, us := range globalStatus.UplinkStatus {
		if us.Free {
			if pickNum == 0 {
				return us.IfName, nil
			}
			pickNum -= 1
		}
	}
	return "", errors.New("GetUplinkFree past end")
}

// Return all free uplink interfaces
func GetUplinksFree(globalStatus DeviceNetworkStatus, rotation int) []string {
	var uplinks []string

	for _, us := range globalStatus.UplinkStatus {
		if us.Free {
			uplinks = append(uplinks, us.IfName)
		}
	}
	return rotate(uplinks, rotation)
}

func rotate(arr []string, amount int) []string {
	if len(arr) == 0 {
		return []string{}
	}
	amount = amount % len(arr)
	return append(append([]string{}, arr[amount:]...), arr[:amount]...)
}

// Return all non-free uplink interfaces
func GetUplinksNonFree(globalStatus DeviceNetworkStatus, rotation int) []string {
	var uplinks []string

	for _, us := range globalStatus.UplinkStatus {
		if !us.Free {
			uplinks = append(uplinks, us.IfName)
		}
	}
	return rotate(uplinks, rotation)
}

// Return number of local IP addresses for all the uplinks, unless if
// uplink is set in which case we could it.
func CountLocalAddrAny(globalStatus DeviceNetworkStatus, uplink string) int {
	// Count the number of addresses which apply
	addrs, _ := getInterfaceAddr(globalStatus, false, uplink, true)
	return len(addrs)
}

// Return number of local IP addresses for all the free uplinks, unless if
// uplink is set in which case we could it.
func CountLocalAddrFree(globalStatus DeviceNetworkStatus, uplink string) int {
	// Count the number of addresses which apply
	addrs, _ := getInterfaceAddr(globalStatus, true, uplink, true)
	return len(addrs)
}

// Return number of local IP addresses for all the uplinks, unless if
// uplink is set in which case we could it.
func CountLocalAddrAnyNoLinkLocal(globalStatus DeviceNetworkStatus) int {
	// Count the number of addresses which apply
	addrs, _ := getInterfaceAddr(globalStatus, false, "", false)
	return len(addrs)
}

// Return a list of free uplinks that have non link local IP addresses
func GetUplinkFreeNoLocal(globalStatus DeviceNetworkStatus) ([]NetworkUplink) {
	// Return Uplink list with valid non link local addresses
	links, _ := getInterfaceAndAddr(globalStatus, true, "", false)
	return links
}

// Return number of local IP addresses for all the free uplinks, unless if
// uplink is set in which case we could it.
func CountLocalAddrFreeNoLinkLocal(globalStatus DeviceNetworkStatus) int {
	// Count the number of addresses which apply
	addrs, _ := getInterfaceAddr(globalStatus, true, "", false)
	return len(addrs)
}

// Pick one address from all of the uplinks, unless if uplink is set in which we
// pick from that uplink
// We put addresses from the free uplinks first in the list i.e., returned
// for the lower 'pickNum'
func GetLocalAddrAny(globalStatus DeviceNetworkStatus, pickNum int, uplink string) (net.IP, error) {
	// Count the number of addresses which apply
	addrs, err := getInterfaceAddr(globalStatus, false, uplink, true)
	if err != nil {
		return net.IP{}, err
	}
	numAddrs := len(addrs)
	pickNum = pickNum % numAddrs
	return addrs[pickNum], nil
}

// Pick one address from all of the free uplinks, unless if uplink is set
// in which we pick from that uplink
func GetLocalAddrFree(globalStatus DeviceNetworkStatus, pickNum int, uplink string) (net.IP, error) {
	// Count the number of addresses which apply
	addrs, err := getInterfaceAddr(globalStatus, true, uplink, true)
	if err != nil {
		return net.IP{}, err
	}
	numAddrs := len(addrs)
	pickNum = pickNum % numAddrs
	return addrs[pickNum], nil
}

func getInterfaceAndAddr(globalStatus DeviceNetworkStatus, free bool, ifname string,
	includeLinkLocal bool) ([]NetworkUplink, error) {
	var links []NetworkUplink
	for _, u := range globalStatus.UplinkStatus {
		if free && !u.Free {
			continue
		}
		// If ifname is set it should match
		if u.IfName != ifname && ifname != "" {
			continue
		}

		if includeLinkLocal {
			link := NetworkUplink {
				IfName: u.IfName,
				//Addrs: u.Addrs,
				AddrInfoList: u.AddrInfoList,
			}
			links = append(links, link)
		} else {
			var addrs []AddrInfo
			var link NetworkUplink
			link.IfName = u.IfName
			for _, a := range u.AddrInfoList {
				if !a.Addr.IsLinkLocalUnicast() {
					addrs = append(addrs, a)
				}
			}
			if len(addrs) > 0 {
				link.AddrInfoList = addrs
				links = append(links, link)
			}
		}
	}
	if len(links) != 0 {
		return links, nil
	} else {
		return []NetworkUplink{}, errors.New("No good Uplinks")
	}
}

// Check if an interface/adapter name is an uplink
func IsUplink(globalStatus DeviceNetworkStatus, ifname string) bool {
	for _, us := range globalStatus.UplinkStatus {
		if us.IfName == ifname {
			return true
		}
	}
	return false
}

func GetUplink(globalStatus DeviceNetworkStatus, ifname string) *NetworkUplink {
	for _, us := range globalStatus.UplinkStatus {
		if us.IfName == ifname {
			return &us
		}
	}
	return nil
}

// Given an address tell me its interface
func GetUplinkFromAddr(globalStatus DeviceNetworkStatus, addr net.IP) string {
	for _, u := range globalStatus.UplinkStatus {
		for _, i := range u.AddrInfoList {
			if i.Addr.Equal(addr) {
				return u.IfName
			}
		}
	}
	return ""
}

// Returns addresses based on free, ifname, and whether or not we want
// IPv6 link-locals.
// If free is not set, the addresses from the free uplinks are first.
func getInterfaceAddr(globalStatus DeviceNetworkStatus, free bool, ifname string, includeLinkLocal bool) ([]net.IP, error) {
	var freeAddrs []net.IP
	var nonfreeAddrs []net.IP
	for _, u := range globalStatus.UplinkStatus {
		if free && !u.Free {
			continue
		}
		// If ifname is set it should match
		if u.IfName != ifname && ifname != "" {
			continue
		}
		var addrs []net.IP
		for _, i := range u.AddrInfoList {
			if includeLinkLocal || !i.Addr.IsLinkLocalUnicast() {
				addrs = append(addrs, i.Addr)
			}
		}
		if free {
			freeAddrs = append(freeAddrs, addrs...)
		} else {
			nonfreeAddrs = append(nonfreeAddrs, addrs...)
		}
	}
	addrs := append(freeAddrs, nonfreeAddrs...)
	if len(addrs) != 0 {
		return addrs, nil
	} else {
		return []net.IP{}, errors.New("No good IP address")
	}
}

// Return list of interfaces we will report in info and metrics
// Always include dbo1x0 for now.
// Latter will move to a system app when we disaggregate
func ReportInterfaces(deviceNetworkStatus DeviceNetworkStatus) []string {
	var names []string
	names = append(names, "dbo1x0")
	for _, uplink := range deviceNetworkStatus.UplinkStatus {
		names = append(names, uplink.IfName)
	}
	return names
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

// Network metrics for overlay and underlay
// Matches networkMetrics protobuf message
type NetworkMetrics struct {
	MetricList []NetworkMetric
}

type NetworkMetric struct {
	IfName              string
	TxBytes             uint64
	RxBytes             uint64
	TxDrops             uint64
	RxDrops             uint64
	TxPkts              uint64
	RxPkts              uint64
	TxErrors            uint64
	RxErrors            uint64
	TxAclDrops          uint64 // For implicit deny/drop at end
	RxAclDrops          uint64 // For implicit deny/drop at end
	TxAclRateLimitDrops uint64 // For all rate limited rules
	RxAclRateLimitDrops uint64 // For all rate limited rules
}

// XXX this works but ugly as ...
// Alternative seems to be a deep walk with type assertions in order
// to produce the map of map of map with the correct type.
func CastNetworkMetrics(in interface{}) NetworkMetrics {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastNetworkMetrics")
	}
	var output NetworkMetrics
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastNetworkMetrics")
	}
	return output
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
