// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/eriknordmark/ipinfo"
	"github.com/eriknordmark/netlink"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Indexed by UUID
// If IsZedmanager is set we do not create boN but instead configure the EID
// locally. This will go away once ZedManager runs in a domU like any
// application.
type AppNetworkConfig struct {
	UUIDandVersion      UUIDandVersion
	DisplayName         string
	Activate            bool
	IsZedmanager        bool
	LegacyDataPlane     bool
	OverlayNetworkList  []OverlayNetworkConfig
	UnderlayNetworkList []UnderlayNetworkConfig
}

func (config AppNetworkConfig) Key() string {
	return config.UUIDandVersion.UUID.String()
}

func (config AppNetworkConfig) VerifyFilename(fileName string) bool {
	expect := config.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

func (config *AppNetworkConfig) getOverlayConfig(
	network uuid.UUID) *OverlayNetworkConfig {
	for i := range config.OverlayNetworkList {
		olConfig := &config.OverlayNetworkList[i]
		if olConfig.Network == network {
			return olConfig
		}
	}
	return nil
}

func (config *AppNetworkConfig) getUnderlayConfig(
	network uuid.UUID) *UnderlayNetworkConfig {
	for i := range config.UnderlayNetworkList {
		ulConfig := &config.UnderlayNetworkList[i]
		if ulConfig.Network == network {
			return ulConfig
		}
	}
	return nil
}

func (config *AppNetworkConfig) IsNetworkUsed(network uuid.UUID) bool {
	olConfig := config.getOverlayConfig(network)
	if olConfig != nil {
		return true
	}
	ulConfig := config.getUnderlayConfig(network)
	if ulConfig != nil {
		return true
	}
	// Network UUID matching neither UL nor OL network
	return false
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

func (status AppNetworkStatus) Pending() bool {
	return status.PendingAdd || status.PendingModify || status.PendingDelete
}

// Indexed by UUID
type AppNetworkStatus struct {
	UUIDandVersion UUIDandVersion
	AppNum         int
	Activated      bool
	PendingAdd     bool
	PendingModify  bool
	PendingDelete  bool
	DisplayName    string
	// Copy from the AppNetworkConfig; used to delete when config is gone.
	IsZedmanager        bool
	LegacyDataPlane     bool
	OverlayNetworkList  []OverlayNetworkStatus
	UnderlayNetworkList []UnderlayNetworkStatus
	MissingNetwork      bool // If any Missing flag is set in the networks
	// Any errros from provisioning the network
	Error     string
	ErrorTime time.Time
}

func (status AppNetworkStatus) Key() string {
	return status.UUIDandVersion.UUID.String()
}

func (status AppNetworkStatus) VerifyFilename(fileName string) bool {
	expect := status.Key() + ".json"
	ret := expect == fileName
	if !ret {
		log.Errorf("Mismatch between filename and contained uuid: %s vs. %s\n",
			fileName, expect)
	}
	return ret
}

// Array in timestamp aka priority order; first one is the most desired
// config to use
type DevicePortConfigList struct {
	CurrentIndex   int
	PortConfigList []DevicePortConfig
}

// A complete set of configuration for all the ports used by zedrouter on the
// device
type DevicePortConfig struct {
	Version      DevicePortConfigVersion
	Key          string
	TimePriority time.Time // All zero's is fallback lowest priority

	// Times when last ping test Failed/Succeeded.
	// All zeros means never tested.
	LastFailed    time.Time
	LastSucceeded time.Time
	LastError     string // Set when LastFailed is updated

	Ports []NetworkPortConfig
}

type DevicePortConfigVersion uint32

// GetPortByIfName - DevicePortConfig Methord to Get Port structure by IfName
func (portConfig *DevicePortConfig) GetPortByIfName(
	u string) (NetworkPortConfig, error) {
	var port NetworkPortConfig
	for _, port = range portConfig.Ports {
		if u == port.IfName {
			return port, nil
		}
	}
	err := fmt.Errorf("DevicePortConfig can't find port")
	return port, err
}

// When new fields and/or new semantics are added to DevicePortConfig a new
// version value is added here.
const (
	DPCInitial DevicePortConfigVersion = iota
	DPCIsMgmt                          // Require IsMgmt to be set for management ports
)

// DoSanitize -
func (portConfig *DevicePortConfig) DoSanitize(
	sanitizeTimePriority bool,
	sanitizeKey bool, key string,
	sanitizeName bool) {

	if sanitizeTimePriority {
		zeroTime := time.Time{}
		if portConfig.TimePriority == zeroTime {
			// If we can stat the file use its modify time
			filename := fmt.Sprintf("%s/DevicePortConfig/%s.json",
				TmpDirname, key)
			fi, err := os.Stat(filename)
			if err == nil {
				portConfig.TimePriority = fi.ModTime()
			} else {
				portConfig.TimePriority = time.Unix(0, 0)
			}
			log.Infof("DoSanitize: Forcing TimePriority for %s to %v\n",
				key, portConfig.TimePriority)
		}
	}
	if sanitizeKey {
		if portConfig.Key == "" {
			portConfig.Key = key
			log.Infof("DoSanitize: Forcing Key for %s TS %v\n",
				key, portConfig.TimePriority)
		}
	}
	if sanitizeName {
		// In case Name isn't set we make it match IfName
		// XXX still needed?
		for i := range portConfig.Ports {
			port := &portConfig.Ports[i]
			if port.Name == "" {
				port.Name = port.IfName
				log.Infof("DoSanitize: Forcing Name for %s ifname %s\n",
					key, port.IfName)
			}
		}
	}
}

// IsDPCTestable - Return false if recent failure (less than 60 seconds ago)
func (portConfig DevicePortConfig) IsDPCTestable() bool {

	if portConfig.LastFailed.IsZero() {
		return true
	}
	if portConfig.LastSucceeded.After(portConfig.LastFailed) {
		return true
	}
	// convert time difference in nano seconds to seconds
	timeDiff := time.Since(portConfig.LastFailed) / time.Second
	return (timeDiff > 60)
}

// IsDPCUntested -
func (portConfig DevicePortConfig) IsDPCUntested() bool {
	if portConfig.LastFailed.IsZero() && portConfig.LastSucceeded.IsZero() {
		return true
	}
	return false
}

// WasDPCWorking - Check if the last results for the DPC was Success
func (portConfig DevicePortConfig) WasDPCWorking() bool {

	if portConfig.LastSucceeded.IsZero() {
		return false
	}
	if portConfig.LastSucceeded.After(portConfig.LastFailed) {
		return true
	}
	return false
}

type NetworkProxyType uint8

// Values if these definitions should match the values
// given to the types in zapi.ProxyProto
const (
	NPT_HTTP NetworkProxyType = iota
	NPT_HTTPS
	NPT_SOCKS
	NPT_FTP
	NPT_NOPROXY
	NPT_LAST = 255
)

// WifiKeySchemeType - types of key management
type WifiKeySchemeType uint8

// Key Scheme type
const (
	KeySchemeNone WifiKeySchemeType = iota // enum for key scheme
	KeySchemeWpaPsk
	KeySchemeWpaEap
	KeySchemeOther
)

// WirelessType - types of wireless media
type WirelessType uint8

// enum wireless type
const (
	WirelessTypeNone WirelessType = iota // enum for wireless type
	WirelessTypeCellular
	WirelessTypeWifi
)

type ProxyEntry struct {
	Type   NetworkProxyType
	Server string
	Port   uint32
}

type ProxyConfig struct {
	Proxies    []ProxyEntry
	Exceptions string
	Pacfile    string
	// If Enable is set we use WPAD. If the URL is not set we try
	// the various DNS suffixes until we can download a wpad.dat file
	NetworkProxyEnable bool     // Enable WPAD
	NetworkProxyURL    string   // Complete URL i.e., with /wpad.dat
	WpadURL            string   // The URL determined from DNS
	ProxyCertPEM       [][]byte // List of certs which will be added to TLS trust
}

type DhcpConfig struct {
	Dhcp       DhcpType // If DT_STATIC use below; if DT_NONE do nothing
	AddrSubnet string   // In CIDR e.g., 192.168.1.44/24
	Gateway    net.IP
	DomainName string
	NtpServer  net.IP
	DnsServers []net.IP // If not set we use Gateway as DNS server
}

// CryptoBlock - crypto data
type CryptoBlock struct {
	Identity string // encrypted identity or username for WPA-EAP
	Password string // encrypted string of pass phrase or password hash
}

// WifiConfig - Wifi structure
type WifiConfig struct {
	SSID      string            // wifi SSID
	KeyScheme WifiKeySchemeType // such as WPA-PSK, WPA-EAP
	Identity  string            // identity or username for WPA-EAP
	Password  string            // string of pass phrase or password hash
	Crypto    CryptoBlock       // encrypted block of items
	Priority  int32
}

// CellConfig - Cellular part of the configure
type CellConfig struct {
	APN string // LTE APN
}

// WirelessConfig - wireless structure
type WirelessConfig struct {
	WType    WirelessType // Wireless Type
	Cellular []CellConfig // LTE APN
	Wifi     []WifiConfig // Wifi Config params
}

type NetworkPortConfig struct {
	IfName string
	Name   string // New logical name set by controller/model
	IsMgmt bool   // Used to talk to controller
	Free   bool   // Higher priority to talk to controller since no cost
	DhcpConfig
	ProxyConfig
	WirelessCfg WirelessConfig
	// Errrors from the parser go here and get reflects in NetworkPortStatus
	ParseError     string
	ParseErrorTime time.Time
}

type NetworkPortStatus struct {
	IfName string
	Name   string // New logical name set by controller/model
	IsMgmt bool   // Used to talk to controller
	Free   bool
	NetworkXObjectConfig
	AddrInfoList []AddrInfo
	ProxyConfig
	Error     string
	ErrorTime time.Time
}

type AddrInfo struct {
	Addr             net.IP
	Geo              ipinfo.IPInfo
	LastGeoTimestamp time.Time
}

// Published to microservices which needs to know about ports and IP addresses
type DeviceNetworkStatus struct {
	Version DevicePortConfigVersion // From DevicePortConfig
	Testing bool                    // Ignore since it is not yet verified
	Ports   []NetworkPortStatus
}

func (status *DeviceNetworkStatus) GetPortByName(
	port string) *NetworkPortStatus {
	for _, portStatus := range status.Ports {
		if strings.EqualFold(portStatus.Name, port) {
			log.Infof("Found NetworkPortStatus for %s", port)
			return &portStatus
		}
	}
	return nil
}

func (status *DeviceNetworkStatus) GetPortByIfName(
	port string) *NetworkPortStatus {
	for _, portStatus := range status.Ports {
		if portStatus.IfName == port {
			log.Infof("Found NetworkPortStatus for %s", port)
			return &portStatus
		}
	}
	return nil
}

func rotate(arr []string, amount int) []string {
	if len(arr) == 0 {
		return []string{}
	}
	amount = amount % len(arr)
	return append(append([]string{}, arr[amount:]...), arr[:amount]...)
}

// Return all management ports
func GetMgmtPortsAny(globalStatus DeviceNetworkStatus, rotation int) []string {
	return getMgmtPortsImpl(globalStatus, rotation, false, false)
}

// Return all free management ports
func GetMgmtPortsFree(globalStatus DeviceNetworkStatus, rotation int) []string {
	return getMgmtPortsImpl(globalStatus, rotation, true, false)
}

// Return all non-free management ports
func GetMgmtPortsNonFree(globalStatus DeviceNetworkStatus, rotation int) []string {
	return getMgmtPortsImpl(globalStatus, rotation, false, true)
}

// Returns the IfNames.
func getMgmtPortsImpl(globalStatus DeviceNetworkStatus, rotation int,
	freeOnly bool, nonfreeOnly bool) []string {

	var ports []string
	for _, us := range globalStatus.Ports {
		if freeOnly && !us.Free {
			continue
		}
		if nonfreeOnly && us.Free {
			continue
		}
		if globalStatus.Version >= DPCIsMgmt &&
			!us.IsMgmt {
			continue
		}
		ports = append(ports, us.IfName)
	}
	return rotate(ports, rotation)
}

// Return number of local IP addresses for all the management ports
// excluding link-local addresses
func CountLocalAddrAnyNoLinkLocal(globalStatus DeviceNetworkStatus) int {

	// Count the number of addresses which apply
	addrs, _ := getInterfaceAddr(globalStatus, false, "", false)
	return len(addrs)
}

// Return number of local IP addresses for all the management ports
// excluding link-local addresses
func CountLocalAddrAnyNoLinkLocalIf(globalStatus DeviceNetworkStatus,
	port string) int {

	// Count the number of addresses which apply
	addrs, _ := getInterfaceAddr(globalStatus, false, port, false)
	return len(addrs)
}

// Return a list of free management ports that have non link local IP addresses
// Used by LISP.
func GetMgmtPortsFreeNoLinkLocal(globalStatus DeviceNetworkStatus) []NetworkPortStatus {
	// Return MgmtPort list with valid non link local addresses
	links, _ := getInterfaceAndAddr(globalStatus, true, "", false)
	return links
}

// Return number of local IP addresses for all the free management ports
// excluding link-local addresses
func CountLocalAddrFreeNoLinkLocal(globalStatus DeviceNetworkStatus) int {

	// Count the number of addresses which apply
	addrs, _ := getInterfaceAddr(globalStatus, true, "", false)
	return len(addrs)
}

// XXX move AF functionality to getInterfaceAddr?
// Only IPv4 counted
func CountLocalIPv4AddrAnyNoLinkLocal(globalStatus DeviceNetworkStatus) int {

	// Count the number of addresses which apply
	addrs, _ := getInterfaceAddr(globalStatus, false, "", false)
	count := 0
	log.Infof("CountLocalIPv4AddrAnyNoLinkLocal: total %d: %v\n",
		len(addrs), addrs)
	for _, addr := range addrs {
		if addr.To4() == nil {
			continue
		}
		count += 1
	}
	return count
}

// CountDNSServers returns the number of DNS servers; for port if set
func CountDNSServers(globalStatus DeviceNetworkStatus, port string) int {

	var ifname string
	if port != "" {
		ifname = AdapterToIfName(&globalStatus, port)
	} else {
		ifname = port
	}
	count := 0
	for _, us := range globalStatus.Ports {
		if us.IfName != ifname && ifname != "" {
			continue
		}
		count += len(us.DnsServers)
	}
	return count
}

// GetDNSServers returns all, or the ones on one interface if port is set
func GetDNSServers(globalStatus DeviceNetworkStatus, port string) []net.IP {

	var ifname string
	if port != "" {
		ifname = AdapterToIfName(&globalStatus, port)
	} else {
		ifname = port
	}
	var servers []net.IP
	for _, us := range globalStatus.Ports {
		if !us.IsMgmt {
			continue
		}
		if ifname != "" && ifname != us.IfName {
			continue
		}
		for _, server := range us.DnsServers {
			servers = append(servers, server)
		}
	}
	return servers
}

// Return number of local IP addresses for all the management ports with given name
// excluding link-local addresses
func CountLocalAddrFreeNoLinkLocalIf(globalStatus DeviceNetworkStatus,
	port string) int {

	// Count the number of addresses which apply
	addrs, _ := getInterfaceAddr(globalStatus, true, port, false)
	return len(addrs)
}

// Return number of local IP addresses for all the management ports with given name
// excluding link-local addresses
// Only IPv4 counted
func CountLocalIPv4AddrAnyNoLinkLocalIf(globalStatus DeviceNetworkStatus,
	port string) int {

	// Count the number of addresses which apply
	addrs, _ := getInterfaceAddr(globalStatus, true, port, false)
	count := 0
	log.Infof("CountLocalIPv4AddrAnyNoLinkLocalIf(%s): total %d: %v\n",
		port, len(addrs), addrs)
	for _, addr := range addrs {
		if addr.To4() == nil {
			continue
		}
		count += 1
	}
	return count
}

// Pick one address from all of the management ports, unless if port is set
// in which we pick from that port. Includes link-local addresses.
// We put addresses from the free management ports first in the list i.e.,
// returned for the lower 'pickNum'
func GetLocalAddrAny(globalStatus DeviceNetworkStatus, pickNum int,
	port string) (net.IP, error) {

	freeOnly := false
	includeLinkLocal := true
	return getLocalAddrImpl(globalStatus, pickNum, port, freeOnly,
		includeLinkLocal)
}

// Pick one address from all of the management ports, unless if port is set
// in which we pick from that port. Excludes link-local addresses.
// We put addresses from the free management ports first in the list i.e.,
// returned for the lower 'pickNum'
func GetLocalAddrAnyNoLinkLocal(globalStatus DeviceNetworkStatus, pickNum int,
	port string) (net.IP, error) {

	freeOnly := false
	includeLinkLocal := false
	return getLocalAddrImpl(globalStatus, pickNum, port, freeOnly,
		includeLinkLocal)
}

// Pick one address from the free management ports, unless if port is set
// in which we pick from that port. Excludes link-local addresses.
// We put addresses from the free management ports first in the list i.e.,
// returned for the lower 'pickNum'
func GetLocalAddrFreeNoLinkLocal(globalStatus DeviceNetworkStatus, pickNum int,
	port string) (net.IP, error) {

	freeOnly := true
	includeLinkLocal := false
	return getLocalAddrImpl(globalStatus, pickNum, port, freeOnly,
		includeLinkLocal)
}

func getLocalAddrImpl(globalStatus DeviceNetworkStatus, pickNum int,
	port string, freeOnly bool, includeLinkLocal bool) (net.IP, error) {

	// Count the number of addresses which apply
	addrs, err := getInterfaceAddr(globalStatus, freeOnly, port,
		includeLinkLocal)
	if err != nil {
		return net.IP{}, err
	}
	numAddrs := len(addrs)
	pickNum = pickNum % numAddrs
	return addrs[pickNum], nil
}

func getInterfaceAndAddr(globalStatus DeviceNetworkStatus, free bool, port string,
	includeLinkLocal bool) ([]NetworkPortStatus, error) {

	var links []NetworkPortStatus
	var ifname string
	if port != "" {
		ifname = AdapterToIfName(&globalStatus, port)
	} else {
		ifname = port
	}
	for _, us := range globalStatus.Ports {
		if globalStatus.Version >= DPCIsMgmt &&
			!us.IsMgmt {
			continue
		}
		if free && !us.Free {
			continue
		}
		// If ifname is set it should match
		if us.IfName != ifname && ifname != "" {
			continue
		}

		link := NetworkPortStatus{
			IfName: us.IfName,
			Name:   us.Name,
			IsMgmt: us.IsMgmt,
			Free:   us.Free,
		}
		if includeLinkLocal {
			link.AddrInfoList = us.AddrInfoList
			links = append(links, link)
		} else {
			var addrs []AddrInfo
			for _, a := range us.AddrInfoList {
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
		return []NetworkPortStatus{}, errors.New("No good MgmtPorts")
	}
}

// Return the list of ifnames in DNC which exist in the kernel
func GetExistingInterfaceList(globalStatus DeviceNetworkStatus) []string {

	var ifs []string
	for _, us := range globalStatus.Ports {

		link, _ := netlink.LinkByName(us.IfName)
		if link == nil {
			log.Warnf("GetExistingInterfaceList: if %s not found\n",
				us.IfName)
			continue
		}
		ifs = append(ifs, us.IfName)
	}
	return ifs
}

// Check if an interface/adapter name is a port owned by zedrouter
func IsPort(globalStatus DeviceNetworkStatus, port string) bool {
	for _, us := range globalStatus.Ports {
		if us.Name != port && us.IfName != port {
			continue
		}
		return true
	}
	return false
}

// Check if an interface/adapter name is a management port
func IsMgmtPort(globalStatus DeviceNetworkStatus, port string) bool {
	for _, us := range globalStatus.Ports {
		if us.Name != port && us.IfName != port {
			continue
		}
		if globalStatus.Version >= DPCIsMgmt &&
			!us.IsMgmt {
			continue
		}
		return true
	}
	return false
}

// Check if an interface/adapter name is a free management port
func IsFreeMgmtPort(globalStatus DeviceNetworkStatus, port string) bool {
	for _, us := range globalStatus.Ports {
		if us.Name != port && us.IfName != port {
			continue
		}
		if globalStatus.Version >= DPCIsMgmt &&
			!us.IsMgmt {
			continue
		}
		return us.Free
	}
	return false
}

func GetPort(globalStatus DeviceNetworkStatus, port string) *NetworkPortStatus {
	for _, us := range globalStatus.Ports {
		if us.Name != port && us.IfName != port {
			continue
		}
		if globalStatus.Version < DPCIsMgmt {
			us.IsMgmt = true
		}
		return &us
	}
	return nil
}

// Given an address tell me its IfName
func GetMgmtPortFromAddr(globalStatus DeviceNetworkStatus, addr net.IP) string {
	for _, us := range globalStatus.Ports {
		if globalStatus.Version >= DPCIsMgmt &&
			!us.IsMgmt {
			continue
		}
		for _, i := range us.AddrInfoList {
			if i.Addr.Equal(addr) {
				return us.IfName
			}
		}
	}
	return ""
}

// Returns addresses based on free, ifname, and whether or not we want
// IPv6 link-locals. Only applies to management ports.
// If free is not set, the addresses from the free management ports are first.
func getInterfaceAddr(globalStatus DeviceNetworkStatus, free bool,
	port string, includeLinkLocal bool) ([]net.IP, error) {

	var freeAddrs []net.IP
	var nonfreeAddrs []net.IP
	var ifname string
	if port != "" {
		ifname = AdapterToIfName(&globalStatus, port)
	} else {
		ifname = port
	}
	for _, us := range globalStatus.Ports {
		if free && !us.Free {
			continue
		}
		if globalStatus.Version >= DPCIsMgmt &&
			!us.IsMgmt {
			continue
		}
		// If ifname is set it should match
		if us.IfName != ifname && ifname != "" {
			continue
		}
		var addrs []net.IP
		for _, i := range us.AddrInfoList {
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

// Return list of port names we will report in info and metrics
func ReportPorts(deviceNetworkStatus DeviceNetworkStatus) []string {

	var names []string
	for _, port := range deviceNetworkStatus.Ports {
		names = append(names, port.Name)
	}
	return names
}

// lookup port Name to find IfName
// Can also match on IfName
// If not found, return the adapter string
func AdapterToIfName(deviceNetworkStatus *DeviceNetworkStatus,
	adapter string) string {

	for _, p := range deviceNetworkStatus.Ports {
		if p.Name == adapter {
			log.Debugf("AdapterToIfName: found %s for %s\n",
				p.IfName, adapter)
			return p.IfName
		}
	}
	for _, p := range deviceNetworkStatus.Ports {
		if p.IfName == adapter {
			log.Debugf("AdapterToIfName: matched %s\n", adapter)
			return adapter
		}
	}
	log.Debugf("AdapterToIfName: no match for %s\n", adapter)
	return adapter
}

// IsAnyPortInPciBack
//		Checks is any of the Ports are part of IO bundles which are in PCIback.
//		If true, it also returns the portName ( NOT bundle name )
//		Also returns whether it is currently used by an application by
//		returning a UUID. If the UUID is zero it is in PCIback but available.
func (portConfig *DevicePortConfig) IsAnyPortInPciBack(
	aa *AssignableAdapters) (bool, string, uuid.UUID) {
	if aa == nil {
		log.Infof("IsAnyPortInPciBack: nil aa")
		return false, "", uuid.UUID{}
	}
	log.Infof("IsAnyPortInPciBack: aa init %t, %d bundles, %d ports",
		aa.Initialized, len(aa.IoBundleList), len(portConfig.Ports))
	for _, port := range portConfig.Ports {
		// XXX this assumes that ioBundle.Name is the ifname known
		// by the kernel/ifconfig
		ioBundle := aa.LookupIoBundleNet(port.IfName)
		if ioBundle == nil {
			// It is not guaranteed that all Ports are part of Assignable Adapters
			// If not found, the adaptor is not capable of being assigned at
			// PCI level. So it cannot be in PCI back.
			log.Infof("IsAnyPortInPciBack: ifname %s not found",
				port.IfName)
			continue
		}
		if ioBundle.IsPCIBack {
			return true, port.IfName, ioBundle.UsedByUUID
		}
	}
	return false, "", uuid.UUID{}
}

type MapServerType uint8

const (
	MST_INVALID MapServerType = iota
	MST_MAPSERVER
	MST_SUPPORT_SERVER
	MST_LAST = 255
)

// CurrIntfStatusType - enum for probe current uplink intf UP/Down status
type CurrIntfStatusType uint8

// CurrentIntf status
const (
	CurrIntfNone CurrIntfStatusType = iota
	CurrIntfDown
	CurrIntfUP
)

// ServerProbe - remote probe info configured from the cloud
type ServerProbe struct {
	ServerURL     string // include method,host,paths
	ServerIP      net.IP
	ProbeInterval uint32 // probe frequence in seconds
}

// ProbeInfo - per phyical port probing info
type ProbeInfo struct {
	IfName    string
	IsPresent bool // for GC purpose
	TransDown bool // local up long time, transition to down
	// local nexthop probe state
	GatewayUP  bool // local nexthop is in UP state
	LocalAddr  net.IP
	NhAddr     net.IP
	IsFree     bool
	FailedCnt  uint32 // continuous ping fail count, reset when ping success
	SuccessCnt uint32 // continous ping success count, reset when ping fail

	// remote host probe state
	RemoteHostUP    bool   // remote host is in UP state
	FailedProbeCnt  uint32 // continuous remote ping fail count, reset when ping success
	SuccessProbeCnt uint32 // continuous remote ping success count, reset when ping fail
	AveLatency      int64  // average delay in msec
}

// NetworkInstanceProbeStatus - probe status per network instance
type NetworkInstanceProbeStatus struct {
	PConfig           ServerProbe          // user configuration for remote server
	NeedIntfUpdate    bool                 // flag to indicate the CurrentUpLinkIntf status has changed
	PrevUplinkIntf    string               // previously used uplink interface
	CurrentUplinkIntf string               // decided by local/remote probing
	ProgUplinkIntf    string               // Currently programmed uplink interface for app traffic
	CurrIntfUP        CurrIntfStatusType   // the current picked interface can be up or down
	TriggerCnt        uint32               // number of times Uplink change triggered
	PInfo             map[string]ProbeInfo // per physical port eth0, eth1 probing state
}

type MapServer struct {
	ServiceType MapServerType
	NameOrIp    string
	Credential  string
}

type LispConfig struct {
	MapServers    []MapServer
	IID           uint32
	Allocate      bool
	ExportPrivate bool
	EidPrefix     net.IP
	EidPrefixLen  uint32

	Experimental bool
}

type NetworkInstanceLispConfig struct {
	MapServers    []MapServer
	IID           uint32
	Allocate      bool
	ExportPrivate bool
	EidPrefix     net.IP
	EidPrefixLen  uint32

	Experimental bool
}

type OverlayNetworkConfig struct {
	Name          string // From proto message
	EID           net.IP // Always EIDv6
	LispSignature string
	ACLs          []ACE
	AppMacAddr    net.HardwareAddr // If set use it for vif
	AppIPAddr     net.IP           // EIDv4 or EIDv6
	Network       uuid.UUID        // Points to a NetworkInstance.

	// Error
	//	If there is a parsing error and this uLNetwork config cannot be
	//	processed, set the error here. This allows the error to be propagated
	//  back to zedcloud
	//	If this is non-empty ( != ""), the network Config should not be
	// 	processed further. It Should just	be flagged to be in error state
	//  back to the cloud.
	Error string
	// Optional additional information
	AdditionalInfoDevice *AdditionalInfoDevice

	// These field are only for isMgmt. XXX remove when isMgmt is removed
	MgmtIID             uint32
	MgmtDnsNameToIPList []DnsNameToIP // Used to populate DNS for the overlay
	MgmtMapServers      []MapServer
}

type OverlayNetworkStatus struct {
	OverlayNetworkConfig
	VifInfo
	BridgeMac    net.HardwareAddr
	BridgeIPAddr string // The address for DNS/DHCP service in zedrouter
	Assigned     bool   // Set to true once DHCP has assigned EID to domU
	HostName     string
	ACLRules     IPTablesRuleList
}

type DhcpType uint8

const (
	DT_NOOP       DhcpType = iota
	DT_STATIC              // Device static config
	DT_NONE                // App passthrough e.g., to a bridge
	DT_Deprecated          // XXX to match .proto value
	DT_CLIENT              // Device client on external port
)

type UnderlayNetworkConfig struct {
	Name       string           // From proto message
	AppMacAddr net.HardwareAddr // If set use it for vif
	AppIPAddr  net.IP           // If set use DHCP to assign to app

	// Error
	//	If there is a parsing error and this uLNetwork config cannot be
	//	processed, set the error here. This allows the error to be propagated
	//  back to zedcloud
	//	If this is non-empty ( != ""), the UL network Config should not be
	// 	processed further. It Should just	be flagged to be in error state
	//  back to the cloud.
	Error   string
	Network uuid.UUID // Points to a NetworkInstance.
	ACLs    []ACE
}

type UnderlayNetworkStatus struct {
	UnderlayNetworkConfig
	VifInfo
	BridgeMac       net.HardwareAddr
	BridgeIPAddr    string // The address for DNS/DHCP service in zedrouter
	AllocatedIPAddr string // Assigned to domU
	Assigned        bool   // Set to true once DHCP has assigned it to domU
	HostName        string
	ACLRules        IPTablesRuleList
}

type NetworkType uint8

const (
	NT_NOOP      NetworkType = 0
	NT_IPV4                  = 4
	NT_IPV6                  = 6
	NT_CryptoEID             = 14 // Either IPv6 or IPv4; adapter Addr
	// determines whether IPv4 EIDs are in use.
	NT_CryptoV4 = 24 // Not used
	NT_CryptoV6 = 26 // Not used
	// XXX Do we need a NT_DUAL/NT_IPV46? Implies two subnets/dhcp ranges?
	// XXX how do we represent a bridge? NT_L2??
)

// Extracted from the protobuf NetworkConfig. Used by parseSystemAdapter
// XXX replace by inline once we have device model
type NetworkXObjectConfig struct {
	UUID            uuid.UUID
	Type            NetworkType
	Dhcp            DhcpType // If DT_STATIC or DT_CLIENT use below
	Subnet          net.IPNet
	Gateway         net.IP
	DomainName      string
	NtpServer       net.IP
	DnsServers      []net.IP // If not set we use Gateway as DNS server
	DhcpRange       IpRange
	DnsNameToIPList []DnsNameToIP // Used for DNS and ACL ipset
	Proxy           *ProxyConfig
	WirelessCfg     WirelessConfig
	// Any errrors from the parser
	Error     string
	ErrorTime time.Time
}

type IpRange struct {
	Start net.IP
	End   net.IP
}

func (config NetworkXObjectConfig) Key() string {
	return config.UUID.String()
}

type NetworkInstanceInfo struct {
	BridgeNum    int
	BridgeName   string // bn<N>
	BridgeIPAddr string
	BridgeMac    string

	// interface names for the Port
	IfNameList []string // Recorded at time of activate

	// Collection of address assignments; from MAC address to IP address
	IPAssignments map[string]net.IP

	// Union of all ipsets fed to dnsmasq for the linux bridge
	BridgeIPSets []string

	// Set of vifs on this bridge
	Vifs []VifNameMac

	Ipv4Eid bool // Track if this is a CryptoEid with IPv4 EIDs

	// Any errrors from provisioning the network
	Error     string
	ErrorTime time.Time

	// Vif metric map. This should have a union of currently existing
	// vifs and previously deleted vifs.
	// XXX When a vif is removed from bridge (app instance delete case),
	// device might start reporting smaller statistic values. To avoid this
	// from happening, we keep a list of all vifs that were ever connected
	// to this bridge and their statistics.
	// We add statistics from all vifs while reporting to cloud.
	VifMetricMap map[string]NetworkMetric
}

func (instanceInfo *NetworkInstanceInfo) IsVifInBridge(
	vifName string) bool {
	for _, vif := range instanceInfo.Vifs {
		if vif.Name == vifName {
			return true
		}
	}
	return false
}

func (instanceInfo *NetworkInstanceInfo) RemoveVif(
	vifName string) {
	log.Infof("DelVif(%s, %s)\n", instanceInfo.BridgeName, vifName)

	var vifs []VifNameMac
	for _, vif := range instanceInfo.Vifs {
		if vif.Name != vifName {
			vifs = append(vifs, vif)
		}
	}
	instanceInfo.Vifs = vifs
}

func (instanceInfo *NetworkInstanceInfo) AddVif(
	vifName string, appMac string, appID uuid.UUID) {

	log.Infof("addVifToBridge(%s, %s, %s, %s)\n",
		instanceInfo.BridgeName, vifName, appMac, appID.String())
	// XXX Should we just overwrite it? There is a lookup function
	//	anyways if the caller wants "check and add" semantics
	if instanceInfo.IsVifInBridge(vifName) {
		log.Errorf("addVifToBridge(%s, %s) exists\n",
			instanceInfo.BridgeName, vifName)
		return
	}
	info := VifNameMac{
		Name:    vifName,
		MacAddr: appMac,
		AppID:   appID,
	}
	instanceInfo.Vifs = append(instanceInfo.Vifs, info)
}

type NetworkServiceType uint8

const (
	NST_FIRST NetworkServiceType = iota
	NST_STRONGSWAN
	NST_LISP
	NST_BRIDGE
	NST_NAT // Default?
	NST_LB  // What is this?
	// XXX Add a NST_L3/NST_ROUTER to describe IP forwarding?
	NST_LAST = 255
)

type NetworkInstanceMetrics struct {
	UUIDandVersion UUIDandVersion
	DisplayName    string
	Type           NetworkInstanceType
	NetworkMetrics NetworkMetrics
	ProbeMetrics   ProbeMetrics
	VpnMetrics     *VpnMetrics
	LispMetrics    *LispMetrics
}

// ProbeMetrics - NI probe metrics
type ProbeMetrics struct {
	CurrUplinkIntf  string             // the uplink interface probing picks
	RemoteEndpoint  string             // remote either URL or IP address
	LocalPingIntvl  uint32             // local ping interval in seconds
	RemotePingIntvl uint32             // remote probing interval in seconds
	UplinkNumber    uint32             // number of possible uplink interfaces
	IntfProbeStats  []ProbeIntfMetrics // per dom0 intf uplink probing metrics
}

// ProbeIntfMetrics - per dom0 network uplink interface probing
type ProbeIntfMetrics struct {
	IntfName        string // dom0 uplink interface name
	NexthopGw       net.IP // interface local ping nexthop address
	GatewayUP       bool   // Is local gateway in UP status
	RmoteStatusUP   bool   // Is remote endpoint in UP status
	GatewayUPCnt    uint32 // local ping UP count
	GatewayDownCnt  uint32 // local ping DOWN count
	RemoteUPCnt     uint32 // remote probe UP count
	RemoteDownCnt   uint32 // remote probe DOWN count
	LatencyToRemote uint32 // probe latency to remote in msec
}

func (metrics NetworkInstanceMetrics) Key() string {
	return metrics.UUIDandVersion.UUID.String()
}

// Network metrics for overlay and underlay
// Matches networkMetrics protobuf message
type NetworkMetrics struct {
	MetricList []NetworkMetric
}

func (nms *NetworkMetrics) LookupNetworkMetrics(ifName string) (NetworkMetric, bool) {
	for _, metric := range nms.MetricList {
		if ifName == metric.IfName {
			return metric, true
		}
	}
	return NetworkMetric{}, false
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

type NetworkInstanceType int32

// These values should be same as the ones defined in zconfig.ZNetworkInstType
const (
	NetworkInstanceTypeFirst       NetworkInstanceType = 0
	NetworkInstanceTypeSwitch      NetworkInstanceType = 1
	NetworkInstanceTypeLocal       NetworkInstanceType = 2
	NetworkInstanceTypeCloud       NetworkInstanceType = 3
	NetworkInstanceTypeMesh        NetworkInstanceType = 4
	NetworkInstanceTypeHoneyPot    NetworkInstanceType = 5
	NetworkInstanceTypeTransparent NetworkInstanceType = 6
	NetworkInstanceTypeLast        NetworkInstanceType = 255
)

type AddressType int32

// The values here should be same as the ones defined in zconfig.AddressType
const (
	AddressTypeNone       AddressType = 0 // For switch networks
	AddressTypeIPV4       AddressType = 1
	AddressTypeIPV6       AddressType = 2
	AddressTypeCryptoIPV4 AddressType = 3
	AddressTypeCryptoIPV6 AddressType = 4
	AddressTypeLast       AddressType = 255
)

// NetworkInstanceConfig
//		Config Object for NetworkInstance
// 		Extracted from the protobuf NetworkInstanceConfig
type NetworkInstanceConfig struct {
	UUIDandVersion
	DisplayName string

	Type NetworkInstanceType

	// Activate - Activate the config.
	Activate bool

	// Port - Port name specified in the Device Config.
	Port string

	// IP configuration for the Application
	IpType          AddressType
	Subnet          net.IPNet
	Gateway         net.IP
	DomainName      string
	NtpServer       net.IP
	DnsServers      []net.IP // If not set we use Gateway as DNS server
	DhcpRange       IpRange
	DnsNameToIPList []DnsNameToIP // Used for DNS and ACL ipset

	HasEncap bool // Lisp/Vpn, for adjusting pMTU
	// For other network services - Proxy / Lisp /StrongSwan etc..
	OpaqueConfig string
	LispConfig   NetworkInstanceLispConfig
}

func (config *NetworkInstanceConfig) Key() string {
	return config.UUID.String()
}

func (config *NetworkInstanceConfig) IsIPv6() bool {
	switch config.IpType {
	case AddressTypeIPV6:
		return true
	case AddressTypeCryptoIPV6:
		return true
	}
	return false
}

type ChangeInProgressType int32

const (
	ChangeInProgressTypeNone   ChangeInProgressType = 0
	ChangeInProgressTypeCreate ChangeInProgressType = 1
	ChangeInProgressTypeModify ChangeInProgressType = 2
	ChangeInProgressTypeDelete ChangeInProgressType = 3
	ChangeInProgressTypeLast   ChangeInProgressType = 255
)

// NetworkInstanceStatus
//		Config Object for NetworkInstance
// 		Extracted from the protobuf NetworkInstanceConfig
type NetworkInstanceStatus struct {
	NetworkInstanceConfig
	ChangeInProgress ChangeInProgressType

	// Activated
	//	Keeps track of current state of object - if it has been activated
	Activated bool

	NetworkInstanceInfo

	OpaqueStatus string
	LispStatus   NetworkInstanceLispConfig

	VpnStatus      *VpnStatus
	LispInfoStatus *LispInfoStatus
	LispMetrics    *LispMetrics

	NetworkInstanceProbeStatus
}

type VifNameMac struct {
	Name    string
	MacAddr string
	AppID   uuid.UUID
}

// AppNetworkACLArgs : args for converting ACL to iptables rules
type AppNetworkACLArgs struct {
	IsMgmt     bool
	IPVer      int
	BridgeName string
	VifName    string
	BridgeIP   string
	AppIP      string
	UpLinks    []string
	NIType     NetworkInstanceType
	// This is the same AppNum that comes from AppNetworkStatus
	AppNum int32
}

// IPTablesRule : iptables rule detail
type IPTablesRule struct {
	IPVer            int      // 4 or, 6
	Table            string   // filter/nat/raw/mangle...
	Chain            string   // FORWARDING/INPUT/PREROUTING...
	Prefix           []string // constructed using ACLArgs
	Rule             []string // rule match
	Action           []string // rule action
	RuleID           int32    // Unique rule ID
	RuleName         string
	ActionChainName  string
	IsUserConfigured bool // Does this rule come from user configuration/manifest?
	IsMarkingRule    bool // Rule does marking of packet for flow tracking.
	IsPortMapRule    bool // Is this a port map rule?
	IsLimitDropRule  bool // Is this a policer limit drop rule?
	IsDefaultDrop    bool // Is this a default drop rule that forwards to dummy?
}

// IPTablesRuleList : list of iptables rules
type IPTablesRuleList []IPTablesRule

/*
 * Tx/Rx of bridge is equal to the total of Tx/Rx on all member
 * virtual interfaces excluding the bridge itself.
 *
 * Drops/Errors/AclDrops of bridge is equal to total of Drops/Errors/AclDrops
 * on all member virtual interface including the bridge.
 */
func (status *NetworkInstanceStatus) UpdateNetworkMetrics(
	nms *NetworkMetrics) *NetworkMetric {

	netMetric := NetworkMetric{IfName: status.BridgeName}
	for _, vif := range status.Vifs {
		metric, found := nms.LookupNetworkMetrics(vif.Name)
		if !found {
			log.Debugf("No metrics found for interface %s",
				vif.Name)
			continue
		}
		status.VifMetricMap[vif.Name] = metric
	}
	for _, metric := range status.VifMetricMap {
		netMetric.TxBytes += metric.TxBytes
		netMetric.RxBytes += metric.RxBytes
		netMetric.TxPkts += metric.TxPkts
		netMetric.RxPkts += metric.RxPkts
		netMetric.TxErrors += metric.TxErrors
		netMetric.RxErrors += metric.RxErrors
		netMetric.TxDrops += metric.TxDrops
		netMetric.RxDrops += metric.RxDrops
		netMetric.TxAclDrops += metric.TxAclDrops
		netMetric.RxAclDrops += metric.RxAclDrops
		netMetric.TxAclRateLimitDrops += metric.TxAclRateLimitDrops
		netMetric.RxAclRateLimitDrops += metric.RxAclRateLimitDrops
	}
	return &netMetric
}

/*
 * Tx/Rx of bridge is equal to the total of Tx/Rx on all member
 * virtual interfaces excluding the bridge itself.
 *
 * Drops/Errors/AclDrops of bridge is equal to total of Drops/Errors/AclDrops
 * on all member virtual interface including the bridge.
 */
func (status *NetworkInstanceStatus) UpdateBridgeMetrics(
	nms *NetworkMetrics, netMetric *NetworkMetric) {
	// Get bridge metrics
	bridgeMetric, found := nms.LookupNetworkMetrics(status.BridgeName)
	if !found {
		log.Debugf("No metrics found for Bridge %s",
			status.BridgeName)
	} else {
		netMetric.TxErrors += bridgeMetric.TxErrors
		netMetric.RxErrors += bridgeMetric.RxErrors
		netMetric.TxDrops += bridgeMetric.TxDrops
		netMetric.RxDrops += bridgeMetric.RxDrops
		netMetric.TxAclDrops += bridgeMetric.TxAclDrops
		netMetric.RxAclDrops += bridgeMetric.RxAclDrops
		netMetric.TxAclRateLimitDrops += bridgeMetric.TxAclRateLimitDrops
		netMetric.RxAclRateLimitDrops += bridgeMetric.RxAclRateLimitDrops
	}
}

func (status *NetworkInstanceStatus) SetError(err error) {
	log.Errorln(err.Error())
	status.Error = err.Error()
	status.ErrorTime = time.Now()
	return
}

// Returns true if found
func (status *NetworkInstanceStatus) IsIpAssigned(ip net.IP) bool {
	for _, a := range status.IPAssignments {
		if ip.Equal(a) {
			return true
		}
	}
	return false
}

// Check if port is used even if a label like "uplink" is used to specify it
func (status *NetworkInstanceStatus) IsUsingPort(port string) bool {
	if strings.EqualFold(port, status.Port) {
		return true
	}
	for _, ifname := range status.IfNameList {
		if ifname == port {
			return true
		}
	}
	return false
}

// ACEDirection :
// Rule direction
type ACEDirection uint8

const (
	// AceDirBoth : Rule applies in both directions
	AceDirBoth ACEDirection = iota
	// AceDirIngress : Rules applies in Ingress direction (from internet to app)
	AceDirIngress ACEDirection = 1
	// AceDirEgress : Rules applies in Egress direction (from app to internet)
	AceDirEgress ACEDirection = 2
)

// Similar support as in draft-ietf-netmod-acl-model
type ACE struct {
	Matches []ACEMatch
	Actions []ACEAction
	Name    string
	RuleID  int32
	Dir     ACEDirection
}

// The Type can be "ip" or "host" (aka domain name), "eidset", "protocol",
// "fport", or "lport" for now. The ip and host matches the remote IP/hostname.
// The host matching is suffix-matching thus zededa.net matches *.zededa.net.
// XXX Need "interface"... e.g. "uplink" or "eth1"? Implicit in network used?
// For now the matches are bidirectional.
// XXX Add directionality? Different rate limits in different directions?
// Value is always a string.
// There is an implicit reject rule at the end.
// The "eidset" type is special for the overlay. Matches all the IPs which
// are part of the DnsNameToIPList.
type ACEMatch struct {
	Type  string
	Value string
}

type ACEAction struct {
	Drop bool // Otherwise accept

	Limit      bool   // Is limiter enabled?
	LimitRate  int    // Packets per unit
	LimitUnit  string // "s", "m", "h", for second, minute, hour
	LimitBurst int    // Packets

	PortMap    bool // Is port mapping part of action?
	TargetPort int  // Internal port
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

// Input Opaque Config
type StrongSwanConfig struct {
	VpnRole          string
	PolicyBased      bool
	IsClient         bool
	VpnGatewayIpAddr string
	VpnSubnetBlock   string
	VpnLocalIpAddr   string
	VpnRemoteIpAddr  string
	PreSharedKey     string
	LocalSubnetBlock string
	ClientConfigList []VpnClientConfig
}

// structure for internal handling
type VpnConfig struct {
	VpnRole          string
	PolicyBased      bool
	IsClient         bool
	PortConfig       NetLinkConfig
	AppLinkConfig    NetLinkConfig
	GatewayConfig    NetLinkConfig
	ClientConfigList []VpnClientConfig
}

type NetLinkConfig struct {
	Name        string
	IpAddr      string
	SubnetBlock string
}

type VpnClientConfig struct {
	IpAddr       string
	SubnetBlock  string
	PreSharedKey string
	TunnelConfig VpnTunnelConfig
}

type VpnTunnelConfig struct {
	Name         string
	Key          string
	Mtu          string
	Metric       string
	LocalIpAddr  string
	RemoteIpAddr string
}

type LispRlocState struct {
	Rloc      net.IP
	Reachable bool
}

type LispMapCacheEntry struct {
	EID   net.IP
	Rlocs []LispRlocState
}

type LispDatabaseMap struct {
	IID             uint64
	MapCacheEntries []LispMapCacheEntry
}

type LispDecapKey struct {
	Rloc     net.IP
	Port     uint64
	KeyCount uint64
}

type LispInfoStatus struct {
	ItrCryptoPort uint64
	EtrNatPort    uint64
	Interfaces    []string
	DatabaseMaps  []LispDatabaseMap
	DecapKeys     []LispDecapKey
}

type LispPktStat struct {
	Pkts  uint64
	Bytes uint64
}

type LispRlocStatistics struct {
	Rloc                   net.IP
	Stats                  LispPktStat
	SecondsSinceLastPacket uint64
}

type EidStatistics struct {
	IID       uint64
	Eid       net.IP
	RlocStats []LispRlocStatistics
}

type EidMap struct {
	IID  uint64
	Eids []net.IP
}

type LispMetrics struct {
	// Encap Statistics
	EidMaps            []EidMap
	EidStats           []EidStatistics
	ItrPacketSendError LispPktStat
	InvalidEidError    LispPktStat

	// Decap Statistics
	NoDecryptKey       LispPktStat
	OuterHeaderError   LispPktStat
	BadInnerVersion    LispPktStat
	GoodPackets        LispPktStat
	ICVError           LispPktStat
	LispHeaderError    LispPktStat
	CheckSumError      LispPktStat
	DecapReInjectError LispPktStat
	DecryptError       LispPktStat
}

type LispDataplaneConfig struct {
	// If true, we run legacy lispers.net data plane.
	Legacy bool
}

type VpnState uint8

const (
	VPN_INVALID VpnState = iota
	VPN_INITIAL
	VPN_CONNECTING
	VPN_ESTABLISHED
	VPN_INSTALLED
	VPN_REKEYED
	VPN_DELETED  VpnState = 10
	VPN_MAXSTATE VpnState = 255
)

type VpnLinkInfo struct {
	SubNet    string // connecting subnet
	SpiId     string // security parameter index
	Direction bool   // 0 - in, 1 - out
	PktStats  PktStats
}

type VpnLinkStatus struct {
	Id         string
	Name       string
	ReqId      string
	InstTime   uint64 // installation time
	ExpTime    uint64 // expiry time
	RekeyTime  uint64 // rekey time
	EspInfo    string
	State      VpnState
	LInfo      VpnLinkInfo
	RInfo      VpnLinkInfo
	MarkDelete bool
}

type VpnEndPoint struct {
	Id     string // ipsec id
	IpAddr string // end point ip address
	Port   uint32 // udp port
}

type VpnConnStatus struct {
	Id         string   // ipsec connection id
	Name       string   // connection name
	State      VpnState // vpn state
	Version    string   // ike version
	Ikes       string   // ike parameters
	EstTime    uint64   // established time
	ReauthTime uint64   // reauth time
	LInfo      VpnEndPoint
	RInfo      VpnEndPoint
	Links      []*VpnLinkStatus
	StartLine  uint32
	EndLine    uint32
	MarkDelete bool
}

type VpnStatus struct {
	Version            string    // strongswan package version
	UpTime             time.Time // service start time stamp
	IpAddrs            string    // listening ip addresses, can be multiple
	ActiveVpnConns     []*VpnConnStatus
	StaleVpnConns      []*VpnConnStatus
	ActiveTunCount     uint32
	ConnectingTunCount uint32
	PolicyBased        bool
}

type PktStats struct {
	Pkts  uint64
	Bytes uint64
}

type LinkPktStats struct {
	InPkts  PktStats
	OutPkts PktStats
}

type VpnLinkMetrics struct {
	SubNet string // connecting subnet
	SpiId  string // security parameter index
}

type VpnEndPointMetrics struct {
	IpAddr   string // end point ip address
	LinkInfo VpnLinkMetrics
	PktStats PktStats
}

type VpnConnMetrics struct {
	Id        string // ipsec connection id
	Name      string // connection name
	EstTime   uint64 // established time
	Type      NetworkServiceType
	NIType    NetworkInstanceType
	LEndPoint VpnEndPointMetrics
	REndPoint VpnEndPointMetrics
}

type VpnMetrics struct {
	UpTime     time.Time // service start time stamp
	DataStat   LinkPktStats
	IkeStat    LinkPktStats
	NatTStat   LinkPktStats
	EspStat    LinkPktStats
	ErrStat    LinkPktStats
	PhyErrStat LinkPktStats
	VpnConns   []*VpnConnMetrics
}

// IPTuple :
type IPTuple struct {
	Src     net.IP // local App IP address
	Dst     net.IP // remote IP address
	SrcPort int32  // local App IP Port
	DstPort int32  // remote IP Port
	Proto   int32
}

// FlowScope :
type FlowScope struct {
	UUID      uuid.UUID
	Intf      string
	Localintf string
	NetUUID   uuid.UUID
	Sequence  string // used internally for limit and pkt size per app/bn
}

// FlowRec :
type FlowRec struct {
	Flow      IPTuple
	Inbound   bool
	ACLID     int32
	Action    string
	StartTime int64
	StopTime  int64
	TxBytes   int64
	TxPkts    int64
	RxBytes   int64
	RxPkts    int64
}

// DNSReq :
type DNSReq struct {
	HostName    string
	Addrs       []net.IP
	RequestTime int64
	ACLNum      int32
}

// IPFlow :
type IPFlow struct {
	DevID   uuid.UUID
	Scope   FlowScope
	Flows   []FlowRec
	DNSReqs []DNSReq
}

// Key :
func (flows IPFlow) Key() string {
	return flows.Scope.UUID.String() + flows.Scope.NetUUID.String() + flows.Scope.Sequence
}

// VifIPTrig - structure contains Mac Address
type VifIPTrig struct {
	MacAddr string
	IPAddr  net.IP
}

// Key - VifIPTrig key function
func (vifIP VifIPTrig) Key() string {
	return vifIP.MacAddr
}
