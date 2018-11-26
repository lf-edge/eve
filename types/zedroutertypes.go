// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package types

import (
	"encoding/json"
	"errors"
	"github.com/eriknordmark/ipinfo"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
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
	SeparateDataPlane   bool
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
	SeparateDataPlane   bool
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

// Global network config. For backwards compatibility with build artifacts
// XXX move to using DeviceUplinkConfig in build?
type DeviceNetworkConfig struct {
	Uplink      []string // ifname; all uplinks
	FreeUplinks []string // subset used for image downloads
}

type DeviceUplinkConfig struct {
	Uplinks []NetworkUplinkConfig
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
	NetworkProxyEnable bool   // Enable WPAD
	NetworkProxyURL    string // Complete URL i.e., with /wpad.dat
}

type DhcpConfig struct {
	Dhcp       DhcpType // If DT_STATIC use below
	AddrSubnet string   // In CIDR e.g., 192.168.1.44/24
	Gateway    net.IP
	DomainName string
	NtpServer  net.IP
	DnsServers []net.IP // If not set we use Gateway as DNS server
}

type NetworkUplinkConfig struct {
	IfName string
	Free   bool
	DhcpConfig
	ProxyConfig
}

type NetworkUplink struct {
	IfName string
	Free   bool
	NetworkObjectConfig
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

// Return all uplink interfaces
func GetUplinks(globalStatus DeviceNetworkStatus, rotation int) []string {
	var uplinks []string

	for _, us := range globalStatus.UplinkStatus {
		if us.Free {
			uplinks = append(uplinks, us.IfName)
		}
	}
	return rotate(uplinks, rotation)
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
func GetUplinkFreeNoLocal(globalStatus DeviceNetworkStatus) []NetworkUplink {
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
			link := NetworkUplink{
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

// Check if an interface/adapter name is a free uplink
func IsFreeUplink(globalStatus DeviceNetworkStatus, ifname string) bool {
	for _, us := range globalStatus.UplinkStatus {
		if us.IfName == ifname {
			return us.Free
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

type MapServerType uint8

const (
	MST_INVALID MapServerType = iota
	MST_MAPSERVER
	MST_SUPPORT_SERVER
	MST_LAST = 255
)

type MapServer struct {
	ServiceType MapServerType
	NameOrIp    string
	Credential  string
}

type ServiceLispConfig struct {
	MapServers    []MapServer
	IID           uint32
	Allocate      bool
	ExportPrivate bool
	EidPrefix     net.IP
	EidPrefixLen  uint32

	Experimental bool
}

type OverlayNetworkConfig struct {
	EID           net.IP // Always EIDv6
	LispSignature string
	ACLs          []ACE
	AppMacAddr    net.HardwareAddr // If set use it for vif
	AppIPAddr     net.IP           // EIDv4 or EIDv6
	Network       uuid.UUID

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
	HostName     string
	// XXX MissingNetwork bool // If Network UUID not found
}

type DhcpType uint8

const (
	DT_NOOP        DhcpType = iota
	DT_STATIC               // Device static config
	DT_PASSTHROUGH          // App passthrough e.g., to a bridge
	DT_SERVER               // Local server for app network
	DT_CLIENT               // Device client on external port
)

type UnderlayNetworkConfig struct {
	AppMacAddr net.HardwareAddr // If set use it for vif
	AppIPAddr  net.IP           // If set use DHCP to assign to app
	Network    uuid.UUID
	ACLs       []ACE
}

type UnderlayNetworkStatus struct {
	UnderlayNetworkConfig
	VifInfo
	BridgeMac      net.HardwareAddr
	BridgeIPAddr   string // The address for DNS/DHCP service in zedrouter
	AssignedIPAddr string // Assigned to domU
	HostName       string
	// XXX MissingNetwork bool // If Network UUID not found
}

type NetworkType uint8

const (
	NT_IPV4      NetworkType = 4
	NT_IPV6                  = 6
	NT_CryptoEID             = 14 // Either IPv6 or IPv4; adapter Addr
	// determines whether IPv4 EIDs are in use.
	// XXX Do we need a NT_DUAL/NT_IPV46? Implies two subnets/dhcp ranges?
	// XXX how do we represent a bridge? NT_L2??
)

// Extracted from the protobuf NetworkConfig
// Referenced using the UUID in Overlay/UnderlayNetworkConfig
// Note that NetworkConfig can be referenced (by UUID) from NetworkService.
// If there is no such reference the NetworkConfig ends up being local to the
// host.
type NetworkObjectConfig struct {
	UUID            uuid.UUID
	Type            NetworkType
	Dhcp            DhcpType // If DT_STATIC or DT_SERVER use below
	Subnet          net.IPNet
	Gateway         net.IP
	DomainName      string
	NtpServer       net.IP
	DnsServers      []net.IP // If not set we use Gateway as DNS server
	DhcpRange       IpRange
	DnsNameToIPList []DnsNameToIP // Used for DNS and ACL ipset
	Proxy           *ProxyConfig
}

type IpRange struct {
	Start net.IP
	End   net.IP
}

func (config NetworkObjectConfig) Key() string {
	return config.UUID.String()
}

type NetworkObjectStatus struct {
	NetworkObjectConfig
	PendingAdd    bool
	PendingModify bool
	PendingDelete bool
	BridgeNum     int
	BridgeName    string // bn<N>
	BridgeIPAddr  string

	// Used to populate DNS and eid ipset
	DnsNameToIPList []DnsNameToIP

	// Collection of address assignments; from MAC address to IP address
	IPAssignments map[string]net.IP

	// Union of all ipsets fed to dnsmasq for the linux bridge
	BridgeIPSets []string

	// Set of vifs on this bridge
	VifNames []string

	Ipv4Eid bool // Track if this is a CryptoEid with IPv4 EIDs

	// Any errrors from provisioning the network
	Error     string
	ErrorTime time.Time
}

func (status NetworkObjectStatus) Key() string {
	return status.UUID.String()
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

// Extracted from protobuf Service definition
type NetworkServiceConfig struct {
	UUID         uuid.UUID
	Internal     bool // Internally created - not from zedcloud
	DisplayName  string
	Type         NetworkServiceType
	Activate     bool
	AppLink      uuid.UUID
	Adapter      string // Ifname or group like "uplink", or empty
	OpaqueConfig string
	LispConfig   ServiceLispConfig
}

func (config NetworkServiceConfig) Key() string {
	return config.UUID.String()
}

type NetworkServiceStatus struct {
	UUID          uuid.UUID
	PendingAdd    bool
	PendingModify bool
	PendingDelete bool
	DisplayName   string
	Type          NetworkServiceType
	Activated     bool
	AppLink       uuid.UUID
	Adapter       string // Ifname or group like "uplink", or empty
	OpaqueStatus  string
	LispStatus    ServiceLispConfig
	AdapterList   []string  // Recorded at time of activate
	Subnet        net.IPNet // Recorded at time of activate

	MissingNetwork bool // If AppLink UUID not found
	// Any errrors from provisioning the service
	Error          string
	ErrorTime      time.Time
	VpnStatus      *ServiceVpnStatus
	LispInfoStatus *LispInfoStatus
	LispMetrics    *LispMetrics
}

func (status NetworkServiceStatus) Key() string {
	return status.UUID.String()
}

type NetworkServiceMetrics struct {
	UUID        uuid.UUID
	DisplayName string
	Type        NetworkServiceType
	VpnMetrics  *VpnMetrics
	LispMetrics *LispMetrics
}

func (metrics NetworkServiceMetrics) Key() string {
	return metrics.UUID.String()
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

// The Type can be "ip" or "host" (aka domain name), "eidset", "protocol",
// "fport", or "lport" for now. The ip and host matches the remote IP/hostname.
// The host matching is suffix-matching thus zededa.net matches *.zededa.net.
// XXX Need "interface"... e.g. "uplink" or "eth1"? Implicit in network used?
// For now the matches are bidirectional.
// XXX Add directionality? Different ragte limits in different directions?
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
type StrongSwanServiceConfig struct {
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
type VpnServiceConfig struct {
	VpnRole          string
	PolicyBased      bool
	IsClient         bool
	UpLinkConfig     NetLinkConfig
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
	Experimental bool
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

type ServiceVpnStatus struct {
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
