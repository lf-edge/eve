// Copyright (c) 2017-2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/kube/cnirpc"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/objtonum"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// AppNetworkConfig : network configuration for a given application.
type AppNetworkConfig struct {
	UUIDandVersion    UUIDandVersion
	DisplayName       string
	Activate          bool
	GetStatsIPAddr    net.IP
	AppNetAdapterList []AppNetAdapterConfig
	CloudInitUserData *string `json:"pubsub-large-CloudInitUserData"`
	CipherBlockStatus CipherBlockStatus
	MetaDataType      MetaDataType
}

// Key :
func (config AppNetworkConfig) Key() string {
	return config.UUIDandVersion.UUID.String()
}

// LogCreate :
func (config AppNetworkConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AppNetworkConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("activate", config.Activate).
		Noticef("App network config create")
}

// LogModify :
func (config AppNetworkConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AppNetworkConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())

	oldConfig, ok := old.(AppNetworkConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AppNetworkConfig type")
	}
	if oldConfig.Activate != config.Activate {

		logObject.CloneAndAddField("activate", config.Activate).
			AddField("old-activate", oldConfig.Activate).
			Noticef("App network config modify")
	} else {
		// Log at Function level
		logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
			Functionf("App network config modify other change")
	}
}

// LogDelete :
func (config AppNetworkConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AppNetworkConfigLogType, config.DisplayName,
		config.UUIDandVersion.UUID, config.LogKey())
	logObject.CloneAndAddField("activate", config.Activate).
		Noticef("App network config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config AppNetworkConfig) LogKey() string {
	return string(base.AppNetworkConfigLogType) + "-" + config.Key()
}

func (config *AppNetworkConfig) getAppNetAdapterConfig(
	network uuid.UUID) *AppNetAdapterConfig {
	for i := range config.AppNetAdapterList {
		adapterConfig := &config.AppNetAdapterList[i]
		if adapterConfig.Network == network {
			return adapterConfig
		}
	}
	return nil
}

// IsNetworkUsed returns true if the given network instance is used by this app.
func (config *AppNetworkConfig) IsNetworkUsed(network uuid.UUID) bool {
	return config.getAppNetAdapterConfig(network) != nil
}

// AppNetworkStatus : status of app connectivity.
type AppNetworkStatus struct {
	UUIDandVersion UUIDandVersion
	AppNum         int
	Activated      bool
	PendingAdd     bool
	PendingModify  bool
	PendingDelete  bool
	ConfigInSync   bool
	DisplayName    string
	// AppPod is only valid in Kubernetes mode.
	AppPod cnirpc.AppPod
	// Copy from the AppNetworkConfig; used to delete when config is gone.
	GetStatsIPAddr       net.IP
	AppNetAdapterList    []AppNetAdapterStatus
	AwaitNetworkInstance bool // If any Missing flag is set in the networks
	// ID of the MAC generator variant that was used to generate MAC addresses for this app.
	MACGenerator int
	// Any errors from provisioning the network
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

// Key :
func (status AppNetworkStatus) Key() string {
	return status.UUIDandVersion.UUID.String()
}

// LogCreate :
func (status AppNetworkStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AppNetworkStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("activated", status.Activated).
		Noticef("App network status create")
}

// LogModify :
func (status AppNetworkStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AppNetworkStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())

	oldStatus, ok := old.(AppNetworkStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AppNetworkStatus type")
	}
	if oldStatus.Activated != status.Activated {

		logObject.CloneAndAddField("activated", status.Activated).
			AddField("old-activated", oldStatus.Activated).
			Noticef("App network status modify")
	} else {
		// Log at Function level
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Functionf("App network status modify other change")
	}

	if status.HasError() {
		errAndTime := status.ErrorAndTime
		logObject.CloneAndAddField("activated", status.Activated).
			AddField("error", errAndTime.Error).
			AddField("error-time", errAndTime.ErrorTime).
			Noticef("App network status modify")
	}
}

// LogDelete :
func (status AppNetworkStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AppNetworkStatusLogType, status.DisplayName,
		status.UUIDandVersion.UUID, status.LogKey())
	logObject.CloneAndAddField("activated", status.Activated).
		Noticef("App network status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status AppNetworkStatus) LogKey() string {
	return string(base.AppNetworkStatusLogType) + "-" + status.Key()
}

// Pending returns true if the last configuration operation is still pending
// and not processed yet.
func (status AppNetworkStatus) Pending() bool {
	return status.PendingAdd || status.PendingModify || status.PendingDelete
}

// AwaitingNetwork - Is the app waiting for network?
func (status AppNetworkStatus) AwaitingNetwork() bool {
	return status.AwaitNetworkInstance
}

// GetAdaptersStatusForNI returns AppNetAdapterStatus for every application VIF
// connected to the given network instance (there can be multiple interfaces connected
// to the same network instance).
func (status AppNetworkStatus) GetAdaptersStatusForNI(netUUID uuid.UUID) []*AppNetAdapterStatus {
	var adapters []*AppNetAdapterStatus
	for i := range status.AppNetAdapterList {
		adapter := &status.AppNetAdapterList[i]
		if adapter.Network == netUUID {
			adapters = append(adapters, adapter)
		}
	}
	return adapters
}

// AppContainerMetrics - App Container Metrics
type AppContainerMetrics struct {
	UUIDandVersion UUIDandVersion // App UUID
	// Stats Collection time for uploading stats to cloud
	CollectTime time.Time
	StatsList   []AppContainerStats
}

// AppContainerStats - for App Container Stats
type AppContainerStats struct {
	ContainerName string // unique under an App
	Status        string // uptime, pause, stop status
	Pids          uint32 // number of PIDs within the container
	// CPU stats
	Uptime         int64  // unix.nano, time since container starts
	CPUTotal       uint64 // container CPU since starts in nanosec
	SystemCPUTotal uint64 // total system, user, idle in nanosec
	// Memory stats
	UsedMem      uint32 // in MBytes
	AllocatedMem uint32 // in MBytes
	// Network stats
	TxBytes uint64 // in Bytes
	RxBytes uint64 // in Bytes
	// Disk stats
	ReadBytes  uint64 // in MBytes
	WriteBytes uint64 // in MBytes
}

// Key - key for AppContainerMetrics
func (acMetric AppContainerMetrics) Key() string {
	return acMetric.UUIDandVersion.UUID.String()
}

// LogCreate :
func (acMetric AppContainerMetrics) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AppContainerMetricsLogType, "",
		acMetric.UUIDandVersion.UUID, acMetric.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("App container metric create")
}

// LogModify :
func (acMetric AppContainerMetrics) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AppContainerMetricsLogType, "",
		acMetric.UUIDandVersion.UUID, acMetric.LogKey())

	oldAcMetric, ok := old.(AppContainerMetrics)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of AppContainerMetrics type")
	}
	// XXX remove? XXX huge?
	logObject.CloneAndAddField("diff", cmp.Diff(oldAcMetric, acMetric)).
		Metricf("App container metric modify")
}

// LogDelete :
func (acMetric AppContainerMetrics) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AppContainerMetricsLogType, "",
		acMetric.UUIDandVersion.UUID, acMetric.LogKey())
	logObject.Metricf("App container metric delete")

	base.DeleteLogObject(logBase, acMetric.LogKey())
}

// LogKey :
func (acMetric AppContainerMetrics) LogKey() string {
	return string(base.AppContainerMetricsLogType) + "-" + acMetric.Key()
}

// AppNetAdapterConfig : configuration for one application network adapter.
type AppNetAdapterConfig struct {
	Name       string           // From proto message
	AppMacAddr net.HardwareAddr // If set use it for vif
	AppIPAddr  net.IP           // If set use DHCP to assign to app
	IntfOrder  int32            // XXX need to get from API

	// XXX Shouldn't we use ErrorAndTime here
	// Error
	//	If there is a parsing error and this AppNetAdapterNetwork config cannot be
	//	processed, set the error here. This allows the error to be propagated
	//  back to zedcloud
	Error        string
	Network      uuid.UUID // Points to a NetworkInstance.
	ACLs         []ACE
	AccessVlanID uint32
	IfIdx        uint32 // If we have multiple interfaces on that network, we will increase the index
}

// ACEDirection determines rule direction.
type ACEDirection uint8

const (
	// AceDirBoth : Rule applies in both directions
	AceDirBoth ACEDirection = iota
	// AceDirIngress : Rules applies in Ingress direction (from internet to app)
	AceDirIngress ACEDirection = 1
	// AceDirEgress : Rules applies in Egress direction (from app to internet)
	AceDirEgress ACEDirection = 2
)

// ACE definition is very similar to draft-ietf-netmod-acl-model
type ACE struct {
	Matches []ACEMatch
	Actions []ACEAction
	Name    string
	RuleID  int32
	Dir     ACEDirection
}

// ACEMatch determines which traffic is matched by a given ACE.
// The Type can be "ip" or "host" (aka domain name), "eidset", "protocol",
// "fport", or "lport" for now. The ip and host matches the remote IP/hostname.
// The host matching is suffix-matching thus zededa.net matches *.zededa.net.
// XXX Need "interface"... e.g. "uplink" or "eth1"? Implicit in network used?
// For now the matches are bidirectional.
// XXX Add directionality? Different rate limits in different directions?
// Value is always a string.
// There is an implicit reject rule at the end.
// The "eidset" type is special for the overlay. Matches all the IPs which
// are part of the DNSNameToIPList.
type ACEMatch struct {
	Type  string
	Value string
}

// ACEAction decides what to do with traffic matched by a given ACE.
type ACEAction struct {
	Drop bool // Otherwise accept

	Limit      bool   // Is limiter enabled?
	LimitRate  int    // Packets per unit
	LimitUnit  string // "s", "m", "h", for second, minute, hour
	LimitBurst int    // Packets

	PortMap    bool // Is port mapping part of action?
	TargetPort int  // Internal port
}

// AppNetAdapterStatus : status of application network adapter.
type AppNetAdapterStatus struct {
	AppNetAdapterConfig
	VifInfo
	BridgeMac         net.HardwareAddr
	BridgeIPAddr      net.IP   // The address for DNS/DHCP service in zedrouter
	AllocatedIPv4Addr net.IP   // Assigned to domU
	AllocatedIPv6List []net.IP // IPv6 addresses assigned to domU
	IPv4Assigned      bool     // Set to true once DHCP has assigned it to domU
	IPAddrMisMatch    bool
	HostName          string
}

// NetworkInstanceInfo : info about created Network instance.
type NetworkInstanceInfo struct {
	BridgeNum     int
	BridgeName    string
	BridgeIPAddr  net.IP
	BridgeMac     net.HardwareAddr
	BridgeIfindex int

	// Collection of address assignments; from MAC address to IP address
	IPAssignments map[string]AssignedAddrs

	// Set of vifs on this bridge
	Vifs []VifNameMac

	// Maintain a map of all access vlan ids to their counts, used by apps
	// connected to this network instance.
	VlanMap map[uint32]uint32
	// Counts the number of trunk ports attached to this network instance
	NumTrunkPorts uint32
}

// AssignedAddrs : IP addresses assigned to application network adapter.
type AssignedAddrs struct {
	IPv4Addr  net.IP
	IPv6Addrs []net.IP
}

// VifNameMac : name and MAC address assigned to app VIF.
type VifNameMac struct {
	Name    string
	MacAddr net.HardwareAddr
	AppID   uuid.UUID
}

// IsVifInBridge checks if network instance already contains VIF with the given name.
func (instanceInfo *NetworkInstanceInfo) IsVifInBridge(
	vifName string) bool {
	for _, vif := range instanceInfo.Vifs {
		if vif.Name == vifName {
			return true
		}
	}
	return false
}

// RemoveVif : remove VIF record from network instance info.
func (instanceInfo *NetworkInstanceInfo) RemoveVif(log *base.LogObject,
	vifName string) {
	log.Functionf("RemoveVif(%s, %s)", instanceInfo.BridgeName, vifName)

	found := false
	var vifs []VifNameMac
	for _, vif := range instanceInfo.Vifs {
		if vif.Name != vifName {
			vifs = append(vifs, vif)
		} else {
			found = true
		}
	}
	if !found {
		log.Errorf("RemoveVif(%x, %x) not found",
			instanceInfo.BridgeName, vifName)
	}
	instanceInfo.Vifs = vifs
}

// AddVif : add VIF record into network instance info.
func (instanceInfo *NetworkInstanceInfo) AddVif(log *base.LogObject,
	vifName string, appMac net.HardwareAddr, appID uuid.UUID) {

	log.Functionf("AddVif(%s, %s, %s, %s)",
		instanceInfo.BridgeName, vifName, appMac, appID.String())
	// XXX Should we just overwrite it? There is a lookup function
	//	anyways if the caller wants "check and add" semantics
	if instanceInfo.IsVifInBridge(vifName) {
		log.Errorf("AddVif(%s, %s) exists",
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

// NetworkInstanceMetrics : metrics for a given network instance.
type NetworkInstanceMetrics struct {
	UUIDandVersion UUIDandVersion
	DisplayName    string
	Type           NetworkInstanceType
	BridgeName     string
	NetworkMetrics NetworkMetrics
	ProbeMetrics   ProbeMetrics
	VlanMetrics    VlanMetrics
}

// VlanMetrics : VLAN metrics for a given NI.
type VlanMetrics struct {
	NumTrunkPorts uint32
	VlanCounts    map[uint32]uint32
}

// ProbeMetrics - NI probe metrics
type ProbeMetrics struct {
	SelectedUplinkIntf string             // the uplink interface that probing picked
	RemoteEndpoints    []string           // remote IP/URL addresses used for probing
	LocalPingIntvl     uint32             // local ping interval in seconds
	RemotePingIntvl    uint32             // remote probing interval in seconds
	UplinkCount        uint32             // number of possible uplink interfaces
	IntfProbeStats     []ProbeIntfMetrics // per dom0 intf uplink probing metrics
}

// ProbeIntfMetrics - per dom0 network uplink interface probing
type ProbeIntfMetrics struct {
	IntfName        string   // dom0 uplink interface name
	NexthopIPs      []net.IP // interface local next-hop address(es) used for probing
	NexthopUP       bool     // Is local next-hop in UP status
	RemoteUP        bool     // Is remote endpoint in UP status
	NexthopUPCnt    uint32   // local ping UP count
	NexthopDownCnt  uint32   // local ping DOWN count
	RemoteUPCnt     uint32   // remote probe UP count
	RemoteDownCnt   uint32   // remote probe DOWN count
	LatencyToRemote uint32   // probe latency to remote in msec
}

// Key :
func (metrics NetworkInstanceMetrics) Key() string {
	return metrics.UUIDandVersion.UUID.String()
}

// LogCreate :
func (metrics NetworkInstanceMetrics) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.NetworkInstanceMetricsLogType, "",
		metrics.UUIDandVersion.UUID, metrics.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Network instance metrics create")
}

// LogModify :
func (metrics NetworkInstanceMetrics) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.NetworkInstanceMetricsLogType, "",
		metrics.UUIDandVersion.UUID, metrics.LogKey())

	oldMetrics, ok := old.(NetworkInstanceMetrics)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of NetworkInstanceMetrics type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldMetrics, metrics)).
		Metricf("Network instance metrics modify")
}

// LogDelete :
func (metrics NetworkInstanceMetrics) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.NetworkInstanceMetricsLogType, "",
		metrics.UUIDandVersion.UUID, metrics.LogKey())
	logObject.Metricf("Network instance metrics delete")

	base.DeleteLogObject(logBase, metrics.LogKey())
}

// LogKey :
func (metrics NetworkInstanceMetrics) LogKey() string {
	return string(base.NetworkInstanceMetricsLogType) + "-" + metrics.Key()
}

// NetworkMetrics are for all adapters
// Matches networkMetrics protobuf message.
type NetworkMetrics struct {
	MetricList     []NetworkMetric
	TotalRuleCount uint64
}

// Key is used for pubsub
func (nms NetworkMetrics) Key() string {
	return "global"
}

// LogCreate :
func (nms NetworkMetrics) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.NetworkMetricsLogType, "",
		nilUUID, nms.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("Network metrics create")
}

// LogModify :
func (nms NetworkMetrics) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.NetworkMetricsLogType, "",
		nilUUID, nms.LogKey())

	oldNms, ok := old.(NetworkMetrics)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of NetworkMetrics type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldNms, nms)).
		Metricf("Network metrics modify")
}

// LogDelete :
func (nms NetworkMetrics) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.NetworkMetricsLogType, "",
		nilUUID, nms.LogKey())
	logObject.Metricf("Network metrics delete")

	base.DeleteLogObject(logBase, nms.LogKey())
}

// LogKey :
func (nms NetworkMetrics) LogKey() string {
	return string(base.NetworkMetricsLogType) + "-" + nms.Key()
}

// LookupNetworkMetrics : get metrics collected for a given interface.
func (nms *NetworkMetrics) LookupNetworkMetrics(ifName string) (NetworkMetric, bool) {
	for _, metric := range nms.MetricList {
		if ifName == metric.IfName {
			return metric, true
		}
	}
	return NetworkMetric{}, false
}

// NetworkMetric : metrics for a given network interface.
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

// NetworkInstanceType : type of network instance.
type NetworkInstanceType int32

// These values should be same as the ones defined in zconfig.ZNetworkInstType
const (
	NetworkInstanceTypeFirst       NetworkInstanceType = 0
	NetworkInstanceTypeSwitch      NetworkInstanceType = 1
	NetworkInstanceTypeLocal       NetworkInstanceType = 2
	NetworkInstanceTypeCloud       NetworkInstanceType = 3
	NetworkInstanceTypeHoneyPot    NetworkInstanceType = 5
	NetworkInstanceTypeTransparent NetworkInstanceType = 6
	NetworkInstanceTypeLast        NetworkInstanceType = 255
)

// AddressType : type of network address.
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
//
//	Config Object for NetworkInstance
//	Extracted from the protobuf NetworkInstanceConfig
type NetworkInstanceConfig struct {
	UUIDandVersion
	DisplayName string

	Type NetworkInstanceType

	// Activate - Activate the config.
	Activate bool

	// PortLogicalLabel - references port(s) from DevicePortConfig.
	// Can be a specific logicallabel for an interface, or a tag like "uplink"
	PortLogicalLabel string

	// IP configuration for the Application
	IpType          AddressType
	Subnet          net.IPNet
	Gateway         net.IP
	DomainName      string
	NtpServer       net.IP
	DnsServers      []net.IP // If not set we use Gateway as DNS server
	DhcpRange       IPRange
	DnsNameToIPList []DNSNameToIP // Used for DNS and ACL ipset

	// Route configuration
	PropagateConnRoutes bool
	StaticRoutes        []IPRoute

	// Any errors from the parser
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

// IPRoute : single IP route entry.
type IPRoute struct {
	DstNetwork *net.IPNet
	Gateway    net.IP
}

// IsDefaultRoute returns true if this is a default route, i.e. matches all destinations.
func (r IPRoute) IsDefaultRoute() bool {
	if r.DstNetwork == nil {
		return true
	}
	ones, _ := r.DstNetwork.Mask.Size()
	return r.DstNetwork.IP.IsUnspecified() && ones == 0
}

// Key :
func (config *NetworkInstanceConfig) Key() string {
	return config.UUID.String()
}

// LogCreate :
func (config NetworkInstanceConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.NetworkInstanceConfigLogType, "",
		config.UUIDandVersion.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Network instance config create")
}

// LogModify :
func (config NetworkInstanceConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.NetworkInstanceConfigLogType, "",
		config.UUIDandVersion.UUID, config.LogKey())

	oldConfig, ok := old.(NetworkInstanceConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of NetworkInstanceConfig type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
		Noticef("Network instance config modify")
}

// LogDelete :
func (config NetworkInstanceConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.NetworkInstanceConfigLogType, "",
		config.UUIDandVersion.UUID, config.LogKey())
	logObject.Noticef("Network instance config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config NetworkInstanceConfig) LogKey() string {
	return string(base.NetworkInstanceConfigLogType) + "-" + config.Key()
}

// IsIPv6 returns true if the address is IP version 6.
func (config *NetworkInstanceConfig) IsIPv6() bool {
	switch config.IpType {
	case AddressTypeIPV6:
		return true
	case AddressTypeCryptoIPV6:
		return true
	}
	return false
}

// WithUplinkProbing returns true if the network instance is eligible for uplink
// probing (see pkg/pillar/uplinkprober).
// Uplink probing is performed only for L3 networks with non-empty "shared" uplink
// label, matching a subset of uplink ports.
// Even if a network instance is eligible for probing as determined by this method,
// the actual process of connectivity probing may still be inactive if there are
// no uplink ports available that match the label.
func (config *NetworkInstanceConfig) WithUplinkProbing() bool {
	switch config.Type {
	case NetworkInstanceTypeLocal:
		return IsSharedPortLabel(config.PortLogicalLabel)
	default:
		return false
	}
}

// IsUsingUplinkBridge returns true if the network instance is using the bridge
// created (by NIM) for the uplink port, instead of creating its own bridge.
func (config *NetworkInstanceConfig) IsUsingUplinkBridge() bool {
	switch config.Type {
	case NetworkInstanceTypeSwitch:
		airGapped := config.PortLogicalLabel == ""
		return !airGapped
	default:
		return false
	}
}

const (
	// UplinkLabel references all management interfaces.
	UplinkLabel = "uplink"
	// FreeUplinkLabel references all management interfaces with 0 cost.
	FreeUplinkLabel = "freeuplink"
)

// IsSharedPortLabel : returns true if the logical label references multiple
// ports.
// Currently used labels are:
//   - "uplink": any management interface
//   - "freeuplink": any management interface with 0 cost
func IsSharedPortLabel(label string) bool {
	switch label {
	case UplinkLabel:
		return true
	case FreeUplinkLabel:
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
//
//	Config Object for NetworkInstance
//	Extracted from the protobuf NetworkInstanceConfig
type NetworkInstanceStatus struct {
	NetworkInstanceConfig
	// Make sure the Activate from the config isn't exposed as a boolean
	Activate uint64

	ChangeInProgress ChangeInProgressType
	NIConflict       bool // True if config conflicts with another NI

	// Activated is true if the network instance has been created in the network stack.
	Activated bool

	NetworkInstanceInfo

	// Decided by local/remote probing
	SelectedUplinkLogicalLabel string
	SelectedUplinkIntfName     string

	// True if uplink probing is running
	RunningUplinkProbing bool

	// True if NI is not activated only because of (currently) missing uplink.
	WaitingForUplink bool
}

// LogCreate :
func (status NetworkInstanceStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.NetworkInstanceStatusLogType, "",
		status.UUIDandVersion.UUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Network instance status create")
}

// LogModify :
func (status NetworkInstanceStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.NetworkInstanceStatusLogType, "",
		status.UUIDandVersion.UUID, status.LogKey())

	oldStatus, ok := old.(NetworkInstanceStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of NetworkInstanceStatus type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
		Noticef("Network instance status modify")
}

// LogDelete :
func (status NetworkInstanceStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.NetworkInstanceStatusLogType, "",
		status.UUIDandVersion.UUID, status.LogKey())
	logObject.Noticef("Network instance status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status NetworkInstanceStatus) LogKey() string {
	return string(base.NetworkInstanceStatusLogType) + "-" + status.Key()
}

// IsIpAssigned returns true if the given IP address is assigned to any app VIF.
func (status *NetworkInstanceStatus) IsIpAssigned(ip net.IP) bool {
	for _, assignments := range status.IPAssignments {
		if ip.Equal(assignments.IPv4Addr) {
			return true
		}
		for _, nip := range assignments.IPv6Addrs {
			if ip.Equal(nip) {
				return true
			}
		}
	}
	return false
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
	AppUUID        uuid.UUID
	NetAdapterName string // logical name for VIF (set by controller in NetworkAdapter.Name)
	BrIfName       string
	NetUUID        uuid.UUID
	Sequence       string // used internally for limit and pkt size per app/bn
}

// Key identifies flow.
func (fs FlowScope) Key() string {
	// Use adapter name instead of NI UUID because application can be connected to the same
	// network instance with multiple interfaces.
	key := fs.AppUUID.String() + "-" + fs.NetAdapterName
	if fs.Sequence != "" {
		key += "-" + fs.Sequence
	}
	return key
}

// ACLActionType - action
type ACLActionType uint8

// ACLAction Enum
const (
	ACLActionNone ACLActionType = iota
	ACLActionAccept
	ACLActionDrop
)

// FlowRec :
type FlowRec struct {
	Flow      IPTuple
	Inbound   bool
	ACLID     int32
	Action    ACLActionType
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
	Scope   FlowScope
	Flows   []FlowRec
	DNSReqs []DNSReq
}

// Key :
func (flows IPFlow) Key() string {
	return flows.Scope.Key()
}

// LogCreate : we treat IPFlow as Metrics for logging
func (flows IPFlow) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.IPFlowLogType, "",
		nilUUID, flows.LogKey())
	if logObject == nil {
		return
	}
	logObject.Metricf("IP flow create")
}

// LogModify :
func (flows IPFlow) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.IPFlowLogType, "",
		nilUUID, flows.LogKey())

	oldFlows, ok := old.(IPFlow)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of IPFlow type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldFlows, flows)).
		Metricf("IP flow modify")
}

// LogDelete :
func (flows IPFlow) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.IPFlowLogType, "",
		nilUUID, flows.LogKey())
	logObject.Metricf("IP flow delete")

	base.DeleteLogObject(logBase, flows.LogKey())
}

// LogKey :
func (flows IPFlow) LogKey() string {
	return string(base.IPFlowLogType) + "-" + flows.Key()
}

// AppInstMetaDataType - types of app meta data
type AppInstMetaDataType uint8

// enum app metadata type
const (
	AppInstMetaDataTypeNone AppInstMetaDataType = iota // enum for app inst metadata type
	AppInstMetaDataTypeKubeConfig
	AppInstMetaDataCustomStatus
)

// AppInstMetaData : App Instance Metadata
type AppInstMetaData struct {
	AppInstUUID uuid.UUID
	Data        []byte
	Type        AppInstMetaDataType
}

// Key : App Instance Metadata unique key
func (data AppInstMetaData) Key() string {
	return data.AppInstUUID.String() + "-" + string(data.Type)
}

// At the MinSubnetSize there is room for one app instance (.0 being reserved,
// .3 broadcast, .1 is the bridgeIPAddr, and .2 is usable).
const (
	MinSubnetSize   = 4  // minimum Subnet Size
	LargeSubnetSize = 16 // for determining default Dhcp Range
)

// AppBlobsAvailable provides a list of AppCustom blobs which has been provided
// from the cloud
type AppBlobsAvailable struct {
	CustomMeta  string
	DownloadURL string
}

// AppInfo provides various information to the application
type AppInfo struct {
	AppBlobs []AppBlobsAvailable
}

// AppMACGenerator persistently stores ID of the MAC generator that was used to generate
// MAC addresses for interfaces of a given app.
type AppMACGenerator struct {
	*UuidToNum
}

// New is used by objtonum.ObjNumPublisher.
func (g *AppMACGenerator) New(objKey objtonum.ObjKey) objtonum.ObjNumContainer {
	uuidToNum, ok := g.UuidToNum.New(objKey).(*UuidToNum)
	if !ok {
		logrus.Fatalf("Wrong type returned by UuidToNum.New()")
	}
	return &AppMACGenerator{
		UuidToNum: uuidToNum,
	}
}

// LogCreate logs newly added AppMACGenerator entry.
func (g AppMACGenerator) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.AppMACGeneratorLogType, "",
		g.UUID, g.LogKey())
	logObject.Noticef("AppMACGenerator item create")
}

// LogModify logs modified AppMACGenerator entry.
func (g AppMACGenerator) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.AppMACGeneratorLogType, "",
		g.UUID, g.LogKey())
	oldEntry, ok := old.(AppMACGenerator)
	if !ok {
		logObject.Clone().Fatalf("LogModify: old object is not of AppMACGenerator type")
	}
	logObject.CloneAndAddField("diff", cmp.Diff(oldEntry, g)).
		Noticef("AppMACGenerator item modify")
}

// LogDelete logs deleted AppMACGenerator entry.
func (g AppMACGenerator) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.AppMACGeneratorLogType, "",
		g.UUID, g.LogKey())
	logObject.Noticef("AppMACGenerator item delete")
	base.DeleteLogObject(logBase, g.LogKey())
}

// LogKey identifies AppMACGenerator entry for logging purposes.
func (g AppMACGenerator) LogKey() string {
	return string(base.AppMACGeneratorLogType) + "-" + g.Key()
}

// IDs assigned to different variants of MAC generators.
const (
	// MACGeneratorUnspecified : MAC generator is not specified.
	MACGeneratorUnspecified = 0
	// MACGeneratorNodeScoped generates MAC addresses which are guaranteed to be unique
	// only within the scope of the given single device.
	// The exception are MAC addresses generated for switch network instances,
	// which are always generated with global scope.
	MACGeneratorNodeScoped = 1
	// MACGeneratorGloballyScoped generates MAC addresses which are with high probability
	// unique globally, i.e. across entire fleet of devices.
	MACGeneratorGloballyScoped = 2
)
