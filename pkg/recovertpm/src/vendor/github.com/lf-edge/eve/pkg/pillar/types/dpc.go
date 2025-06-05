// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"reflect"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	uuid "github.com/satori/go.uuid"
)

// DevicePortConfigVersion is used to track major changes in DPC semantics.
type DevicePortConfigVersion uint32

// When new fields and/or new semantics are added to DevicePortConfig a new
// version value is added here.
const (
	DPCInitial DevicePortConfigVersion = iota
	DPCIsMgmt                          // Require IsMgmt to be set for management ports
)

// DPCState tracks the progression a DPC verification.
type DPCState uint8

const (
	// DPCStateNone : undefined state.
	DPCStateNone DPCState = iota
	// DPCStateFail : DPC verification failed.
	DPCStateFail
	// DPCStateFailWithIPAndDNS : failed to reach controller but has IP/DNS.
	DPCStateFailWithIPAndDNS
	// DPCStateSuccess : DPC verification succeeded.
	DPCStateSuccess
	// DPCStateIPDNSWait : waiting for interface IP address(es) and/or DNS server(s).
	DPCStateIPDNSWait
	// DPCStatePCIWait : waiting for some interface to come from pciback.
	DPCStatePCIWait
	// DPCStateIntfWait : waiting for some interface to appear in the network stack.
	DPCStateIntfWait
	// DPCStateRemoteWait : DPC verification failed because controller is down
	// or has old certificate.
	DPCStateRemoteWait
	// DPCStateAsyncWait : waiting for some config operations to finalize which are
	// running asynchronously in the background.
	DPCStateAsyncWait
	// DPCStateWwanWait : waiting for the wwan microservice to apply the latest
	// cellular configuration.
	DPCStateWwanWait
)

// String returns the string name
func (status DPCState) String() string {
	switch status {
	case DPCStateNone:
		return ""
	case DPCStateFail:
		return "DPC_FAIL"
	case DPCStateFailWithIPAndDNS:
		return "DPC_FAIL_WITH_IPANDDNS"
	case DPCStateSuccess:
		return "DPC_SUCCESS"
	case DPCStateIPDNSWait:
		return "DPC_IPDNS_WAIT"
	case DPCStatePCIWait:
		return "DPC_PCI_WAIT"
	case DPCStateIntfWait:
		return "DPC_INTF_WAIT"
	case DPCStateRemoteWait:
		return "DPC_REMOTE_WAIT"
	case DPCStateAsyncWait:
		return "DPC_ASYNC_WAIT"
	case DPCStateWwanWait:
		return "DPC_WWAN_WAIT"
	default:
		return fmt.Sprintf("Unknown status %d", status)
	}
}

const (
	// PortCostMin is the lowest cost
	PortCostMin = uint8(0)
	// PortCostMax is the highest cost
	PortCostMax = uint8(255)
)

const (
	// DefaultMTU : the default Ethernet MTU of 1500 bytes.
	DefaultMTU = 1500
	// MinMTU : minimum accepted MTU value.
	// As per RFC 8200, the MTU must not be less than 1280 bytes to accommodate IPv6 packets.
	MinMTU = 1280
	// MaxMTU : maximum accepted MTU value.
	// The Total Length field of IPv4 and the Payload Length field of IPv6 each have a size
	// of 16 bits, thus allowing data of up to 65535 octets.
	// For now, we will not support IPv6 jumbograms.
	MaxMTU = 65535
)

// DevicePortConfig is a misnomer in that it includes the total test results
// plus the test results for a given port. The complete status with
// IP addresses lives in DeviceNetworkStatus
type DevicePortConfig struct {
	Version      DevicePortConfigVersion
	Key          string
	TimePriority time.Time // All zero's is fallback lowest priority
	State        DPCState
	ShaFile      string // File in which to write ShaValue once DevicePortConfigList published
	ShaValue     []byte
	TestResults
	LastIPAndDNS time.Time // Time when we got some IP addresses and DNS

	Ports []NetworkPortConfig
}

// PubKey is used for pubsub. Key string plus TimePriority
func (config DevicePortConfig) PubKey() string {
	return config.Key + "@" + config.TimePriority.UTC().Format(time.RFC3339Nano)
}

// LogCreate :
func (config DevicePortConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DevicePortConfigLogType, "",
		nilUUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("ports-int64", len(config.Ports)).
		AddField("last-failed", config.LastFailed).
		AddField("last-succeeded", config.LastSucceeded).
		AddField("last-error", config.LastError).
		AddField("last-warning", config.LastWarning).
		AddField("state", config.State.String()).
		Noticef("DevicePortConfig create")
	for _, p := range config.Ports {
		// XXX different logobject for a particular port?
		logObject.CloneAndAddField("ifname", p.IfName).
			AddField("last-error", p.LastError).
			AddField("last-warning", p.LastWarning).
			AddField("last-succeeded", p.LastSucceeded).
			AddField("last-failed", p.LastFailed).
			Noticef("DevicePortConfig port create")
	}
}

// LogModify :
func (config DevicePortConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DevicePortConfigLogType, "",
		nilUUID, config.LogKey())

	oldConfig, ok := old.(DevicePortConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of DevicePortConfig type")
	}
	if len(oldConfig.Ports) != len(config.Ports) ||
		oldConfig.LastFailed != config.LastFailed ||
		oldConfig.LastSucceeded != config.LastSucceeded ||
		oldConfig.LastError != config.LastError ||
		oldConfig.LastWarning != config.LastWarning ||
		oldConfig.State != config.State {

		logData := logObject.CloneAndAddField("ports-int64", len(config.Ports)).
			AddField("last-failed", config.LastFailed).
			AddField("last-succeeded", config.LastSucceeded).
			AddField("last-error", config.LastError).
			AddField("last-warning", config.LastWarning).
			AddField("state", config.State.String()).
			AddField("old-ports-int64", len(oldConfig.Ports)).
			AddField("old-last-failed", oldConfig.LastFailed).
			AddField("old-last-succeeded", oldConfig.LastSucceeded).
			AddField("old-last-error", oldConfig.LastError).
			AddField("old-last-warning", oldConfig.LastWarning).
			AddField("old-state", oldConfig.State.String())
		if len(oldConfig.Ports) == len(config.Ports) &&
			config.LastFailed == oldConfig.LastFailed &&
			config.LastError == oldConfig.LastError &&
			config.LastWarning == oldConfig.LastWarning &&
			oldConfig.State == config.State &&
			config.LastSucceeded.After(oldConfig.LastFailed) &&
			oldConfig.LastSucceeded.After(oldConfig.LastFailed) {
			// if we have success again, reduce log level
			logData.Function("DevicePortConfig modify")
		} else {
			logData.Notice("DevicePortConfig modify")
		}
	}
	// XXX which fields to compare/log?
	for i, p := range config.Ports {
		if len(oldConfig.Ports) <= i {
			continue
		}
		op := oldConfig.Ports[i]
		// XXX different logobject for a particular port?
		if p.HasError() != op.HasError() ||
			p.LastFailed != op.LastFailed ||
			p.LastSucceeded != op.LastSucceeded ||
			p.LastError != op.LastError ||
			p.LastWarning != op.LastWarning {
			logData := logObject.CloneAndAddField("ifname", p.IfName).
				AddField("last-error", p.LastError).
				AddField("last-warning", p.LastWarning).
				AddField("last-succeeded", p.LastSucceeded).
				AddField("last-failed", p.LastFailed).
				AddField("old-last-error", op.LastError).
				AddField("old-last-warning", op.LastWarning).
				AddField("old-last-succeeded", op.LastSucceeded).
				AddField("old-last-failed", op.LastFailed)
			if p.HasError() == op.HasError() &&
				p.LastError == op.LastError &&
				p.LastWarning == op.LastWarning {
				// if we have success or the same error again, reduce log level
				logData.Function("DevicePortConfig port modify")
			} else {
				logData.Notice("DevicePortConfig port modify")
			}
		}
	}
}

// LogDelete :
func (config DevicePortConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DevicePortConfigLogType, "",
		nilUUID, config.LogKey())
	logObject.CloneAndAddField("ports-int64", len(config.Ports)).
		AddField("last-failed", config.LastFailed).
		AddField("last-succeeded", config.LastSucceeded).
		AddField("last-error", config.LastError).
		AddField("last-warning", config.LastWarning).
		AddField("state", config.State.String()).
		Noticef("DevicePortConfig delete")
	for _, p := range config.Ports {
		// XXX different logobject for a particular port?
		logObject.CloneAndAddField("ifname", p.IfName).
			AddField("last-error", p.LastError).
			AddField("last-warning", p.LastWarning).
			AddField("last-succeeded", p.LastSucceeded).
			AddField("last-failed", p.LastFailed).
			Noticef("DevicePortConfig port delete")
	}

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config DevicePortConfig) LogKey() string {
	return string(base.DevicePortConfigLogType) + "-" + config.PubKey()
}

// LookupPortByIfName returns port configuration for the given interface.
func (config *DevicePortConfig) LookupPortByIfName(ifName string) *NetworkPortConfig {
	for i := range config.Ports {
		port := &config.Ports[i]
		if ifName == port.IfName {
			return port
		}
	}
	return nil
}

// LookupPortByLogicallabel returns port configuration referenced by the logical label.
func (config *DevicePortConfig) LookupPortByLogicallabel(
	label string) *NetworkPortConfig {
	for i := range config.Ports {
		port := &config.Ports[i]
		if port.Logicallabel == label {
			return port
		}
	}
	return nil
}

// LookupPortsByLabel returns all port configurations with the given label assigned
// (can be logical label or shared label).
func (config *DevicePortConfig) LookupPortsByLabel(
	label string) (ports []*NetworkPortConfig) {
	for i := range config.Ports {
		port := &config.Ports[i]
		if port.Logicallabel == label || generics.ContainsItem(port.SharedLabels, label) {
			ports = append(ports, port)
		}
	}
	return ports
}

// RecordPortSuccess - Record for given ifname in PortConfig
func (config *DevicePortConfig) RecordPortSuccess(ifname string) {
	portPtr := config.LookupPortByIfName(ifname)
	if portPtr != nil {
		portPtr.RecordSuccess()
	}
}

// RecordPortFailure - Record for given ifname in PortConfig
func (config *DevicePortConfig) RecordPortFailure(ifname string, errStr string) {
	portPtr := config.LookupPortByIfName(ifname)
	if portPtr != nil {
		portPtr.RecordFailure(errStr)
	}
}

// IsPortUsedAsVlanParent - returns true if port with the given logical label
// is used as a VLAN parent interface.
func (config DevicePortConfig) IsPortUsedAsVlanParent(portLabel string) bool {
	for _, port2 := range config.Ports {
		if port2.L2Type == L2LinkTypeVLAN && port2.VLAN.ParentPort == portLabel {
			return true
		}
	}
	return false
}

// DPCSanitizeArgs : arguments for DevicePortConfig.DoSanitize().
type DPCSanitizeArgs struct {
	SanitizeTimePriority bool
	SanitizeKey          bool
	KeyToUseIfEmpty      string
	SanitizeName         bool
	SanitizeL3Port       bool
	SanitizeSharedLabels bool
}

// DoSanitize ensures that some of the DPC attributes that could be missing
// in a user-injected override.json or after an EVE upgrade are filled in.
func (config *DevicePortConfig) DoSanitize(log *base.LogObject, args DPCSanitizeArgs) {
	if args.SanitizeKey {
		if config.Key == "" {
			config.Key = args.KeyToUseIfEmpty
			log.Noticef("DoSanitize: Forcing Key for %s TS %v\n",
				config.Key, config.TimePriority)
		}
	}
	if args.SanitizeTimePriority {
		zeroTime := time.Time{}
		if config.TimePriority == zeroTime {
			// A json override file should really contain a
			// timepriority field so we can determine whether
			// it or the information received from the controller
			// is more current.
			// If we can stat the file we use 1980, otherwise
			// we use 1970; using the modify time of the file
			// is too unpredictable.
			_, err1 := os.Stat(fmt.Sprintf("%s/DevicePortConfig/%s.json",
				TmpDirname, config.Key))
			_, err2 := os.Stat(fmt.Sprintf("%s/DevicePortConfig/%s.json",
				IdentityDirname, config.Key))
			if err1 == nil || err2 == nil {
				config.TimePriority = time.Date(1980,
					time.January, 1, 0, 0, 0, 0, time.UTC)
			} else {
				config.TimePriority = time.Date(1970,
					time.January, 1, 0, 0, 0, 0, time.UTC)
			}
			log.Warnf("DoSanitize: Forcing TimePriority for %s to %v",
				config.Key, config.TimePriority)
		}
	}
	if args.SanitizeName {
		// In case Phylabel isn't set we make it match IfName. Ditto for Logicallabel
		// XXX still needed?
		for i := range config.Ports {
			port := &config.Ports[i]
			if port.Phylabel == "" {
				port.Phylabel = port.IfName
				log.Functionf("XXX DoSanitize: Forcing Phylabel for %s ifname %s\n",
					config.Key, port.IfName)
			}
			if port.Logicallabel == "" {
				port.Logicallabel = port.IfName
				log.Functionf("XXX DoSanitize: Forcing Logicallabel for %s ifname %s\n",
					config.Key, port.IfName)
			}
		}
	}
	if args.SanitizeL3Port {
		// IsL3Port flag was introduced to NetworkPortConfig in 7.3.0
		// It is used to differentiate between L3 ports (with IP/DNS config)
		// and intermediate L2-only ports (bond slaves, VLAN parents, etc.).
		// Before 7.3.0, EVE didn't support L2-only adapters and all uplink ports
		// were L3 endpoints.
		// However, even with VLANs and bonds there has to be at least one L3
		// port (L2 adapters are only intermediates with L3 endpoint(s) at the top).
		// This means that to support upgrade from older EVE versions,
		// we can simply check if there is at least one L3 port, and if not, it means
		// that we are dealing with an older persisted/override DPC, where all
		// ports should be marked as L3.
		var hasL3Port bool
		for _, port := range config.Ports {
			hasL3Port = hasL3Port || port.IsL3Port
		}
		if !hasL3Port {
			for i := range config.Ports {
				config.Ports[i].IsL3Port = true
			}
		}
	}
	if args.SanitizeSharedLabels {
		// When upgrading from older EVE version or importing override.json,
		// shared labels can be missing.
		for i := range config.Ports {
			config.Ports[i].UpdateEveDefinedSharedLabels()
		}
	}
}

// CountMgmtPorts returns the number of management ports
// Exclude any broken ones with Dhcp = DhcpTypeNone
// Optionally exclude mgmt ports with invalid config
func (config *DevicePortConfig) CountMgmtPorts(onlyValidConfig bool) int {
	count := 0
	for _, port := range config.Ports {
		if port.IsMgmt && port.Dhcp != DhcpTypeNone &&
			!(onlyValidConfig && port.InvalidConfig) {
			count++
		}
	}
	return count
}

// MostlyEqual compares two DevicePortConfig but skips things that are
// more of status such as the timestamps and the TestResults
// XXX Compare Version or not?
// We compare the Ports in array order.
func (config *DevicePortConfig) MostlyEqual(config2 *DevicePortConfig) bool {

	if config.Key != config2.Key {
		return false
	}
	if len(config.Ports) != len(config2.Ports) {
		return false
	}
	for i, p1 := range config.Ports {
		p2 := config2.Ports[i]
		if p1.IfName != p2.IfName ||
			p1.PCIAddr != p2.PCIAddr ||
			p1.USBAddr != p2.USBAddr ||
			p1.Phylabel != p2.Phylabel ||
			p1.Logicallabel != p2.Logicallabel ||
			!generics.EqualSets(p1.SharedLabels, p2.SharedLabels) ||
			p1.Alias != p2.Alias ||
			p1.IsMgmt != p2.IsMgmt ||
			p1.Cost != p2.Cost ||
			p1.MTU != p2.MTU {
			return false
		}
		if !reflect.DeepEqual(p1.DhcpConfig, p2.DhcpConfig) ||
			!reflect.DeepEqual(p1.ProxyConfig, p2.ProxyConfig) ||
			!reflect.DeepEqual(p1.WirelessCfg, p2.WirelessCfg) {
			return false
		}
	}
	return true
}

// IsDPCTestable - Return false if recent failure (less than "minTimeSinceFailure")
// Also returns false if it isn't usable
func (config DevicePortConfig) IsDPCTestable(minTimeSinceFailure time.Duration) bool {
	if !config.IsDPCUsable() {
		return false
	}
	if config.LastFailed.IsZero() {
		return true
	}
	if config.LastSucceeded.After(config.LastFailed) {
		return true
	}
	if config.LastFailed.After(time.Now()) {
		// Clocks are not in sync - most likely they are still around
		// the start of the epoch.
		// Network is likely needed to synchronize the clocks using NTP,
		// and we should attempt to establish network connectivity using
		// any DPC available.
		return true
	}
	return time.Since(config.LastFailed) >= minTimeSinceFailure
}

// IsDPCUntested - returns true if this is something we might want to test now.
// Checks if it is Usable since there is no point in testing unusable things.
func (config DevicePortConfig) IsDPCUntested() bool {
	if config.LastFailed.IsZero() && config.LastSucceeded.IsZero() &&
		config.IsDPCUsable() {
		return true
	}
	return false
}

// IsDPCUsable - checks whether something is invalid; no management IP
// addresses means it isn't usable hence we return false if none.
func (config DevicePortConfig) IsDPCUsable() bool {
	mgmtCount := config.CountMgmtPorts(true)
	return mgmtCount > 0
}

// WasDPCWorking - Check if the last results for the DPC was Success
func (config DevicePortConfig) WasDPCWorking() bool {

	if config.LastSucceeded.IsZero() {
		return false
	}
	if config.LastSucceeded.After(config.LastFailed) {
		return true
	}
	return false
}

// UpdatePortStatusFromIntfStatusMap - Set TestResults for ports in DevicePortConfig to
// those from intfStatusMap. If a port is not found in intfStatusMap, it means
// the port was not tested, so we retain the original TestResults for the port.
func (config *DevicePortConfig) UpdatePortStatusFromIntfStatusMap(
	intfStatusMap IntfStatusMap) {
	for indx := range config.Ports {
		portPtr := &config.Ports[indx]
		tr, ok := intfStatusMap.StatusMap[portPtr.IfName]
		if ok {
			portPtr.TestResults.Update(tr)
		}
		// Else - Port not tested hence no change
	}
}

// IsAnyPortInPciBack
//
//	Checks if any of the Ports are part of IO bundles which are in PCIback.
//	If true, it also returns the ifName ( NOT bundle name )
//	Also returns whether it is currently used by an application by
//	returning a UUID. If the UUID is zero it is in PCIback but available.
//	Use filterUnassigned to filter out unassigned ports.
func (config *DevicePortConfig) IsAnyPortInPciBack(
	log *base.LogObject, aa *AssignableAdapters, filterUnassigned bool) (bool, string, uuid.UUID) {
	if aa == nil {
		log.Functionf("IsAnyPortInPciBack: nil aa")
		return false, "", uuid.UUID{}
	}
	log.Functionf("IsAnyPortInPciBack: aa init %t, %d bundles, %d ports",
		aa.Initialized, len(aa.IoBundleList), len(config.Ports))
	for _, port := range config.Ports {
		ioBundle := aa.LookupIoBundleIfName(port.IfName)
		if ioBundle == nil {
			// It is not guaranteed that all Ports are part of Assignable Adapters
			// If not found, the adapter is not capable of being assigned at
			// PCI level. So it cannot be in PCI back.
			log.Functionf("IsAnyPortInPciBack: ifname %s not found",
				port.IfName)
			continue
		}
		if ioBundle.IsPCIBack && (!filterUnassigned || ioBundle.UsedByUUID != nilUUID) {
			return true, port.IfName, ioBundle.UsedByUUID
		}
	}
	return false, "", uuid.UUID{}
}

// NetworkPortConfig has the configuration and some status like TestResults
// for one IfName.
// XXX odd to have ParseErrors and/or TestResults here but we don't have
// a corresponding Status struct.
// Note that if fields are added the MostlyEqual function needs to be updated.
type NetworkPortConfig struct {
	IfName       string
	USBAddr      string
	PCIAddr      string
	Phylabel     string // Physical name set by controller/model
	Logicallabel string // SystemAdapter's name which is logical label in phyio
	// Unlike the logicallabel, which is defined in the device model and unique
	// for each port, these user-configurable "shared" labels are potentially
	// assigned to multiple ports so that they can be used all together with
	// some config object (e.g. multiple ports assigned to NI).
	// Some special shared labels, such as "uplink" or "freeuplink", are assigned
	// to particular ports automatically.
	SharedLabels []string
	Alias        string // From SystemAdapter's alias
	// NetworkUUID - UUID of the Network Object configured for the port.
	NetworkUUID uuid.UUID
	IsMgmt      bool // Used to talk to controller
	IsL3Port    bool // True if port is applicable to operate on the network layer
	// InvalidConfig is used to flag port config which failed parsing or (static) validation
	// checks, such as: malformed IP address, undefined required field, IP address not inside
	// the subnet, etc.
	InvalidConfig bool
	Cost          uint8 // Zero is free
	MTU           uint16
	DhcpConfig
	ProxyConfig
	L2LinkConfig
	WirelessCfg WirelessConfig
	// TestResults - Errors from parsing plus success/failure from testing
	TestResults
	IgnoreDhcpNtpServers bool
}

// EVE-defined port labels.
const (
	// AllPortsLabel references all device ports.
	AllPortsLabel = "all"
	// UplinkLabel references all management ports.
	UplinkLabel = "uplink"
	// FreeUplinkLabel references all management ports with 0 cost.
	FreeUplinkLabel = "freeuplink"
)

// IsEveDefinedPortLabel returns true if the given port label is defined by EVE
// and not by the user.
func IsEveDefinedPortLabel(label string) bool {
	switch label {
	case AllPortsLabel, UplinkLabel, FreeUplinkLabel:
		return true
	}
	return false
}

// UpdateEveDefinedSharedLabels updates EVE-defined shared labels that this port
// should have based on its properties.
func (port *NetworkPortConfig) UpdateEveDefinedSharedLabels() {
	// First remove any EVE-defined shared labels from the list.
	isUserLabel := func(label string) bool {
		return !IsEveDefinedPortLabel(label)
	}
	port.SharedLabels = generics.FilterList(port.SharedLabels, isUserLabel)
	// (Re-)Add shared labels that this port should have based on its config.
	port.SharedLabels = append(port.SharedLabels, AllPortsLabel)
	if port.IsMgmt {
		port.SharedLabels = append(port.SharedLabels, UplinkLabel)
	}
	if port.IsMgmt && port.Cost == 0 {
		port.SharedLabels = append(port.SharedLabels, FreeUplinkLabel)
	}
	port.SharedLabels = generics.FilterDuplicates(port.SharedLabels)
}

// DhcpType decides how EVE should obtain IP address for a given network port.
type DhcpType uint8

const (
	// DhcpTypeNOOP : DHCP type is undefined.
	DhcpTypeNOOP DhcpType = iota
	// DhcpTypeStatic : static IP config.
	DhcpTypeStatic
	// DhcpTypeNone : DHCP passthrough for switch NI
	// (between app VIF and external DHCP server).
	DhcpTypeNone
	// DhcpTypeDeprecated : defined here just to match deprecated value in EVE API.
	DhcpTypeDeprecated
	// DhcpTypeClient : run DHCP client to obtain IP address.
	DhcpTypeClient
)

// NetworkType decided IP version(s) that EVE should use for a given network port.
type NetworkType uint8

const (
	// NetworkTypeNOOP : network type is undefined.
	NetworkTypeNOOP NetworkType = 0
	// NetworkTypeIPv4 : IPv4 addresses.
	NetworkTypeIPv4 NetworkType = 4
	// NetworkTypeIPV6 : IPv6 addresses.
	NetworkTypeIPV6 NetworkType = 6

	// EVE has been running with Dual stack DHCP behavior with both IPv4 & IPv6 specific networks.
	// There can be users who are currently benefiting from this behavior.
	// It makes sense to introduce two new types IPv4_ONLY & IPv6_ONLY and allow
	// the same family selection from UI for the use cases where only one of the IP families
	// is required on management/app-shared adapters.

	// NetworkTypeIpv4Only : IPv4 addresses only
	NetworkTypeIpv4Only NetworkType = 5
	// NetworkTypeIpv6Only : IPv6 addresses only
	NetworkTypeIpv6Only NetworkType = 7
	// NetworkTypeDualStack : Run with dual stack
	NetworkTypeDualStack NetworkType = 8
)

// DhcpConfig : DHCP configuration for network port.
type DhcpConfig struct {
	Dhcp       DhcpType // If DhcpTypeStatic use below; if DhcpTypeNone do nothing
	AddrSubnet string   // In CIDR e.g., 192.168.1.44/24
	Gateway    net.IP
	DomainName string
	NTPServers []string
	DNSServers []net.IP    // If not set we use Gateway as DNS server
	Type       NetworkType // IPv4 or IPv6 or Dual stack
}

// NetworkProxyType is used to differentiate proxies for different network protocols.
type NetworkProxyType uint8

// Values if these definitions should match the values
// given to the types in zapi.ProxyProto
const (
	NetworkProxyTypeHTTP NetworkProxyType = iota
	NetworkProxyTypeHTTPS
	NetworkProxyTypeSOCKS
	NetworkProxyTypeFTP
	NetworkProxyTypeNOPROXY
	NetworkProxyTypeLAST = 255
)

// ProxyEntry is used to store address of a single network proxy.
type ProxyEntry struct {
	Type   NetworkProxyType `json:"type"`
	Server string           `json:"server"`
	Port   uint32           `json:"port"`
}

// ProxyConfig : proxy configuration for a network port.
type ProxyConfig struct {
	Proxies    []ProxyEntry
	Exceptions string
	Pacfile    string
	// If Enable is set we use WPAD. If the URL is not set we try
	// the various DNS suffixes until we can download a wpad.dat file
	NetworkProxyEnable bool   // Enable WPAD
	NetworkProxyURL    string // Complete URL i.e., with /wpad.dat
	WpadURL            string // The URL determined from DNS
	// List of certs which will be added to TLS trust
	ProxyCertPEM [][]byte `json:"pubsub-large-ProxyCertPEM"` //nolint:tagliatelle
}

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

// WirelessConfig - wireless structure
type WirelessConfig struct {
	// WType : Wireless Type, either Cellular or WiFi.
	WType WirelessType
	// CellularV2 : configuration for Cellular connectivity.
	// This is version 2 of the cellular APIs. With the introduction of support
	// for multiple modems and multiple SIMs, the previously used CellConfig
	// structure was no longer suitable for storing all the new config attributes.
	CellularV2 CellNetPortConfig
	// Wifi : configuration for WiFi connectivity.
	Wifi []WifiConfig
	// Cellular : old and now deprecated structure for the cellular connectivity
	// configuration (aka version 1).
	// It is kept here only for backward-compatibility, i.e. to support upgrades from
	// EVE versions which still use this structure.
	Cellular []DeprecatedCellConfig
}

// IsEmpty returns true if the wireless config is empty.
func (wc WirelessConfig) IsEmpty() bool {
	switch wc.WType {
	case WirelessTypeWifi:
		return len(wc.Wifi) == 0
	case WirelessTypeCellular:
		return len(wc.CellularV2.AccessPoints) == 0 &&
			len(wc.Cellular) == 0
	}
	return true
}

// WifiConfig - Wifi structure
type WifiConfig struct {
	SSID      string            // wifi SSID
	KeyScheme WifiKeySchemeType // such as WPA-PSK, WPA-EAP

	// XXX: to be deprecated, use CipherBlockStatus instead
	Identity string // identity or username for WPA-EAP

	// XXX: to be deprecated, use CipherBlockStatus instead
	Password string // string of pass phrase or password hash
	Priority int32

	// CipherBlockStatus, for encrypted credentials
	CipherBlockStatus
}

// DeprecatedCellConfig : old and now deprecated structure for storing cellular
// network port config. It is preserved only to support upgrades from older EVE
// versions where this is still being used (under the original struct name "CellConfig")
type DeprecatedCellConfig struct {
	APN              string
	ProbeAddr        string
	DisableProbe     bool
	LocationTracking bool
}

// CellNetPortConfig - configuration for cellular network port (part of DPC).
type CellNetPortConfig struct {
	// Parameters to apply for connecting to cellular networks.
	// Configured separately for every SIM card inserted into the modem.
	AccessPoints []CellularAccessPoint
	// Probe used to detect broken connection.
	Probe WwanProbe
	// Enable to get location info from the GNSS receiver of the cellular modem.
	LocationTracking bool
}

// CellularAccessPoint contains config parameters for connecting to a cellular network.
type CellularAccessPoint struct {
	// SIM card slot to which this configuration applies.
	// 0 - unspecified (apply to currently activated or the only available)
	// 1 - config for SIM card in the first slot
	// 2 - config for SIM card in the second slot
	// etc.
	SIMSlot uint8
	// If true, then this configuration is currently activated.
	Activated bool
	// Access Point Network for the default bearer.
	APN string
	// The IP addressing type to use for the default bearer.
	IPType WwanIPType
	// Authentication protocol used for the default bearer.
	AuthProtocol WwanAuthProtocol
	// Encrypted user credentials for the default bearer and/or the attach bearer
	// (when required).
	EncryptedCredentials CipherBlockStatus
	// The set of cellular network operators that modem should preferably try to register
	// and connect into.
	// Network operator should be referenced by PLMN (Public Land Mobile Network) code.
	PreferredPLMNs []string
	// The list of preferred Radio Access Technologies (RATs) to use for connecting
	// to the network.
	PreferredRATs []WwanRAT
	// If true, then modem will avoid connecting to networks with roaming.
	ForbidRoaming bool
	// Access Point Network for the attach (aka initial) bearer.
	AttachAPN string
	// The IP addressing type to use for the attach bearer.
	AttachIPType WwanIPType
	// Authentication protocol used for the attach bearer.
	AttachAuthProtocol WwanAuthProtocol
}

// Equal compares two instances of CellularAccessPoint for equality.
func (ap CellularAccessPoint) Equal(ap2 CellularAccessPoint) bool {
	if ap.SIMSlot != ap2.SIMSlot ||
		ap.Activated != ap2.Activated ||
		ap.APN != ap2.APN ||
		ap.IPType != ap2.IPType ||
		ap.AuthProtocol != ap2.AuthProtocol ||
		!ap.EncryptedCredentials.Equal(ap2.EncryptedCredentials) {
		return false
	}
	if !generics.EqualLists(ap.PreferredPLMNs, ap2.PreferredPLMNs) ||
		!generics.EqualLists(ap.PreferredRATs, ap2.PreferredRATs) ||
		ap.ForbidRoaming != ap2.ForbidRoaming {
		return false
	}
	if ap.AttachAPN != ap2.AttachAPN ||
		ap.AttachIPType != ap2.AttachIPType ||
		ap.AttachAuthProtocol != ap2.AttachAuthProtocol {
		return false
	}
	return true
}

// L2LinkType - supported types of an L2 link
type L2LinkType uint8

const (
	// L2LinkTypeNone : not an L2 link (used for physical network adapters).
	L2LinkTypeNone L2LinkType = iota
	// L2LinkTypeVLAN : VLAN sub-interface
	L2LinkTypeVLAN
	// L2LinkTypeBond : Bond interface
	L2LinkTypeBond
)

// L2LinkConfig - contains either VLAN or Bond interface configuration,
// depending on the L2Type.
type L2LinkConfig struct {
	L2Type L2LinkType
	VLAN   VLANConfig
	Bond   BondConfig
}

// VLANConfig - VLAN sub-interface configuration.
type VLANConfig struct {
	// Logical name of the parent port.
	ParentPort string
	// VLAN ID.
	ID uint16
}

// BondMode specifies the policy indicating how bonding slaves are used
// during network transmissions.
type BondMode uint8

const (
	// BondModeUnspecified : default is Round-Robin
	BondModeUnspecified BondMode = iota
	// BondModeBalanceRR : Round-Robin
	BondModeBalanceRR
	// BondModeActiveBackup : Active/Backup
	BondModeActiveBackup
	// BondModeBalanceXOR : select slave for a packet using a hash function
	BondModeBalanceXOR
	// BondModeBroadcast : send every packet on all slaves
	BondModeBroadcast
	// BondMode802Dot3AD : IEEE 802.3ad Dynamic link aggregation
	BondMode802Dot3AD
	// BondModeBalanceTLB : Adaptive transmit load balancing
	BondModeBalanceTLB
	// BondModeBalanceALB : Adaptive load balancing
	BondModeBalanceALB
)

// LacpRate specifies the rate in which EVE will ask LACP link partners
// to transmit LACPDU packets in 802.3ad mode.
type LacpRate uint8

const (
	// LacpRateUnspecified : default is Slow.
	LacpRateUnspecified LacpRate = iota
	// LacpRateSlow : Request partner to transmit LACPDUs every 30 seconds.
	LacpRateSlow
	// LacpRateFast : Request partner to transmit LACPDUs every 1 second.
	LacpRateFast
)

// BondConfig - Bond (LAG) interface configuration.
type BondConfig struct {
	// Logical names of PhysicalIO network adapters aggregated by this bond.
	AggregatedPorts []string

	// Bonding policy.
	Mode BondMode

	// LACPDU packets transmission rate.
	// Applicable for BondMode802Dot3AD only.
	LacpRate LacpRate

	// Link monitoring is either disabled or one of the monitors
	// is enabled, never both at the same time.
	MIIMonitor BondMIIMonitor
	ARPMonitor BondArpMonitor
}

// BondMIIMonitor : MII link monitoring parameters (see devmodel.proto for description).
type BondMIIMonitor struct {
	Enabled   bool
	Interval  uint32
	UpDelay   uint32
	DownDelay uint32
}

// BondArpMonitor : ARP-based link monitoring parameters (see devmodel.proto for description).
type BondArpMonitor struct {
	Enabled   bool
	Interval  uint32
	IPTargets []net.IP
}

// Equal compares two BondArpMonitor configs for equality.
func (m BondArpMonitor) Equal(m2 BondArpMonitor) bool {
	return m.Enabled == m2.Enabled &&
		m.Interval == m2.Interval &&
		generics.EqualSetsFn(m.IPTargets, m2.IPTargets, netutils.EqualIPs)
}

// DevicePortConfigList is an array in timestamp aka priority order;
// first one is the most desired config to use
// It includes test results hence is misnamed - should have a separate status
// This is only published under the key "global"
type DevicePortConfigList struct {
	CurrentIndex   int
	PortConfigList []DevicePortConfig
}

// MostlyEqual - Equal if everything else other than timestamps is equal.
func (config DevicePortConfigList) MostlyEqual(config2 DevicePortConfigList) bool {

	if len(config.PortConfigList) != len(config2.PortConfigList) {
		return false
	}
	if config.CurrentIndex != config2.CurrentIndex {
		return false
	}
	for i, c1 := range config.PortConfigList {
		c2 := config2.PortConfigList[i]

		if !c1.MostlyEqual(&c2) || c1.State != c2.State {
			return false
		}
	}
	return true
}

// PubKey is used for pubsub
func (config DevicePortConfigList) PubKey() string {
	return "global"
}

// LogCreate :
func (config DevicePortConfigList) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DevicePortConfigListLogType, "",
		nilUUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("current-index-int64", config.CurrentIndex).
		AddField("num-portconfig-int64", len(config.PortConfigList)).
		Noticef("DevicePortConfigList create")
}

// LogModify :
func (config DevicePortConfigList) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DevicePortConfigListLogType, "",
		nilUUID, config.LogKey())

	oldConfig, ok := old.(DevicePortConfigList)
	if !ok {
		logObject.Clone().Errorf("LogModify: Old object interface passed is not of DevicePortConfigList type")
		return
	}
	if oldConfig.CurrentIndex != config.CurrentIndex ||
		len(oldConfig.PortConfigList) != len(config.PortConfigList) {

		logObject.CloneAndAddField("current-index-int64", config.CurrentIndex).
			AddField("num-portconfig-int64", len(config.PortConfigList)).
			AddField("old-current-index-int64", oldConfig.CurrentIndex).
			AddField("old-num-portconfig-int64", len(oldConfig.PortConfigList)).
			Noticef("DevicePortConfigList modify")
	} else {
		// Log at Trace level - most likely just a timestamp change
		logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
			Tracef("DevicePortConfigList modify other change")
	}

}

// LogDelete :
func (config DevicePortConfigList) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DevicePortConfigListLogType, "",
		nilUUID, config.LogKey())
	logObject.CloneAndAddField("current-index-int64", config.CurrentIndex).
		AddField("num-portconfig-int64", len(config.PortConfigList)).
		Noticef("DevicePortConfigList delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config DevicePortConfigList) LogKey() string {
	return string(base.DevicePortConfigListLogType) + "-" + config.PubKey()
}

// NetworkXObjectConfig is extracted from the protobuf NetworkConfig.
// Used by zedagent as an intermediate structure when parsing network config
// from protobuf API into DevicePortConfig.
// XXX replace by inline once we have device model
type NetworkXObjectConfig struct {
	UUID                 uuid.UUID
	Type                 NetworkType
	Dhcp                 DhcpType // If DhcpTypeStatic or DhcpTypeClient use below
	Subnet               net.IPNet
	Gateway              net.IP
	DomainName           string
	NTPServers           []string
	IgnoreDhcpNtpServers bool
	DNSServers           []net.IP // If not set we use Gateway as DNS server
	DhcpRange            IPRange
	DNSNameToIPList      []DNSNameToIP // Used for DNS and ACL ipset
	Proxy                *ProxyConfig
	WirelessCfg          WirelessConfig
	MTU                  uint16
	// Any errors from the parser
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

// DNSNameToIP : static mapping between hostname and IP addresses.
type DNSNameToIP struct {
	HostName string
	IPs      []net.IP
}

// IPRange : range of consecutive IP addresses.
type IPRange struct {
	Start net.IP
	End   net.IP
}

// Contains used to evaluate whether an IP address
// is within the range
func (ipRange IPRange) Contains(ipAddr net.IP) bool {
	if bytes.Compare(ipAddr, ipRange.Start) >= 0 &&
		bytes.Compare(ipAddr, ipRange.End) <= 0 {
		return true
	}
	return false
}

// Size returns addresses count inside IPRange
func (ipRange IPRange) Size() uint32 {
	//TBD:XXX, IPv6 handling
	ip1v4 := ipRange.Start.To4()
	ip2v4 := ipRange.End.To4()
	if ip1v4 == nil || ip2v4 == nil {
		return 0
	}
	ip1Int := binary.BigEndian.Uint32(ip1v4)
	ip2Int := binary.BigEndian.Uint32(ip2v4)
	if ip1Int > ip2Int {
		return ip1Int - ip2Int
	}
	return ip2Int - ip1Int
}

func (config NetworkXObjectConfig) Key() string {
	return config.UUID.String()
}

// LogCreate :
func (config NetworkXObjectConfig) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.NetworkXObjectConfigLogType, "",
		config.UUID, config.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("NetworkXObject config create")
}

// LogModify :
func (config NetworkXObjectConfig) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.NetworkXObjectConfigLogType, "",
		config.UUID, config.LogKey())

	oldConfig, ok := old.(NetworkXObjectConfig)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of NetworkXObjectConfig type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldConfig, config)).
		Noticef("NetworkXObject config modify")
}

// LogDelete :
func (config NetworkXObjectConfig) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.NetworkXObjectConfigLogType, "",
		config.UUID, config.LogKey())
	logObject.Noticef("NetworkXObject config delete")

	base.DeleteLogObject(logBase, config.LogKey())
}

// LogKey :
func (config NetworkXObjectConfig) LogKey() string {
	return string(base.NetworkXObjectConfigLogType) + "-" + config.Key()
}
