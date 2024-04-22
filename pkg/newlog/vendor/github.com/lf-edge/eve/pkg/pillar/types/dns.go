// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"sort"
	"time"

	"github.com/eriknordmark/ipinfo"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
)

// DeviceNetworkStatus is published to microservices which needs to know about ports and IP addresses
// It is published under the key "global" only
type DeviceNetworkStatus struct {
	DPCKey       string                  // For logs/testing
	Version      DevicePortConfigVersion // From DevicePortConfig
	Testing      bool                    // Ignore since it is not yet verified
	State        DPCState                // Details about testing state
	CurrentIndex int                     // For logs
	RadioSilence RadioSilence            // The actual state of the radio-silence mode
	Ports        []NetworkPortStatus
}

type NetworkPortStatus struct {
	IfName         string
	Phylabel       string // Physical name set by controller/model
	Logicallabel   string
	Alias          string // From SystemAdapter's alias
	IsMgmt         bool   // Used to talk to controller
	IsL3Port       bool   // True if port is applicable to operate on the network layer
	Cost           uint8
	Dhcp           DhcpType
	Type           NetworkType // IPv4 or IPv6 or Dual stack
	Subnet         net.IPNet
	NtpServer      net.IP // This comes from network instance configuration
	DomainName     string
	DNSServers     []net.IP // If not set we use Gateway as DNS server
	NtpServers     []net.IP // This comes from DHCP done on uplink port
	AddrInfoList   []AddrInfo
	Up             bool
	MacAddr        net.HardwareAddr
	DefaultRouters []net.IP
	MTU            uint16
	WirelessCfg    WirelessConfig
	WirelessStatus WirelessStatus
	ProxyConfig
	L2LinkConfig
	// TestResults provides recording of failure and success
	TestResults
}

type AddrInfo struct {
	Addr             net.IP
	Geo              ipinfo.IPInfo
	LastGeoTimestamp time.Time
}

// WirelessStatus : state information for a single wireless device
type WirelessStatus struct {
	WType    WirelessType
	Cellular WwanNetworkStatus
	// TODO: Wifi status
}

// HasIPAndDNS - Check if the given port has a valid unicast IP along with DNS & Gateway.
func (port NetworkPortStatus) HasIPAndDNS() bool {
	foundUnicast := false
	for _, addr := range port.AddrInfoList {
		if !addr.Addr.IsLinkLocalUnicast() {
			foundUnicast = true
		}
	}
	if foundUnicast && len(port.DefaultRouters) > 0 && len(port.DNSServers) > 0 {
		return true
	}
	return false
}

// Key is used for pubsub
func (status DeviceNetworkStatus) Key() string {
	return "global"
}

// LogCreate :
func (status DeviceNetworkStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DeviceNetworkStatusLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("testing-bool", status.Testing).
		AddField("ports-int64", len(status.Ports)).
		AddField("state", status.State.String()).
		AddField("current-index-int64", status.CurrentIndex).
		Noticef("DeviceNetworkStatus create")
	for _, p := range status.Ports {
		// XXX different logobject for a particular port?
		logObject.CloneAndAddField("ifname", p.IfName).
			AddField("last-error", p.LastError).
			AddField("last-succeeded", p.LastSucceeded).
			AddField("last-failed", p.LastFailed).
			Noticef("DeviceNetworkStatus port create")
	}
}

// LogModify :
func (status DeviceNetworkStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.DeviceNetworkStatusLogType, "",
		nilUUID, status.LogKey())

	oldStatus, ok := old.(DeviceNetworkStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of DeviceNetworkStatus type")
	}
	if oldStatus.Testing != status.Testing ||
		oldStatus.State != status.State ||
		oldStatus.CurrentIndex != status.CurrentIndex ||
		len(oldStatus.Ports) != len(status.Ports) {

		logData := logObject.CloneAndAddField("testing-bool", status.Testing).
			AddField("ports-int64", len(status.Ports)).
			AddField("state", status.State.String()).
			AddField("current-index-int64", status.CurrentIndex).
			AddField("old-testing-bool", oldStatus.Testing).
			AddField("old-ports-int64", len(oldStatus.Ports)).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-current-index-int64", oldStatus.CurrentIndex)

		if oldStatus.State == status.State && oldStatus.CurrentIndex == status.CurrentIndex &&
			len(oldStatus.Ports) == len(status.Ports) {
			// if only testing state changed, reduce log level
			logData.Function("DeviceNetworkStatus modify")
		} else {
			logData.Notice("DeviceNetworkStatus modify")
		}
	}
	// XXX which fields to compare/log?
	for i, p := range status.Ports {
		if len(oldStatus.Ports) <= i {
			continue
		}
		op := oldStatus.Ports[i]
		// XXX different logobject for a particular port?
		if p.HasError() != op.HasError() ||
			p.LastFailed != op.LastFailed ||
			p.LastSucceeded != op.LastSucceeded ||
			p.LastError != op.LastError {
			logData := logObject.CloneAndAddField("ifname", p.IfName).
				AddField("last-error", p.LastError).
				AddField("last-succeeded", p.LastSucceeded).
				AddField("last-failed", p.LastFailed).
				AddField("old-last-error", op.LastError).
				AddField("old-last-succeeded", op.LastSucceeded).
				AddField("old-last-failed", op.LastFailed)
			if p.HasError() == op.HasError() &&
				p.LastError == op.LastError {
				// if we have success or the same error again, reduce log level
				logData.Function("DeviceNetworkStatus port modify")
			} else {
				logData.Notice("DeviceNetworkStatus port modify")
			}
		}
	}
}

// LogDelete :
func (status DeviceNetworkStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.DeviceNetworkStatusLogType, "",
		nilUUID, status.LogKey())
	logObject.CloneAndAddField("testing-bool", status.Testing).
		AddField("ports-int64", len(status.Ports)).
		AddField("state", status.State.String()).
		Noticef("DeviceNetworkStatus instance status delete")
	for _, p := range status.Ports {
		// XXX different logobject for a particular port?
		logObject.CloneAndAddField("ifname", p.IfName).
			AddField("last-error", p.LastError).
			AddField("last-succeeded", p.LastSucceeded).
			AddField("last-failed", p.LastFailed).
			Noticef("DeviceNetworkStatus port delete")
	}

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status DeviceNetworkStatus) LogKey() string {
	return string(base.DeviceNetworkStatusLogType) + "-" + status.Key()
}

// MostlyEqual compares two DeviceNetworkStatus but skips things the test status/results aspects, including State and Testing.
// We compare the Ports in array order.
func (status DeviceNetworkStatus) MostlyEqual(status2 DeviceNetworkStatus) bool {

	if len(status.Ports) != len(status2.Ports) {
		return false
	}
	for i, p1 := range status.Ports {
		p2 := status2.Ports[i]
		if p1.IfName != p2.IfName ||
			p1.Phylabel != p2.Phylabel ||
			p1.Logicallabel != p2.Logicallabel ||
			p1.Alias != p2.Alias ||
			p1.IsMgmt != p2.IsMgmt ||
			p1.IsL3Port != p2.IsL3Port ||
			p1.Cost != p2.Cost {
			return false
		}
		if p1.Dhcp != p2.Dhcp ||
			!netutils.EqualIPNets(&p1.Subnet, &p2.Subnet) ||
			!p1.NtpServer.Equal(p2.NtpServer) ||
			p1.DomainName != p2.DomainName {
			return false
		}
		if len(p1.DNSServers) != len(p2.DNSServers) {
			return false
		}
		for i := range p1.DNSServers {
			if !p1.DNSServers[i].Equal(p2.DNSServers[i]) {
				return false
			}
		}
		if len(p1.AddrInfoList) != len(p2.AddrInfoList) {
			return false
		}
		for i := range p1.AddrInfoList {
			if !p1.AddrInfoList[i].Addr.Equal(p2.AddrInfoList[i].Addr) {
				return false
			}
		}
		if p1.Up != p2.Up ||
			!bytes.Equal(p1.MacAddr, p2.MacAddr) {
			return false
		}
		if len(p1.DefaultRouters) != len(p2.DefaultRouters) {
			return false
		}
		for i := range p1.DefaultRouters {
			if !p1.DefaultRouters[i].Equal(p2.DefaultRouters[i]) {
				return false
			}
		}

		if !reflect.DeepEqual(p1.ProxyConfig, p2.ProxyConfig) ||
			!reflect.DeepEqual(p1.WirelessStatus, p2.WirelessStatus) {
			return false
		}
	}
	return reflect.DeepEqual(status.RadioSilence, status2.RadioSilence)
}

// MostlyEqualStatus compares two DeviceNetworkStatus but skips things that are
// unimportant like just an increase in the success timestamp, but detects
// when a port changes to/from a failure.
func (status *DeviceNetworkStatus) MostlyEqualStatus(status2 DeviceNetworkStatus) bool {

	if !status.MostlyEqual(status2) {
		return false
	}
	if status.State != status2.State || status.Testing != status2.Testing ||
		status.CurrentIndex != status2.CurrentIndex {
		return false
	}
	if len(status.Ports) != len(status2.Ports) {
		return false
	}
	for i, p1 := range status.Ports {
		p2 := status2.Ports[i]
		// Did we change to/from failure?
		if p1.HasError() != p2.HasError() {
			return false
		}
	}
	return true
}

// GetPortByIfName - Get Port Status for port with given Ifname
func (status *DeviceNetworkStatus) GetPortByIfName(
	ifname string) *NetworkPortStatus {
	for i := range status.Ports {
		if status.Ports[i].IfName == ifname {
			return &status.Ports[i]
		}
	}
	return nil
}

// GetPortsByLogicallabel - Get Port Status for all ports matching the given label.
func (status *DeviceNetworkStatus) GetPortsByLogicallabel(
	label string) (ports []*NetworkPortStatus) {
	// Check for shared labels first.
	switch label {
	case UplinkLabel:
		for i := range status.Ports {
			if status.Version >= DPCIsMgmt && !status.Ports[i].IsMgmt {
				continue
			}
			ports = append(ports, &status.Ports[i])
		}
		return ports
	case FreeUplinkLabel:
		for i := range status.Ports {
			if status.Version >= DPCIsMgmt && !status.Ports[i].IsMgmt {
				continue
			}
			if status.Ports[i].Cost > 0 {
				continue
			}
			ports = append(ports, &status.Ports[i])
		}
		return ports
	}
	// Label is referencing single port.
	for i := range status.Ports {
		if status.Ports[i].Logicallabel == label {
			ports = append(ports, &status.Ports[i])
			return ports
		}
	}
	return nil
}

// HasErrors - DeviceNetworkStatus has errors on any of it's ports?
func (status DeviceNetworkStatus) HasErrors() bool {
	for _, port := range status.Ports {
		if port.HasError() {
			return true
		}
	}
	return false
}

// GetPortAddrInfo returns address info for a given interface and its IP address.
func (status DeviceNetworkStatus) GetPortAddrInfo(ifname string, addr net.IP) *AddrInfo {
	portStatus := status.GetPortByIfName(ifname)
	if portStatus == nil {
		return nil
	}
	for i := range portStatus.AddrInfoList {
		if portStatus.AddrInfoList[i].Addr.Equal(addr) {
			return &portStatus.AddrInfoList[i]
		}
	}
	return nil
}

func rotate(arr []string, amount int) []string {
	if len(arr) == 0 {
		return []string{}
	}
	amount %= len(arr)
	return append(append([]string{}, arr[amount:]...), arr[:amount]...)
}

// GetMgmtPortsSortedCost returns all management ports sorted by port cost
// rotation causes rotation/round-robin within each cost
func GetMgmtPortsSortedCost(dns DeviceNetworkStatus, rotation int) []string {
	return getPortsSortedCostImpl(dns, rotation,
		PortCostMax, true, true, false)
}

// GetAllPortsSortedCost returns all ports (management and app shared) sorted by port cost.
// Rotation causes rotation/round-robin within each cost.
func GetAllPortsSortedCost(dns DeviceNetworkStatus, l3Only bool, rotation int) []string {
	return getPortsSortedCostImpl(dns, rotation,
		PortCostMax, l3Only, false, false)
}

// GetMgmtPortsSortedCostWithoutFailed returns all management ports sorted by
// port cost ignoring ports with failures.
// rotation causes rotation/round-robin within each cost
func GetMgmtPortsSortedCostWithoutFailed(dns DeviceNetworkStatus, rotation int) []string {
	return getPortsSortedCostImpl(dns, rotation,
		PortCostMax, true, true, true)
}

// getPortsSortedCostImpl returns all ports sorted by port cost
// up to and including the maxCost
func getPortsSortedCostImpl(dns DeviceNetworkStatus, rotation int, maxCost uint8,
	l3Only, mgmtOnly, dropFailed bool) []string {
	ifnameList := []string{}
	costList := getPortCostListImpl(dns, maxCost)
	for _, cost := range costList {
		ifnameList = append(ifnameList,
			getPortsImpl(dns, rotation, true, cost, l3Only, mgmtOnly, dropFailed)...)
	}
	return ifnameList
}

// GetMgmtPortsAny returns all management ports
func GetMgmtPortsAny(dns DeviceNetworkStatus, rotation int) []string {
	return getPortsImpl(dns, rotation, false, 0, true, true, false)
}

// GetMgmtPortsByCost returns all management ports with a given port cost
func GetMgmtPortsByCost(dns DeviceNetworkStatus, cost uint8) []string {
	return getPortsImpl(dns, 0, true, cost, true, true, false)
}

// Returns the IfNames.
func getPortsImpl(dns DeviceNetworkStatus, rotation int,
	matchCost bool, cost uint8, l3Only, mgmtOnly, dropFailed bool) []string {

	ifnameList := make([]string, 0, len(dns.Ports))
	for _, us := range dns.Ports {
		if matchCost && us.Cost != cost {
			continue
		}
		if mgmtOnly && dns.Version >= DPCIsMgmt &&
			!us.IsMgmt {
			continue
		}
		if l3Only && !us.IsL3Port {
			continue
		}
		if dropFailed && us.HasError() {
			continue
		}
		ifnameList = append(ifnameList, us.IfName)
	}
	return rotate(ifnameList, rotation)
}

// GetPortCostList returns the sorted list of port costs
// with cost zero entries first.
func GetPortCostList(dns DeviceNetworkStatus) []uint8 {

	return getPortCostListImpl(dns, PortCostMax)
}

// getPortCostListImpl returns the sorted port costs up to and including the max
func getPortCostListImpl(dns DeviceNetworkStatus, maxCost uint8) []uint8 {
	costList := make([]uint8, 0, len(dns.Ports))
	for _, us := range dns.Ports {
		costList = append(costList, us.Cost)
	}
	if len(costList) == 0 {
		return []uint8{}
	}
	// Need sort -u so separately we remove the duplicates
	sort.Slice(costList,
		func(i, j int) bool { return costList[i] < costList[j] })
	unique := make([]uint8, 0, len(costList))
	i := 0
	unique = append(unique, costList[0])
	for _, cost := range costList {
		if cost != unique[i] && cost <= maxCost {
			unique = append(unique, cost)
			i++
		}
	}
	return unique
}

// CountLocalAddrAnyNoLinkLocal returns the number of local IP addresses for
// all the management ports (for all port costs) excluding link-local addresses
func CountLocalAddrAnyNoLinkLocal(dns DeviceNetworkStatus) int {

	// Count the number of addresses which apply
	addrs, _ := getLocalAddrListImpl(dns, "", PortCostMax,
		false, 0)
	return len(addrs)
}

// CountLocalAddrAnyNoLinkLocalIf return number of local IP addresses for
// the interface excluding link-local addresses
func CountLocalAddrAnyNoLinkLocalIf(dns DeviceNetworkStatus,
	ifname string) (int, error) {

	if ifname == "" {
		return 0, fmt.Errorf("ifname not specified")
	}
	// Count the number of addresses which apply
	addrs, err := getLocalAddrListImpl(dns, ifname,
		PortCostMax, false, 0)
	return len(addrs), err
}

// CountLocalAddrNoLinkLocalWithCost is like CountLocalAddrAnyNoLinkLocal but
// in addition allows the caller to specify the cost between
// PortCostMin (0) and PortCostMax(255).
// If 0 is specified it only considers cost 0 ports.
// if 255 is specified it considers all the ports.
func CountLocalAddrNoLinkLocalWithCost(dns DeviceNetworkStatus,
	maxCost uint8) int {

	// Count the number of addresses which apply
	addrs, _ := getLocalAddrListImpl(dns, "", maxCost,
		false, 0)
	return len(addrs)
}

// CountLocalIPv4AddrAnyNoLinkLocal is like CountLocalAddrAnyNoLinkLocal but
// only IPv4 addresses are counted
func CountLocalIPv4AddrAnyNoLinkLocal(dns DeviceNetworkStatus) int {

	// Count the number of addresses which apply
	addrs, _ := getLocalAddrListImpl(dns, "", PortCostMax,
		false, 4)
	return len(addrs)
}

// CountDNSServers returns the number of DNS servers; for ifname if set
func CountDNSServers(dns DeviceNetworkStatus, ifname string) int {

	count := 0
	for _, us := range dns.Ports {
		if us.IfName != ifname && ifname != "" {
			continue
		}
		count += len(us.DNSServers)
	}
	return count
}

// GetDNSServers returns all, or the ones on one interface if ifname is set
func GetDNSServers(dns DeviceNetworkStatus, ifname string) []net.IP {

	var servers []net.IP
	for _, us := range dns.Ports {
		if !us.IsMgmt && ifname == "" {
			continue
		}
		if ifname != "" && ifname != us.IfName {
			continue
		}
		servers = append(servers, us.DNSServers...)
	}
	return servers
}

// GetNTPServers returns all, or the ones on one interface if ifname is set
func GetNTPServers(dns DeviceNetworkStatus, ifname string) []net.IP {

	var servers []net.IP
	for _, us := range dns.Ports {
		if ifname != "" && ifname != us.IfName {
			continue
		}
		servers = append(servers, us.NtpServers...)
		// Add statically configured NTP server as well, but avoid duplicates.
		if us.NtpServer != nil {
			var found bool
			for _, server := range servers {
				if server.Equal(us.NtpServer) {
					found = true
					break
				}
			}
			if !found {
				servers = append(servers, us.NtpServer)
			}
		}
	}
	return servers
}

// CountLocalIPv4AddrAnyNoLinkLocalIf is like CountLocalAddrAnyNoLinkLocalIf but
// only IPv4 addresses are counted
func CountLocalIPv4AddrAnyNoLinkLocalIf(dns DeviceNetworkStatus,
	ifname string) (int, error) {

	if ifname == "" {
		return 0, fmt.Errorf("ifname not specified")
	}
	// Count the number of addresses which apply
	addrs, err := getLocalAddrListImpl(dns, ifname,
		PortCostMax, false, 4)
	return len(addrs), err
}

// GetLocalAddrAnyNoLinkLocal is used to pick one address from:
// - ifname if set.
// - otherwise from all of the management ports
// Excludes link-local addresses.
// The addresses are sorted in cost order thus as the caller starts with
// pickNum zero and increases it will use the ports in cost order.
func GetLocalAddrAnyNoLinkLocal(dns DeviceNetworkStatus, pickNum int,
	ifname string) (net.IP, error) {

	includeLinkLocal := false
	return getLocalAddrImpl(dns, pickNum, ifname,
		PortCostMax, includeLinkLocal, 0)
}

// GetLocalAddrNoLinkLocalWithCost is like GetLocalAddrNoLinkLocal but
// in addition allows the caller to specify the cost between
// PortCostMin (0) and PortCostMax(255).
// If 0 is specified it only considers local addresses on cost zero ports;
// if 255 is specified it considers all the local addresses.
func GetLocalAddrNoLinkLocalWithCost(dns DeviceNetworkStatus, pickNum int,
	ifname string, maxCost uint8) (net.IP, error) {

	includeLinkLocal := false
	return getLocalAddrImpl(dns, pickNum, ifname,
		maxCost, includeLinkLocal, 0)
}

// getLocalAddrImpl returns an IP address based on interfaces sorted in
// cost order. If ifname is set, the addresses are from that
// interface. Otherwise from all management interfaces up to and including maxCost.
// af can be set to 0 (any), 4, IPv4), or 6 (IPv6) to select the family.
func getLocalAddrImpl(dns DeviceNetworkStatus, pickNum int,
	ifname string, maxCost uint8, includeLinkLocal bool,
	af uint) (net.IP, error) {

	addrs, err := getLocalAddrListImpl(dns, ifname,
		maxCost, includeLinkLocal, af)
	if err != nil {
		return net.IP{}, err
	}
	numAddrs := len(addrs)
	if numAddrs == 0 {
		return net.IP{}, fmt.Errorf("no addresses")
	}
	pickNum %= numAddrs
	return addrs[pickNum], nil
}

// getLocalAddrListImpl returns a list IP addresses based on interfaces sorted
// in cost order. If ifname is set, the addresses are from that
// interface. Otherwise from all management interfaces up to and including maxCost
// af can be set to 0 (any), 4, IPv4), or 6 (IPv6) to select a subset.
func getLocalAddrListImpl(dns DeviceNetworkStatus,
	ifname string, maxCost uint8, includeLinkLocal bool,
	af uint) ([]net.IP, error) {

	var ifnameList []string
	var ignoreErrors bool
	if ifname == "" {
		// Get interfaces in cost order
		ifnameList = getPortsSortedCostImpl(dns, 0,
			maxCost, true, true, false)
		// If we are looking across all interfaces, then We ignore errors
		// since we get them if there are no addresses on a ports
		ignoreErrors = true
	} else {
		us := GetPort(dns, ifname)
		if us == nil {
			return []net.IP{}, fmt.Errorf("Unknown interface %s",
				ifname)
		}
		if us.Cost > maxCost {
			return []net.IP{}, fmt.Errorf("Interface %s cost %d exceeds maxCost %d",
				ifname, us.Cost, maxCost)
		}
		ifnameList = []string{ifname}
	}
	addrs := []net.IP{}
	for _, ifname := range ifnameList {
		ifaddrs, err := getLocalAddrIf(dns, ifname,
			includeLinkLocal, af)
		if !ignoreErrors && err != nil {
			return addrs, err
		}
		addrs = append(addrs, ifaddrs...)
	}
	return addrs, nil
}

// Check if an interface name is a port owned by nim
func IsPort(dns DeviceNetworkStatus, ifname string) bool {
	for _, us := range dns.Ports {
		if us.IfName != ifname {
			continue
		}
		return true
	}
	return false
}

// IsL3Port checks if an interface name belongs to a port with SystemAdapter attached.
func IsL3Port(dns DeviceNetworkStatus, ifname string) bool {
	for _, us := range dns.Ports {
		if us.IfName != ifname {
			continue
		}
		return us.IsL3Port
	}
	return false
}

// Check if a physical label or ifname is a management port
func IsMgmtPort(dns DeviceNetworkStatus, ifname string) bool {
	for _, us := range dns.Ports {
		if us.IfName != ifname {
			continue
		}
		if dns.Version >= DPCIsMgmt &&
			!us.IsMgmt {
			continue
		}
		return true
	}
	return false
}

// GetPortCost returns the port cost
// Returns 0 if the ifname does not exist.
func GetPortCost(dns DeviceNetworkStatus, ifname string) uint8 {
	for _, us := range dns.Ports {
		if us.IfName != ifname {
			continue
		}
		return us.Cost
	}
	return 0
}

func GetPort(dns DeviceNetworkStatus, ifname string) *NetworkPortStatus {
	for _, us := range dns.Ports {
		if us.IfName != ifname {
			continue
		}
		if dns.Version < DPCIsMgmt {
			us.IsMgmt = true
		}
		return &us
	}
	return nil
}

// Given an address tell me its IfName
func GetMgmtPortFromAddr(dns DeviceNetworkStatus, addr net.IP) string {
	for _, us := range dns.Ports {
		if dns.Version >= DPCIsMgmt &&
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

// GetLocalAddrList returns all IP addresses on the ifName except
// the link local addresses.
func GetLocalAddrList(dns DeviceNetworkStatus,
	ifname string) ([]net.IP, error) {

	if ifname == "" {
		return []net.IP{}, fmt.Errorf("ifname not specified")
	}
	return getLocalAddrIf(dns, ifname, false, 0)
}

// getLocalAddrIf returns all of the IP addresses for the ifname.
// includeLinkLocal and af can be used to exclude addresses.
func getLocalAddrIf(dns DeviceNetworkStatus, ifname string,
	includeLinkLocal bool, af uint) ([]net.IP, error) {

	var addrs []net.IP
	for _, us := range dns.Ports {
		if us.IfName != ifname {
			continue
		}
		for _, i := range us.AddrInfoList {
			if !includeLinkLocal && i.Addr.IsLinkLocalUnicast() {
				continue
			}
			if i.Addr == nil {
				continue
			}
			switch af {
			case 0:
				// Accept any
			case 4:
				if i.Addr.To4() == nil {
					continue
				}
			case 6:
				if i.Addr.To4() != nil {
					continue
				}
			}
			addrs = append(addrs, i.Addr)
		}
	}
	if len(addrs) == 0 {
		return []net.IP{}, &IPAddrNotAvailError{IfName: ifname}
	}
	return addrs, nil
}

// UpdatePortStatusFromIntfStatusMap - Set TestResults for ports in DeviceNetworkStatus to
// those from intfStatusMap. If a port is not found in intfStatusMap, it means
// the port was not tested, so we retain the original TestResults for the port.
func (status *DeviceNetworkStatus) UpdatePortStatusFromIntfStatusMap(
	intfStatusMap IntfStatusMap) {
	for indx := range status.Ports {
		portPtr := &status.Ports[indx]
		tr, ok := intfStatusMap.StatusMap[portPtr.IfName]
		if ok {
			portPtr.TestResults.Update(tr)
		}
		// Else - Port not tested hence no change
	}
}
