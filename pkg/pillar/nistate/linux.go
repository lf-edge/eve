// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nistate

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/gopacket"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	psutilnet "github.com/shirou/gopsutil/net"
	"golang.org/x/net/context"
)

const (
	// How often are conntrack entries listed and app flows collected and published.
	flowCollectInterval = 120 * time.Second
)

// LinuxCollector implements state data collecting for network instances
// configured inside the Linux network stack (using the Linux bridge).
type LinuxCollector struct {
	mu  sync.Mutex
	log *base.LogObject
	nis map[uuid.UUID]*niInfo

	ipLeaseWatcher   *fsnotify.Watcher
	flowWatchers     []chan types.IPFlow
	ipAssignWatchers []chan []VIFAddrsUpdate
	capturedPackets  chan capturedPacket
}

type niInfo struct {
	config          types.NetworkInstanceConfig
	bridge          NIBridge
	vifs            []*vifInfo
	ipLeases        dnsmasqIPLeases
	cancelPCAP      context.CancelFunc
	pcapWG          sync.WaitGroup
	ipv4DNSReqs     []dnsReq
	ipv6DNSReqs     []dnsReq
	arpSnoopEnabled bool
}

// lookupVIFByGuestMAC : Lookup VIF by the MAC address of the guest interface.
func (ni *niInfo) lookupVIFByGuestMAC(mac net.HardwareAddr) *vifInfo {
	for _, vif := range ni.vifs {
		if bytes.Equal(vif.GuestIfMAC, mac) {
			return vif
		}
	}
	return nil
}

type detectedAddr struct {
	types.AssignedAddr
	validUntil time.Time // zero timestamp if validity is not known/limited
}

func (addr detectedAddr) hasExpired() bool {
	return !addr.validUntil.IsZero() && time.Now().After(addr.validUntil)
}

func (addr detectedAddr) fromDHCP() bool {
	return addr.AssignedBy == types.AddressSourceInternalDHCP ||
		addr.AssignedBy == types.AddressSourceExternalDHCP
}

type vifInfo struct {
	AppVIF
	ipv4Addrs []detectedAddr
	ipv6Addrs []detectedAddr
}

func (vif *vifInfo) exportVIFAddrs() VIFAddrs {
	var assignedAddrs types.AssignedAddrs
	for _, addr := range vif.ipv4Addrs {
		assignedAddrs.IPv4Addrs = append(assignedAddrs.IPv4Addrs,
			types.AssignedAddr{
				Address:    addr.Address,
				AssignedBy: addr.AssignedBy,
			})
	}
	for _, addr := range vif.ipv6Addrs {
		assignedAddrs.IPv6Addrs = append(assignedAddrs.IPv6Addrs,
			types.AssignedAddr{
				Address:    addr.Address,
				AssignedBy: addr.AssignedBy,
			})
	}
	return VIFAddrs{
		AssignedAddrs: assignedAddrs,
		VIF:           vif.AppVIF,
	}
}

func (vif *vifInfo) hasIP(ip net.IP) bool {
	for _, ipv4Addr := range vif.ipv4Addrs {
		if ip.Equal(ipv4Addr.Address) {
			return true
		}
	}
	for _, ipv6Addr := range vif.ipv6Addrs {
		if ip.Equal(ipv6Addr.Address) {
			return true
		}
	}
	return false
}

// addIP adds or updates detected/leased IP address into the list of assigned addresses.
func (vif *vifInfo) addIP(ip net.IP, source types.AddressSource,
	validUntil time.Time) (update *VIFAddrsUpdate) {
	ipList := vif.ipv4Addrs
	if ip.To4() == nil {
		ipList = vif.ipv6Addrs
	}
	var alreadyExists, changed bool
	prevAddrs := vif.exportVIFAddrs()
	for i := range ipList {
		if ipList[i].Address.Equal(ip) {
			// IP address is already known for this VIF.
			// Just update the source and the expiration time.
			alreadyExists = true
			if source == types.AddressSourceStatic && ipList[i].fromDHCP() {
				// Prefer info from DHCP snooping over ARP snooping.
				// Ignore this update.
				return nil
			}
			ipList[i].validUntil = validUntil
			if ipList[i].AssignedBy != source {
				// LinuxCollector will publish VIFAddrsUpdate only to update
				// the IP address source.
				changed = true
				ipList[i].AssignedBy = source
			}
			break
		}
	}
	if !alreadyExists {
		// Newly detected IP address.
		changed = true
		ipList = append(ipList, detectedAddr{
			AssignedAddr: types.AssignedAddr{
				Address:    ip,
				AssignedBy: source,
			},
			validUntil: validUntil,
		})
	}
	if ip.To4() == nil {
		vif.ipv6Addrs = ipList
	} else {
		vif.ipv4Addrs = ipList
	}
	if !changed {
		return nil
	}
	newAddrs := vif.exportVIFAddrs()
	return &VIFAddrsUpdate{
		Prev: prevAddrs,
		New:  newAddrs,
	}
}

// delIPs removes all or only some IPs based on the source and the expiration.
func (vif *vifInfo) delIPs(sourceMask int, onlyExpired bool) *VIFAddrsUpdate {
	var changed bool
	var filteredV4Addrs, filteredV6Addrs []detectedAddr
	for _, addr := range vif.ipv4Addrs {
		if (sourceMask&int(addr.AssignedBy) > 0) &&
			(!onlyExpired || addr.hasExpired()) {
			changed = true
			continue
		}
		filteredV4Addrs = append(filteredV4Addrs, addr)
	}
	for _, addr := range vif.ipv6Addrs {
		if (sourceMask&int(addr.AssignedBy) > 0) &&
			(!onlyExpired || addr.hasExpired()) {
			changed = true
			continue
		}
		filteredV6Addrs = append(filteredV6Addrs, addr)
	}
	if !changed {
		return nil
	}
	prevAddrs := vif.exportVIFAddrs()
	vif.ipv4Addrs = filteredV4Addrs
	vif.ipv6Addrs = filteredV6Addrs
	newAddrs := vif.exportVIFAddrs()
	return &VIFAddrsUpdate{
		Prev: prevAddrs,
		New:  newAddrs,
	}
}

// NewLinuxCollector is a constructor for LinuxCollector.
func NewLinuxCollector(log *base.LogObject) *LinuxCollector {
	var err error
	sc := &LinuxCollector{
		log: log,
		nis: make(map[uuid.UUID]*niInfo),
	}
	sc.capturedPackets = make(chan capturedPacket, 100)
	sc.ipLeaseWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("%s: NewWatcher: %v", LogAndErrPrefix, err)
	}
	// Assumes that NewLinuxCollector is called after the directory with
	// IP leases was already created by zedrouter.
	err = sc.ipLeaseWatcher.Add(types.DnsmasqLeaseDir)
	if err != nil {
		log.Fatalf("%s: Watcher.Add: %v", LogAndErrPrefix, err)
	}
	go sc.runStateCollecting()
	return sc
}

// StartCollectingForNI : start collecting state data for the given network instance.
// It is called by zedrouter whenever a new network instance is configured.
func (lc *LinuxCollector) StartCollectingForNI(
	niConfig types.NetworkInstanceConfig, br NIBridge, vifs []AppVIF, enableARPSnoop bool) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if _, duplicate := lc.nis[niConfig.UUID]; duplicate {
		return fmt.Errorf("%s: NI %s is already included in state data collecting",
			LogAndErrPrefix, niConfig.UUID)
	}
	ni := &niInfo{
		config:          niConfig,
		bridge:          br,
		arpSnoopEnabled: enableARPSnoop,
	}
	for _, vif := range vifs {
		ni.vifs = append(ni.vifs, &vifInfo{AppVIF: vif})
	}
	lc.nis[niConfig.UUID] = ni
	if lc.isPcapRequired(niConfig) {
		pcapCtx, cancelPCAP := context.WithCancel(context.Background())
		ni.cancelPCAP = cancelPCAP
		ni.pcapWG.Add(1)
		go lc.sniffDNSandDHCP(pcapCtx, &ni.pcapWG, br, niConfig.Type, enableARPSnoop)
	}
	lc.log.Noticef("%s: Started collecting state data for NI %v "+
		"(br: %+v, vifs: %+v)", LogAndErrPrefix, niConfig.UUID, br, vifs)
	return nil
}

func (lc *LinuxCollector) isPcapRequired(niConfig types.NetworkInstanceConfig) bool {
	// For Switch NIs we need to capture ARP, DHCP and ICMP packets to learn application
	// IP assignments.
	// For both Switch and Local NIs we need to capture DNS packets if flow logging
	// is enabled.
	return niConfig.Type == types.NetworkInstanceTypeSwitch || niConfig.EnableFlowlog
}

// UpdateCollectingForNI : update state data collecting process to reflect a change
// in the network instance config.
// It is called by zedrouter whenever a config of an existing network instance changes
// or when VIF is (dis)connected to/from the NI.
// Note that not every change in network instance config is supported. For example,
// network instance type (switch / local) cannot change.
func (lc *LinuxCollector) UpdateCollectingForNI(
	niConfig types.NetworkInstanceConfig, vifs []AppVIF, enableARPSnoop bool) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if _, exists := lc.nis[niConfig.UUID]; !exists {
		return ErrUnknownNI{NI: niConfig.UUID}
	}
	ni := lc.nis[niConfig.UUID]
	ni.config = niConfig
	var newVifs []*vifInfo
	for _, vif := range vifs {
		newVif := &vifInfo{AppVIF: vif}
		// Preserve already known IP assignments.
		prevVIF := ni.lookupVIFByGuestMAC(vif.GuestIfMAC)
		if prevVIF != nil && prevVIF.App == vif.App && prevVIF.NI == vif.NI {
			newVif.ipv4Addrs = prevVIF.ipv4Addrs
			newVif.ipv6Addrs = prevVIF.ipv6Addrs
		}
		newVifs = append(newVifs, newVif)
	}
	ni.vifs = newVifs
	if ni.cancelPCAP != nil {
		// Stop current PCAP also if arpSnoopEnabled changed and we need to start
		// a new PCAP with an updated BPF filter.
		stopPCAP := !lc.isPcapRequired(niConfig) || ni.arpSnoopEnabled != enableARPSnoop
		if stopPCAP {
			ni.cancelPCAP()
			ni.pcapWG.Wait()
			ni.cancelPCAP = nil
		}
	}
	ni.arpSnoopEnabled = enableARPSnoop
	if lc.isPcapRequired(niConfig) && ni.cancelPCAP == nil {
		pcapCtx, cancelPCAP := context.WithCancel(context.Background())
		ni.cancelPCAP = cancelPCAP
		ni.pcapWG.Add(1)
		go lc.sniffDNSandDHCP(pcapCtx, &ni.pcapWG, ni.bridge, niConfig.Type, enableARPSnoop)
	}
	lc.log.Noticef("%s: Updated state collecting for NI %v "+
		"(br: %+v, vifs: %+v)", LogAndErrPrefix, niConfig.UUID, ni.bridge, ni.vifs)
	return nil
}

// StopCollectingForNI : stop collecting state data for network instance.
// It is called by zedrouter whenever a network instance is about to be deleted.
func (lc *LinuxCollector) StopCollectingForNI(niID uuid.UUID) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if _, exists := lc.nis[niID]; !exists {
		return ErrUnknownNI{NI: niID}
	}
	ni := lc.nis[niID]
	if ni.cancelPCAP != nil {
		ni.cancelPCAP()
		ni.pcapWG.Wait()
		ni.cancelPCAP = nil
	}
	delete(lc.nis, niID)
	lc.log.Noticef("%s: Stopped collecting state data for NI %v", LogAndErrPrefix, niID)
	return nil
}

// GetIPAssignments returns information about currently assigned IP addresses
// to VIFs connected to a given network instance.
func (lc *LinuxCollector) GetIPAssignments(niID uuid.UUID) (VIFAddrsList, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	niInfo, exists := lc.nis[niID]
	if !exists {
		return nil, ErrUnknownNI{NI: niID}
	}
	var addrList VIFAddrsList
	for _, vif := range niInfo.vifs {
		addrList = append(addrList, vif.exportVIFAddrs())
	}
	return addrList, nil
}

// WatchIPAssignments : watch for changes in IP assignments to VIFs across
// all network instances enabled for state collecting.
func (lc *LinuxCollector) WatchIPAssignments() <-chan []VIFAddrsUpdate {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	watcherCh := make(chan []VIFAddrsUpdate)
	lc.ipAssignWatchers = append(lc.ipAssignWatchers, watcherCh)
	return watcherCh
}

// GetNetworkMetrics : get statistics (interface, ACL counters) for all
// network interfaces.
// This actually includes not only interfaces created for network instances
// by zedrouter, but also wireless physical ports and bridges created for wired
// ports by NIM.
func (lc *LinuxCollector) GetNetworkMetrics() (types.NetworkMetrics, error) {
	interfaces, err := psutilnet.IOCounters(true)
	if err != nil {
		err = fmt.Errorf("%s: GetNetworkMetrics failed to read IO counters: %v",
			LogAndErrPrefix, err)
		return types.NetworkMetrics{}, err
	}
	// Call iptables once to get counters
	ac := lc.fetchIptablesCounters()

	// If we have both ethN and kethN then rename ethN to eethN ('e' for EVE)
	// and kethN to ethN (the actual port).
	// This ensures that ethN has the total counters for the actual port
	// The eethN counters are currently not used/reported, but could be
	// used to indicate how much EVE is doing. However, we wouldn't have
	// that separation for wlan and wwan interfaces.
	for i := range interfaces {
		if !strings.HasPrefix(interfaces[i].Name, "eth") {
			continue
		}
		kernIfname := "k" + interfaces[i].Name
		for j := range interfaces {
			if interfaces[j].Name != kernIfname {
				continue
			}
			interfaces[j].Name = interfaces[i].Name
			interfaces[i].Name = "e" + interfaces[i].Name
			break
		}
	}

	lc.mu.Lock()
	defer lc.mu.Unlock()
	var metrics []types.NetworkMetric
	for _, intf := range interfaces {
		metric := types.NetworkMetric{
			IfName:   intf.Name,
			TxPkts:   intf.PacketsSent,
			RxPkts:   intf.PacketsRecv,
			TxBytes:  intf.BytesSent,
			RxBytes:  intf.BytesRecv,
			TxDrops:  intf.Dropout,
			RxDrops:  intf.Dropin,
			TxErrors: intf.Errout,
			RxErrors: intf.Errin,
		}

		// Is this interface associated with any network instance?
		var brIfName, vifName string
		ipVer := 4
		if vif, isVIF := lc.getVIFByIfName(intf.Name); isVIF {
			ipVer = addrTypeToIPVer(lc.nis[vif.NI].config.IpType)
			brIfName = lc.nis[vif.NI].bridge.BrIfName
			vifName = vif.HostIfName
		} else if br, isBr := lc.getBridgeByIfName(intf.Name); isBr {
			ipVer = addrTypeToIPVer(lc.nis[br.NI].config.IpType)
			brIfName = intf.Name
		} else {
			// Not part of any NI, probably device port.
			metrics = append(metrics, metric)
			continue
		}
		if ipVer == 0 {
			ipVer = 4
		}

		metric.TxAclDrops = lc.getIptablesACLDrop(ac, brIfName, vifName, ipVer, true)
		metric.RxAclDrops = lc.getIptablesACLDrop(ac, brIfName, vifName, ipVer, false)
		metric.TxAclRateLimitDrops = lc.getIptablesACLRateLimitDrop(
			ac, brIfName, vifName, ipVer, true)
		metric.RxAclRateLimitDrops = lc.getIptablesACLRateLimitDrop(
			ac, brIfName, vifName, ipVer, false)
		metrics = append(metrics, metric)
	}
	return types.NetworkMetrics{
		MetricList:     metrics,
		TotalRuleCount: uint64(len(ac)),
	}, nil
}

// WatchFlows : get periodic statistics for network flows established between
// applications and remote endpoints.
func (lc *LinuxCollector) WatchFlows() <-chan types.IPFlow {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	watcherCh := make(chan types.IPFlow)
	lc.flowWatchers = append(lc.flowWatchers, watcherCh)
	return watcherCh
}

// Run periodic and on-change state data collecting for network instances
// from a separate Go routine.
func (lc *LinuxCollector) runStateCollecting() {
	gcIPAssignments := time.NewTicker(time.Minute)
	fmax := float64(flowCollectInterval)
	fmin := fmax * 0.9
	flowCollectTimer := flextimer.NewRangeTicker(time.Duration(fmin), time.Duration(fmax))

	for {
		select {
		case leaseChange := <-lc.ipLeaseWatcher.Events:
			switch leaseChange.Op {
			case fsnotify.Create, fsnotify.Remove, fsnotify.Write:
				lc.mu.Lock()
				brIfName := filepath.Base(leaseChange.Name)
				br, found := lc.getBridgeByIfName(brIfName)
				if !found {
					// This is OK - network instance is first configured
					// then state collecting starts, meaning that dnsmasq can add (empty)
					// lease file before State Collector is informed about the new NI.
					lc.mu.Unlock()
					continue
				}
				var addrChanges []VIFAddrsUpdate
				if changed := lc.reloadIPLeases(br); changed {
					addrChanges = lc.processIPLeases(lc.nis[br.NI])
				}
				watchers := lc.ipAssignWatchers
				lc.mu.Unlock()
				if len(addrChanges) != 0 {
					event := fmt.Sprintf("IP Lease event '%s'", leaseChange)
					lc.logAddrChanges(event, addrChanges)
					for _, watcherCh := range watchers {
						watcherCh <- addrChanges
					}
				}
			}
		case <-gcIPAssignments.C:
			lc.mu.Lock()
			var addrChanges []VIFAddrsUpdate
			for _, ni := range lc.nis {
				// First remove IP leases which are no longer reported by the internal
				// DHCP server.
				removedAny := lc.gcIPLeases(ni)
				if removedAny {
					addrChanges = append(addrChanges, lc.processIPLeases(ni)...)
				}
				// Next remove expired IP leases granted from external DHCP servers
				// or statically configured IPs with ARP not seen for more than 10 minutes.
				for _, vif := range ni.vifs {
					sourceMask := int(types.AddressSourceExternalDHCP) |
						int(types.AddressSourceStatic)
					update := vif.delIPs(sourceMask, true)
					if update != nil {
						addrChanges = append(addrChanges, *update)
					}
				}
			}
			watchers := lc.ipAssignWatchers
			lc.mu.Unlock()
			if len(addrChanges) != 0 {
				lc.logAddrChanges("IP Assignment GC event", addrChanges)
				for _, watcherCh := range watchers {
					watcherCh <- addrChanges
				}
			}
		case <-flowCollectTimer.C:
			lc.mu.Lock()
			flows := lc.collectFlows()
			watchers := lc.flowWatchers
			lc.mu.Unlock()
			if len(flows) != 0 {
				for _, watcherCh := range watchers {
					for _, flow := range flows {
						watcherCh <- flow
					}
				}
			}
		case capPacket := <-lc.capturedPackets:
			lc.mu.Lock()
			addrChanges := lc.processCapturedPacket(capPacket)
			watchers := lc.ipAssignWatchers
			lc.mu.Unlock()
			if len(addrChanges) != 0 {
				packetLayers := capPacket.packet.Layers()
				topLayer := packetLayers[len(packetLayers)-1]
				event := fmt.Sprintf("Captured packet (%s)",
					gopacket.LayerString(topLayer))
				lc.logAddrChanges(event, addrChanges)
				for _, watcherCh := range watchers {
					watcherCh <- addrChanges
				}
			}
		}
	}
}

func (lc *LinuxCollector) logAddrChanges(event string, changes []VIFAddrsUpdate) {
	for _, addrChange := range changes {
		lc.log.Noticef(
			"%s: %s revealed IP address changes "+
				"for VIF %+v, prev: %+v, new: %+v",
			LogAndErrPrefix, event, addrChange.Prev.VIF,
			addrChange.Prev.AssignedAddrs, addrChange.New.AssignedAddrs)
	}
}

func (lc *LinuxCollector) getVIFByIfName(ifName string) (vif AppVIF, found bool) {
	for _, niState := range lc.nis {
		for _, niVIF := range niState.vifs {
			if niVIF.HostIfName == ifName {
				return niVIF.AppVIF, true
			}
		}
	}
	return vif, false
}

func (lc *LinuxCollector) getVIFsByAppNum(appNum int) (vifs []*vifInfo) {
	for _, niState := range lc.nis {
		for _, niVIF := range niState.vifs {
			if niVIF.AppNum != appNum {
				continue
			}
			vifs = append(vifs, niVIF)
		}
	}
	return vifs
}

func (lc *LinuxCollector) getBridgeByIfName(ifName string) (br NIBridge, found bool) {
	for _, niState := range lc.nis {
		if niState.bridge.BrIfName == ifName {
			return niState.bridge, true
		}
	}
	return br, false
}
