// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nistate

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/gopacket"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
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
	config      types.NetworkInstanceConfig
	bridge      NIBridge
	vifs        VIFAddrsList
	ipLeases    dnsmasqIPLeases
	cancelPCAP  context.CancelFunc
	ipv4DNSReqs []dnsReq
	ipv6DNSReqs []dnsReq
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
	err = sc.ipLeaseWatcher.Add(devicenetwork.DnsmasqLeaseDir)
	if err != nil {
		log.Fatalf("%s: Watcher.Add: %v", LogAndErrPrefix, err)
	}
	go sc.runStateCollecting()
	return sc
}

// StartCollectingForNI : start collecting state data for the given network instance.
// It is called by zedrouter whenever a new network instance is configured.
func (lc *LinuxCollector) StartCollectingForNI(
	niConfig types.NetworkInstanceConfig, br NIBridge, vifs []AppVIF) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if _, duplicate := lc.nis[niConfig.UUID]; duplicate {
		return fmt.Errorf("%s: NI %s is already included in state data collecting",
			LogAndErrPrefix, niConfig.UUID)
	}
	pcapCtx, cancelPCAP := context.WithCancel(context.Background())
	ni := &niInfo{
		config:     niConfig,
		bridge:     br,
		cancelPCAP: cancelPCAP,
	}
	for _, vif := range vifs {
		ni.vifs = append(ni.vifs, VIFAddrs{VIF: vif})
	}
	lc.nis[niConfig.UUID] = ni
	go lc.sniffDNSandDHCP(pcapCtx, br, niConfig.Type)
	lc.log.Noticef("%s: Started collecting state data for NI %v "+
		"(br: %+v, vifs: %+v)", LogAndErrPrefix, niConfig.UUID, br, vifs)
	return nil
}

// UpdateCollectingForNI : update state data collecting process to reflect a change
// in the network instance config.
// It is called by zedrouter whenever a config of an existing network instance changes
// or when VIF is (dis)connected to/from the NI.
// Note that not every change in network instance config is supported. For example,
// network instance type (switch / local) cannot change.
func (lc *LinuxCollector) UpdateCollectingForNI(
	niConfig types.NetworkInstanceConfig, vifs []AppVIF) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if _, exists := lc.nis[niConfig.UUID]; !exists {
		return ErrUnknownNI{NI: niConfig.UUID}
	}
	ni := lc.nis[niConfig.UUID]
	ni.config = niConfig
	// Preserve already known IP assignments.
	prevVIFs := ni.vifs
	ni.vifs = nil
	for _, vif := range vifs {
		vifWithAddrs := VIFAddrs{VIF: vif}
		// If VIF was deactivated, forget previously recorded IP assignments.
		if vif.Activated {
			if prevVIF := prevVIFs.LookupByGuestMAC(vif.GuestIfMAC); prevVIF != nil {
				vifWithAddrs.IPv4Addr = prevVIF.IPv4Addr
				vifWithAddrs.IPv6Addrs = prevVIF.IPv6Addrs
			}
		}
		ni.vifs = append(ni.vifs, vifWithAddrs)
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
	lc.nis[niID].cancelPCAP()
	delete(lc.nis, niID)
	lc.log.Noticef("%s: Stopped collecting state data for NI %v", LogAndErrPrefix, niID)
	return nil
}

// ActivateVIFStateCollecting : activate collecting of state data for the given VIF.
// NOOP if the VIF is already activated.
func (lc *LinuxCollector) ActivateVIFStateCollecting(
	niID uuid.UUID, appID uuid.UUID, netAdapterName string) error {
	return lc.setAppVIFActivateState(niID, appID, netAdapterName, true)
}

// InactivateVIFStateCollecting : stop collecting state data and forget recorded
// IP assignments for the given VIF.
// (config present but interface was un-configured from the network stack).
func (lc *LinuxCollector) InactivateVIFStateCollecting(
	niID uuid.UUID, appID uuid.UUID, netAdapterName string) error {
	return lc.setAppVIFActivateState(niID, appID, netAdapterName, false)
}

func (lc *LinuxCollector) setAppVIFActivateState(niID uuid.UUID,
	appID uuid.UUID, netAdapterName string, activate bool) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if _, exists := lc.nis[niID]; !exists {
		return ErrUnknownNI{NI: niID}
	}
	vif := lc.nis[niID].vifs.LookupByAdapterName(appID, netAdapterName)
	if vif == nil {
		err := fmt.Errorf("%s: Unknown VIF with adapter name %s for app %s",
			LogAndErrPrefix, netAdapterName, appID)
		return err
	}
	vif.VIF.Activated = activate
	if !activate {
		// Forget previously recorded IP assignments.
		vif.IPv4Addr = nil
		vif.IPv6Addrs = nil
	}
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
	return niInfo.vifs, nil
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
			// Not part of any NI, probably uplink interface.
			metrics = append(metrics, metric)
			continue
		}
		if ipVer == 0 {
			ipVer = 4
		}

		// DROP action is used in two case.
		// 1. DROP rule for the packets exceeding rate-limiter.
		// 2. Default DROP rule in the end.
		// With flow-monitoring support, we cannot have the default DROP rule
		// in the end of rule list. This is to avoid conntrack from deleting
		// connections matching the default rule. Just before the default DROP
		// rule, we add a LOG rule for logging packets that are being forwarded
		// to dummy interface.
		// Packets matching the default DROP rule also match the default LOG rule.
		// Since we will not have the default DROP rule, we can copy statistics
		// from default LOG rule as DROP statistics.
		metric.TxAclDrops = lc.getIptablesACLDrop(ac, brIfName, vifName, ipVer, true)
		metric.TxAclDrops += lc.getIptablesACLLog(ac, brIfName, vifName, ipVer, true)
		metric.RxAclDrops = lc.getIptablesACLDrop(ac, brIfName, vifName, ipVer, false)
		metric.RxAclDrops += lc.getIptablesACLLog(ac, brIfName, vifName, ipVer, false)
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
	gcIPLeases := time.NewTicker(time.Minute)
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
		case <-gcIPLeases.C:
			lc.mu.Lock()
			var addrChanges []VIFAddrsUpdate
			for _, ni := range lc.nis {
				removedAny := lc.gcIPLeases(ni)
				if removedAny {
					addrChanges = append(addrChanges, lc.processIPLeases(ni)...)
				}
			}
			watchers := lc.ipAssignWatchers
			lc.mu.Unlock()
			if len(addrChanges) != 0 {
				lc.logAddrChanges("IP Lease GC event", addrChanges)
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
			if niVIF.VIF.HostIfName == ifName {
				return niVIF.VIF, true
			}
		}
	}
	return vif, false
}

func (lc *LinuxCollector) getVIFsByAppNum(appNum int) (vifs VIFAddrsList) {
	for _, niState := range lc.nis {
		for _, niVIF := range niState.vifs {
			if niVIF.VIF.AppNum != appNum {
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
