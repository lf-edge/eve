// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager

import (
	"context"
	"crypto/x509"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func (m *DpcManager) currentDPC() *types.DevicePortConfig {
	if len(m.dpcList.PortConfigList) == 0 ||
		m.dpcList.CurrentIndex < 0 ||
		m.dpcList.CurrentIndex >= len(m.dpcList.PortConfigList) {
		return nil
	}
	return &m.dpcList.PortConfigList[m.dpcList.CurrentIndex]
}

func (m *DpcManager) addDPC(ctx context.Context, dpc types.DevicePortConfig) {
	mgmtCount := dpc.CountMgmtPorts()
	if mgmtCount == 0 {
		// This DPC will be ignored when we check IsDPCUsable which
		// is called from IsDPCTestable and IsDPCUntested.
		m.Log.Warnf("Received DevicePortConfig key %s has no management ports; "+
			"will be ignored", dpc.Key)
	}

	// XXX really need to know whether anything with current or lower
	// index has changed. We don't care about inserts at the end of the list.
	configChanged := m.updateDPCListAndPublish(dpc, false)

	// We could have just booted up and not run RestartVerify even once.
	// If we see a DPC configuration that we already have in the persistent
	// DPC list that we load from storage, we will return with out testing it.
	// In such case we end up not having any working DeviceNetworkStatus (no ips).
	// When the current DeviceNetworkStatus does not have any usable IP addresses,
	// we should go ahead and call RestartVerify even when "configChanged" is false.
	// Also if we have no working one (index -1) we restart.
	ipAddrCount := types.CountLocalIPv4AddrAnyNoLinkLocal(m.deviceNetStatus)
	numDNSServers := types.CountDNSServers(m.deviceNetStatus, "")
	if !configChanged && ipAddrCount > 0 && numDNSServers > 0 &&
		m.dpcList.CurrentIndex != -1 {
		m.Log.Functionf("addDPC: Config already current. No changes to process\n")
		return
	}

	// Restart verification.
	m.dpcVerify.inProgress = false
	m.restartVerify(ctx, "new DPC")
}

func (m *DpcManager) delDPC(ctx context.Context, dpc types.DevicePortConfig) {
	configChanged := m.updateDPCListAndPublish(dpc, true)
	if !configChanged {
		m.Log.Functionf("delDPC: System current. No change detected.\n")
		return
	}
	m.restartVerify(ctx, "removed DPC")
}

// Returns true if the current config has actually changed.
func (m *DpcManager) updateDPCListAndPublish(
	dpc types.DevicePortConfig, delete bool) bool {
	// Look up based on timestamp, then content.
	current := m.currentDPC() // used to determine if index needs to change
	currentIndex := m.dpcList.CurrentIndex
	oldConfig, _ := m.lookupDPC(dpc)

	if delete {
		if oldConfig == nil {
			m.Log.Errorf("updateDPCListAndPublish - Delete. "+
				"Config not found: %+v\n", dpc)
			return false
		}
		m.Log.Functionf("updateDPCListAndPublish: Delete. "+
			"oldCOnfig %+v found: %+v\n", *oldConfig, dpc)
		m.removeDPC(*oldConfig)
	} else if oldConfig != nil {
		// Compare everything but TimePriority since that is
		// modified by zedagent even if there are no changes.
		// If we modify the timestamp for other than current
		// then treat as a change since it could have moved up
		// in the list.
		if oldConfig.MostlyEqual(&dpc) {
			m.Log.Functionf("updateDPCListAndPublish: no change but timestamps %v %v\n",
				oldConfig.TimePriority, dpc.TimePriority)

			// If this is current and current is in use (index=0)
			// then no work needed. Otherwise we reorder.
			if current != nil && current.MostlyEqual(oldConfig) && currentIndex == 0 {
				m.Log.Functionf(
					"updateDPCListAndPublish: no change and same Ports as currentIndex=0")
				return false
			}
			m.Log.Functionf(
				"updateDPCListAndPublish: changed ports from current; reorder\n")
		} else {
			m.Log.Functionf(
				"updateDPCListAndPublish: change from %+v to %+v\n", *oldConfig, dpc)
		}
		m.updateDPC(oldConfig, dpc)
	} else {
		m.insertDPC(dpc)
	}
	// Check if current moved to a different index or was deleted
	if current == nil {
		// No current index to update
		m.Log.Functionf("updateDPCListAndPublish: no current %d",
			currentIndex)
		m.compressAndPublishDPCL()
		return true
	}
	newplace, newIndex := m.lookupDPC(*current)
	if newplace == nil {
		// Current Got deleted. If [0] was working we stick to it, otherwise we
		// restart looking through the list.
		if len(m.dpcList.PortConfigList) != 0 &&
			m.dpcList.PortConfigList[0].WasDPCWorking() {
			m.dpcList.CurrentIndex = 0
		} else {
			m.dpcList.CurrentIndex = -1
		}
	} else if newIndex != currentIndex {
		m.Log.Functionf("updateDPCListAndPublish: current %d moved to %d",
			currentIndex, newIndex)
		if m.dpcList.PortConfigList[newIndex].WasDPCWorking() {
			m.dpcList.CurrentIndex = newIndex
		} else {
			m.dpcList.CurrentIndex = -1
		}
	}
	m.compressAndPublishDPCL()
	return true
}

// Update content and move if the timestamp changed
func (m *DpcManager) updateDPC(
	oldDpc *types.DevicePortConfig, newDpc types.DevicePortConfig) {
	if oldDpc.TimePriority == newDpc.TimePriority {
		m.Log.Functionf("updateDPC: same time update %+v\n", newDpc)
		*oldDpc = newDpc
		return
	}
	// Preserve TestResults and Last*
	newDpc.TestResults = oldDpc.TestResults
	newDpc.LastIPAndDNS = oldDpc.LastIPAndDNS
	m.Log.Functionf("updateDPC: diff time remove+add %+v\n", newDpc)
	m.removeDPC(*oldDpc)
	m.insertDPC(newDpc)
}

// Insert in reverse timestamp order
func (m *DpcManager) insertDPC(dpc types.DevicePortConfig) {
	var newConfig []types.DevicePortConfig
	inserted := false
	for _, port := range m.dpcList.PortConfigList {
		if !inserted && dpc.TimePriority.After(port.TimePriority) {
			m.Log.Functionf("insertDPC: %+v before %+v\n", dpc, port)
			newConfig = append(newConfig, dpc)
			inserted = true
		}
		newConfig = append(newConfig, port)
	}
	if !inserted {
		m.Log.Functionf("insertDPC: at end %+v\n", dpc)
		newConfig = append(newConfig, dpc)
	}
	m.dpcList.PortConfigList = newConfig
}

// Remove by matching TimePriority and Key
func (m *DpcManager) removeDPC(dpc types.DevicePortConfig) {
	var newConfig []types.DevicePortConfig
	removed := false
	for _, port := range m.dpcList.PortConfigList {
		if !removed && dpc.TimePriority == port.TimePriority && dpc.Key == port.Key {
			m.Log.Functionf("removeDPC: found %+v for %+v\n", port, dpc)
			removed = true
		} else {
			newConfig = append(newConfig, port)
		}
	}
	if !removed {
		m.Log.Errorf("removeDPC: not found %+v\n", dpc)
		return
	}
	m.dpcList.PortConfigList = newConfig
}

// First look for matching timestamp, then compare for identical content
// This is needed since after a restart zedagent will provide new timestamps
// even if we persisted the DevicePortConfig before the restart.
func (m *DpcManager) lookupDPC(dpc types.DevicePortConfig) (*types.DevicePortConfig, int) {
	for i, port := range m.dpcList.PortConfigList {
		if port.Version == dpc.Version &&
			port.Key == dpc.Key &&
			port.TimePriority == dpc.TimePriority {
			m.Log.Functionf("lookupDPC: timestamp found +%v\n", port)
			return &m.dpcList.PortConfigList[i], i
		}
	}
	for i, port := range m.dpcList.PortConfigList {
		if port.Version == dpc.Version && port.MostlyEqual(&dpc) {
			m.Log.Functionf("lookupDPC: MostlyEqual found +%v\n", port)
			return &m.dpcList.PortConfigList[i], i
		}
	}
	return nil, 0
}

// ingestDPCList creates and republishes the initial list.
// Removes useless ones (which might be re-added by the controller/zedagent
// later but at least they are not in the way during boot).
func (m *DpcManager) ingestDPCList() {
	m.Log.Functionf("IngestPortConfigList")
	item, err := m.PubDevicePortConfigList.Get("global")
	var storedDpcl types.DevicePortConfigList
	if err != nil {
		m.Log.Errorf("No global key for DevicePortConfigList")
	} else {
		storedDpcl = item.(types.DevicePortConfigList)
	}
	m.Log.Functionf("Initial DPCL %v", storedDpcl)
	var dpcl types.DevicePortConfigList
	for _, portConfig := range storedDpcl.PortConfigList {
		// Clear the errors from before reboot and start fresh.
		for i := 0; i < len(portConfig.Ports); i++ {
			portPtr := &portConfig.Ports[i]
			portPtr.Clear()
		}
		if portConfig.CountMgmtPorts() == 0 {
			m.Log.Warnf("Stored DevicePortConfig key %s has no management ports; ignored",
				portConfig.Key)
			continue
		}
		var invalidCert bool
		caCertPool := x509.NewCertPool()
		for _, port := range portConfig.Ports {
			for _, pem := range port.ProxyCertPEM {
				if !caCertPool.AppendCertsFromPEM(pem) {
					invalidCert = true
					break
				}
			}
			if invalidCert {
				break
			}
		}
		if invalidCert {
			m.Log.Warnf("Stored DevicePortConfig key %s contains invalid certificate; ignored",
				portConfig.Key)
			continue
		}
		dpcl.PortConfigList = append(dpcl.PortConfigList, portConfig)
	}
	m.dpcList = dpcl
	m.Log.Functionf("Sanitized DPCL %v", dpcl)
	m.compressAndPublishDPCL()
	m.dpcList.CurrentIndex = -1 // No known working one
	m.Log.Functionf("Published DPCL %v", m.dpcList)
	m.Log.Functionf("IngestPortConfigList len %d", len(m.dpcList.PortConfigList))
}

func (m *DpcManager) compressAndPublishDPCL() {
	m.compressDPCL()
	m.publishDPCL()
}

// Make DevicePortConfig have at most two zedagent entries;
// 1. the highest priority (whether it has lastSucceeded after lastFailed or not)
// 2. the next priority with lastSucceeded after lastFailed
// and make it have a single item for the other keys
func (m *DpcManager) compressDPCL() {
	if m.dpcVerify.inProgress || m.dpcList.CurrentIndex != 0 ||
		len(m.dpcList.PortConfigList) == 0 {
		m.Log.Tracef("compressDPCL: DPCL still changing - dpcVerify.inProgress: %t, "+
			"dpcList.CurrentIndex: %d, len(PortConfigList): %d",
			m.dpcVerify.inProgress, m.dpcList.CurrentIndex, len(m.dpcList.PortConfigList))
		return
	}
	firstEntry := m.dpcList.PortConfigList[0]
	if firstEntry.Key != "zedagent" || !firstEntry.WasDPCWorking() {
		m.Log.Tracef("compressDPCL: firstEntry not stable. key: %s, "+
			"WasWorking: %t, firstEntry: %+v",
			firstEntry.Key, firstEntry.WasDPCWorking(), firstEntry)
		return
	}
	m.Log.Tracef("compressDPCL: numEntries: %d, dpcList: %+v",
		len(m.dpcList.PortConfigList), m.dpcList)
	var newConfig []types.DevicePortConfig
	for i, dpc := range m.dpcList.PortConfigList {
		if i == 0 {
			// Always add Current Index ( index 0 )
			newConfig = append(newConfig, dpc)
			m.Log.Tracef("compressDPCL: Adding Current Index: i = %d, dpc: %+v",
				i, dpc)
		} else {
			// Retain the lastresort. Delete everything else.
			if dpc.Key == LastResortKey {
				m.Log.Tracef("compressDPCL: Retaining last resort. i = %d, dpc: %+v",
					i, dpc)
				newConfig = append(newConfig, dpc)
				// last resort also found.. discard all remaining entries
				break
			}
			m.Log.Functionf("compressDPCL: Ignoring - i = %d, dpc: %+v", i, dpc)
			// Check and delete any OriginFile; might already have been deleted
			if dpc.OriginFile != "" {
				err := os.Remove(dpc.OriginFile)
				if err == nil {
					m.Log.Noticef("Removed OriginFile %s for %d", dpc.OriginFile, i)
				}
			}
		}
	}
	m.dpcList = types.DevicePortConfigList{
		CurrentIndex:   0,
		PortConfigList: newConfig,
	}
}

func (m *DpcManager) publishDPCL() {
	if m.PubDevicePortConfigList != nil {
		m.Log.Functionf("Publishing DevicePortConfigList compressed: %+v\n", m.dpcList)
		if err := m.PubDevicePortConfigList.Publish("global", m.dpcList); err != nil {
			m.Log.Errorf("Failed to publish compressed DPC list: %v", err)
		}
	}
}
