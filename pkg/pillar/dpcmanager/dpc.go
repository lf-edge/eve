// Copyright (c) 2022,2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

func (m *DpcManager) currentDPC() *types.DevicePortConfig {
	if len(m.dpcList.PortConfigList) == 0 ||
		m.dpcList.CurrentIndex < 0 ||
		m.dpcList.CurrentIndex >= len(m.dpcList.PortConfigList) {
		return nil
	}
	return &m.dpcList.PortConfigList[m.dpcList.CurrentIndex]
}

func (m *DpcManager) doAddDPC(ctx context.Context, dpc types.DevicePortConfig) {
	m.setDiscoveredWwanIfNames(&dpc)
	mgmtCount := dpc.CountMgmtPorts(false)
	if mgmtCount == 0 {
		// This DPC will be ignored when we check IsDPCUsable which
		// is called from IsDPCTestable and IsDPCUntested.
		m.Log.Warnf("Received DevicePortConfig key %s has no management ports; "+
			"will be ignored", dpc.Key)
	}

	// always delete the existing manual DPC regardless of its time priority
	// there can be only one!
	if dpc.Key == ManualDPCKey {
		m.removeAllDPCbyKey(ManualDPCKey)
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
		m.Log.Functionf("doAddDPC: Config already current. No changes to process\n")
		return
	}

	// Restart verification.
	m.dpcVerify.inProgress = false
	m.restartVerify(ctx, fmt.Sprintf("new DPC (%s/%v)", dpc.Key, dpc.TimePriority))
}

func (m *DpcManager) doDelDPC(ctx context.Context, dpc types.DevicePortConfig) {
	m.setDiscoveredWwanIfNames(&dpc)
	configChanged := m.updateDPCListAndPublish(dpc, true)
	if !configChanged {
		m.Log.Functionf("doDelDPC: System current. No change detected.\n")
		return
	}
	m.restartVerify(ctx, fmt.Sprintf("removed DPC (%s/%v)", dpc.Key, dpc.TimePriority))
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

// Remove all entries by Key
func (m *DpcManager) removeAllDPCbyKey(key string) {
	var newConfig []types.DevicePortConfig
	for _, port := range m.dpcList.PortConfigList {
		if port.Key != key {
			newConfig = append(newConfig, port)
		}
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
// Returns whether or not the DPCList was present
func (m *DpcManager) ingestDPCList() (dpclPresentAtBoot bool) {
	m.Log.Functionf("IngestDPCList")
	item, err := m.PubDevicePortConfigList.Get("global")
	var storedDpcl types.DevicePortConfigList
	if err != nil {
		m.Log.Errorf("No global key for DevicePortConfigList")
	} else {
		storedDpcl = item.(types.DevicePortConfigList)
	}
	m.Log.Noticef("Initial DPCL %v", storedDpcl)
	var dpcl types.DevicePortConfigList
	for _, portConfig := range storedDpcl.PortConfigList {
		// Sanitize port labels and IsL3Port flag.
		portConfig.DoSanitize(m.Log, types.DPCSanitizeArgs{
			SanitizeTimePriority: false,
			SanitizeKey:          false,
			SanitizeName:         true,
			SanitizeL3Port:       true,
			SanitizeSharedLabels: true,
		})
		// Clear runtime errors (not config validation errors) from before reboot
		// and start fresh.
		for i := 0; i < len(portConfig.Ports); i++ {
			portPtr := &portConfig.Ports[i]
			if !portPtr.InvalidConfig {
				portPtr.Clear()
			}
		}
		if portConfig.CountMgmtPorts(false) == 0 {
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
		// We have at least one port
		dpclPresentAtBoot = true
	}
	m.dpcList = dpcl
	m.Log.Functionf("Sanitized DPCL %v", dpcl)
	m.dpcList.CurrentIndex = -1 // No known working one
	// Publish without compressing - this early in the init sequence we do not know
	// if lastresort is enabled. The list will be compressed later during DPC verification.
	m.publishDPCL()
	m.Log.Functionf("Published DPCL %v", m.dpcList)
	m.Log.Functionf("IngestDPCList len %d", len(m.dpcList.PortConfigList))
	return dpclPresentAtBoot
}

func (m *DpcManager) compressAndPublishDPCL() {
	m.compressDPCL()
	m.publishDPCL()
}

// compressDPCL reduces the size of the DevicePortConfigList (DPCL) by removing
// DPCs that are no longer useful to retain.
//
// The function preserves (i.e., does not remove):
//   - The latest (highest-priority) DPC at index 0, regardless of its source (key)
//   - The currently used DPC (the entry pointed to by CurrentIndex)
//   - The most recent DPC with working connectivity, i.e., the highest-priority
//     entry for which WasDPCWorking() returns true
//   - The most recent DPC from the controller (key `zedagent`)
//   - If there is no DPC from the controller (key `zedagent`), or if none of
//     the controller-provided DPCs have ever succeeded in a connectivity test,
//     retain the most recent DPC from each source to ensure fallback options remain available
//   - The "manual" DPC (a singleton created via TUI). Note: this behavior may be
//     revisited in the future, as retaining outdated manually created configs indefinitely
//     might not be ideal
//   - The "lastresort" DPC (a singleton generated by NIM) if network.fallback.any.eth
//     is enabled
//
// All other entries are removed from the DPCL. CurrentIndex is updated to continue
// pointing to the same DPC entry as before.
//
// If DPC verification is currently in progress, DPCL compression is skipped.
func (m *DpcManager) compressDPCL() {
	if m.dpcVerify.inProgress {
		m.Log.Tracef("compressDPCL: Skipped due to ongoing verification")
		return
	}

	var controllerDPCWorked bool
	for _, dpc := range m.dpcList.PortConfigList {
		if dpc.Key == "zedagent" && !dpc.LastSucceeded.IsZero() {
			controllerDPCWorked = true
			break
		}
	}

	var newDPCList []types.DevicePortConfig
	newCurrentIndex := m.dpcList.CurrentIndex
	retainedKeys := make(map[string]struct{})
	var retainedWorkingDPC bool
	for i, dpc := range m.dpcList.PortConfigList {
		var keep bool
		if i == 0 {
			// Always retain the latest network config.
			keep = true
		}
		if i == m.dpcList.CurrentIndex {
			// Never remove currently used DPC.
			keep = true
		}
		if !retainedWorkingDPC && dpc.WasDPCWorking() {
			// Do not remove the most recent DPC with working connectivity.
			keep = true
		}
		_, alreadyRetainedKey := retainedKeys[dpc.Key]
		if dpc.Key == "zedagent" && !alreadyRetainedKey {
			// Do not remove the most recent DPC from the controller.
			keep = true
		}
		if !controllerDPCWorked && !alreadyRetainedKey {
			// If no controller-provided DPC has ever succeeded in a connectivity test,
			// retain fallback options by keeping the most recent DPC from each source.
			keep = true
		}
		if dpc.Key == ManualDPCKey {
			// Never remove the "manual" DPC (there is always at most one).
			// Note: we will revisit this...
			keep = true
		}
		if dpc.Key == LastResortKey && m.enableLastResort {
			// If network.fallback.any.eth is enabled, do not remove the lastresort config.
			keep = true
		}

		if keep {
			m.Log.Tracef("compressDPCL: Keeping DPC %s", dpc.PubKey())
			newDPCList = append(newDPCList, dpc)
			if dpc.WasDPCWorking() {
				retainedWorkingDPC = true
			}
			retainedKeys[dpc.Key] = struct{}{}
		} else {
			m.Log.Noticef("compressDPCL: Removing DPC %s", dpc.PubKey())
			if dpc.ShaFile != "" {
				// Create a file containing the hash of the DPC to record
				// that it has already been used.
				// This applies only to DPCs injected by the installer.
				err := fileutils.SaveShaInFile(dpc.ShaFile, dpc.ShaValue)
				if err != nil {
					m.Log.Errorf("SaveShaInFile %s failed: %s", dpc.ShaFile, err)
				} else {
					m.Log.Noticef("Updated ShaFile %s for DPC %s",
						dpc.ShaFile, dpc.PubKey())
				}
			}
			if dpc.Key == LastResortKey {
				m.lastResort = nil
			}
			if i <= m.dpcList.CurrentIndex {
				newCurrentIndex--
			}
		}
	}

	m.dpcList = types.DevicePortConfigList{
		CurrentIndex:   newCurrentIndex,
		PortConfigList: newDPCList,
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
