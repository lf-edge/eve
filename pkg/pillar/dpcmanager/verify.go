// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/conntester"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	waitForIfRetries    = 2
	waitForAsyncRetries = 2
	waitForIPDNSRetries = 5
)

func (m *DpcManager) restartVerify(ctx context.Context, reason string) {
	m.Log.Noticef("DPC verify: Restarting verification, reason: %s", reason)

	if m.dpcVerify.inProgress {
		m.Log.Noticef("DPC verify: DPC list verification in progress")
		return
	}
	if m.currentDPC() != nil &&
		!m.rsStatus.ChangeInProgress && m.rsStatus.Imposed {
		m.Log.Noticef("DPC verify: Radio-silence is imposed, skipping DPC verification")
		return
	}

	// Refresh the cache with interface attributes before verification so that
	// link updates happening during the verify will not be missed.
	m.rebuildCrucialIfs()

	// Restart at index zero, then skip entries with LastFailed after
	// LastSucceeded and a recent LastFailed (a minute or less).
	nextIndex := m.getNextTestableDPCIndex(0)
	if nextIndex == -1 {
		m.Log.Noticef("DPC verify: nothing testable")
		if m.PubDeviceNetworkStatus != nil {
			m.deviceNetStatus.Testing = false
			m.deviceNetStatus.CurrentIndex = m.dpcList.CurrentIndex
			err := m.PubDeviceNetworkStatus.Publish("global", m.deviceNetStatus)
			if err != nil {
				m.Log.Errorf("DPC verify: failed to publish DNS: %v", err)
			}
		}
		return
	}
	m.setupVerify(nextIndex, reason)
	m.runVerify(ctx, reason)
	m.compressAndPublishDPCL()
}

func (m *DpcManager) setupVerify(index int, reason string) {
	m.Log.Noticef("DPC verify: Setting up verification for DPC at index %d, reason: %s",
		index, reason)
	m.dpcList.CurrentIndex = index
	m.dpcVerify.inProgress = true
	m.dpcVerify.startedAt = time.Now()
	m.Log.Functionf("DPC verify: Started testing DPC (index %d): %v",
		m.dpcList.CurrentIndex, m.dpcList.PortConfigList[m.dpcList.CurrentIndex])
}

func (m *DpcManager) runVerify(ctx context.Context, reason string) {
	m.Log.Noticef("DPC verify: runVerify, reason: %s", reason)
	if !m.dpcVerify.inProgress {
		m.Log.Warn("DPC verify: not In-progress\n")
		return
	}
	if m.currentDPC() == nil {
		m.Log.Warn("DPC verify: nothing to verify")
		return
	}

	// Stop DPC test timer (if running).
	// It shall be resumed when we find working network configuration.
	if m.dpcTestTimer.C != nil {
		m.dpcTestTimer.Stop()
	}
	if m.dpcTestBetterTimer.C != nil {
		m.dpcTestBetterTimer.Stop()
	}

	endloop := false
	var res types.DPCState
	for !endloop {
		res = m.verifyDPC(ctx)
		m.Log.Noticef("DPC verify: Received status %s for DPC at index %d",
			res.String(), m.dpcList.CurrentIndex)

		// Publish DPC via dummy for logging purposes.
		dpc := m.currentDPC()
		_ = m.PubDummyDevicePortConfig.Publish(dpc.PubKey(), *dpc)

		// Decide next action based on the verification status.
		switch res {
		case types.DPCStateAsyncWait,
			// Configuration is not completely applied, some operations are still
			// running in the background.
			// Wait until we hear from DPC reconciler or until PendTimer triggers.
			types.DPCStatePCIWait,
			// verifyDPC has already published the new DNS for domainmgr.
			// Wait until we hear from domainmgr or until PendTimer triggers.
			types.DPCStateIPDNSWait, types.DPCStateIntfWait:
			// Either addressChange or PendTimer will result in calling us again.
			m.pendingDpcTimer = time.NewTimer(m.dpcTestDuration)
			return

		case types.DPCStateFail, types.DPCStateFailWithIPAndDNS:
			m.compressAndPublishDPCL()
			if m.dpcList.PortConfigList[0].IsDPCUntested() ||
				m.dpcList.PortConfigList[0].WasDPCWorking() {
				m.Log.Warnf("DPC verify: %v: New DPC arrived "+
					"or an old working DPC ascended to the top of DPC list "+
					"while network testing was in progress. "+
					"Restarting DPC verification.", res)
				m.setupVerify(0, "DPC at index 0 is untested")
				continue
			}

			// Move to next index (including wrap around).
			// Skip entries with LastFailed after LastSucceeded and a recent LastFailed
			// (a minute or less).
			nextIndex := m.getNextTestableDPCIndex(m.dpcList.CurrentIndex + 1)
			if nextIndex == -1 {
				m.Log.Errorf("DPC verify: No testable DPC found, working with DPC "+
					"found at index %d for now.", m.dpcList.CurrentIndex)
				endloop = true
			} else {
				m.setupVerify(nextIndex, "previous DPC failed")
			}

		case types.DPCStateSuccess, types.DPCStateRemoteWait:
			// We treat DPCStateRemoteWait as DPCStateSuccess because we manage to connect to the controller
			// and we need to wait for certificate or ECONNREFUSED fix on the server side
			endloop = true
			m.Log.Functionf("DPC verify: Working DPC configuration found "+
				"at index %d in DPC list", m.dpcList.CurrentIndex)
		}
	}

	// If there are port level errors in current selected DPC, we should mark
	// it for re-test during the next TestBetterTimer invocation.
	if m.dpcList.CurrentIndex != 0 || m.deviceNetStatus.HasErrors() {
		m.Log.Warnf("DPC verify: Working with DPC configuration found "+
			"at index %d in DPC list", m.dpcList.CurrentIndex)
		if m.dpcTestBetterInterval != 0 {
			// Look for a better choice in a while
			m.dpcTestBetterTimer = time.NewTimer(m.dpcTestBetterInterval)
			m.Log.Warnf("DPC verify: Kick started TestBetterInterval " +
				"to try and get back to DPC at Index 0")
		} else {
			m.Log.Warnf("DPC verify: Did not start TestBetterInterval " +
				"since timer interval is configured to be zero")
		}
	}

	m.Log.Noticef("DPC verify: Verification ended at index %d, has errors: %t",
		m.dpcList.CurrentIndex, m.deviceNetStatus.HasErrors())
	m.dpcVerify.inProgress = false
	m.compressAndPublishDPCL()
	m.updateDNS()

	// Did we get a new DPC at index zero?
	if m.dpcList.PortConfigList[0].IsDPCUntested() {
		m.Log.Warn("DPC verify: %w: New DPC arrived "+
			"or a old working DPC moved up to top of DPC list while network testing "+
			"was in progress. Restarting DPC verification.", res)
		m.restartVerify(ctx, "runVerify "+res.String())
		return
	}
	switch res {
	case types.DPCStateSuccess, types.DPCStateRemoteWait:
		// We just found a new DPC that restored our cloud connectivity.
		m.dpcVerify.cloudConnWorks = true
	default:
	}

	// Restart network test timer
	m.dpcTestTimer = time.NewTimer(m.dpcTestInterval)
}

func (m *DpcManager) verifyDPC(ctx context.Context) (status types.DPCState) {
	dpc := m.currentDPC()
	defer m.updateDNS()

	// Stop pending timer if its running.
	if m.pendingDpcTimer.C != nil {
		m.pendingDpcTimer.Stop()
	}

	// Check if there is any port assigned to an application.
	assignedPort, ifName, usedByUUID := dpc.IsAnyPortInPciBack(m.Log, &m.adapters, true)
	if assignedPort {
		errStr := fmt.Sprintf("port %s in PCIBack is "+
			"used by %s", ifName, usedByUUID.String())
		m.Log.Errorf("DPC verify: %s\n", errStr)
		dpc.RecordFailure(errStr)
		dpc.RecordPortFailure(ifName, errStr)
		status = types.DPCStateFail
		dpc.State = status
		return status
	}

	// Apply configuration even if some ports are missing (could be still in PCIBack).
	// Reconciler will automatically create pending configuration items.
	// If then connectivity check fails, we may decide if it is worth waiting for something.
	elapsed := time.Since(m.dpcVerify.startedAt)
	m.reconcileStatus = m.DpcReconciler.Reconcile(ctx, m.reconcilerArgs())
	if m.reconcileStatus.AsyncInProgress {
		if elapsed < waitForAsyncRetries*m.dpcTestDuration {
			status = types.DPCStateAsyncWait
			dpc.State = status
			return status
		}
		// Async operations were running for too long, cancel them and try connectivity.
		m.Log.Warnf("DPC verify: async ops are running for too long (waited for %v), "+
			"canceling them and continue with verification", elapsed)
		m.reconcileStatus.CancelAsyncOps()
	}

	// Check cloud connectivity.
	m.updateDNS()
	withNetTrace := m.traceNextConnTest()
	intfStatusMap, tracedProbes, err := m.ConnTester.TestConnectivity(
		m.deviceNetStatus, withNetTrace)
	// Use TestResults to update the DevicePortConfigList and DeviceNetworkStatus
	// Note that the TestResults will at least have an updated timestamp
	// for one of the ports.
	dpc.UpdatePortStatusFromIntfStatusMap(intfStatusMap)
	m.deviceNetStatus.UpdatePortStatusFromIntfStatusMap(intfStatusMap)
	defer func() {
		// Publish DPCL, DNS and potentially also netdump at the end when dpc.State
		// is determined.
		_ = m.PubDummyDevicePortConfig.Publish(dpc.PubKey(), *dpc) // for logging
		m.publishDPCL()
		m.deviceNetStatus.State = dpc.State
		m.publishDNS()
		if withNetTrace {
			var cloudConnWorks bool
			switch dpc.State {
			case types.DPCStateFail, types.DPCStateFailWithIPAndDNS:
				cloudConnWorks = false
			case types.DPCStateSuccess:
				cloudConnWorks = true
			default:
				// DpcManager is waiting for something (IP address, DNS server, etc.)
				// Do not publish recorded traces (will be done later when the waiting
				// has ended).
				return
			}
			m.publishNetdump(cloudConnWorks, tracedProbes)
		}
	}()

	if err == nil {
		if m.checkIfMgmtPortsHaveIPandDNS() {
			dpc.LastIPAndDNS = time.Now()
		}
		dpc.RecordSuccess()
		m.Log.Noticef("DPC verify: DPC passed network test: %+v", dpc)
		status = types.DPCStateSuccess
		dpc.State = status
		return status
	}

	_, rtf := err.(*conntester.RemoteTemporaryFailure)
	if rtf {
		m.Log.Errorf("DPC verify: remoteTemporaryFailure: %v", err)
		// NOTE: We retry until the certificate or ECONNREFUSED is fixed
		// on the server side.
		status = types.DPCStateRemoteWait
		dpc.State = status
		return status
	}

	// Connectivity test failed, maybe we are missing an interface or an address.
	elapsed = time.Since(m.dpcVerify.startedAt)
	portInPciBack, ifName, _ := dpc.IsAnyPortInPciBack(m.Log, &m.adapters, false)
	if portInPciBack {
		if elapsed < waitForIfRetries*m.dpcTestDuration {
			m.Log.Noticef("DPC verify: port %s is still in PCIBack (waiting for %v)",
				ifName, elapsed)
			status = types.DPCStatePCIWait
			dpc.State = status
			return status
		}
		// Continue...
	}

	availablePorts, missingPorts := m.checkMgmtPortsPresence()
	if len(missingPorts) > 0 {
		// Still waiting for network interface(s) to appear
		if elapsed < waitForIfRetries*m.dpcTestDuration {
			m.Log.Warnf("DPC verify: interface check: "+
				"retry due to missing ports: %v (waiting for %v)",
				missingPorts, elapsed)
			status = types.DPCStateIntfWait
			dpc.State = status
			return status
		}
		m.Log.Warnf("DPC verify: Mgmt ports %v are missing (waited for %v)",
			missingPorts, elapsed)
	} else {
		m.Log.Functionf("DPC verify: No required ports are missing.")
	}

	for _, ifName = range missingPorts {
		errStr := fmt.Sprintf("missing interface %s", ifName)
		m.Log.Warnf("DPC verify: %s", errStr)
		dpc.RecordPortFailure(ifName, errStr)
	}

	if len(availablePorts) == 0 {
		m.Log.Errorf("DPC verify: no available mgmt ports: exceeded timeout "+
			"(waited for %v): %v for %+v\n", elapsed, err, dpc)
		dpc.RecordFailure(err.Error())
		status = types.DPCStateFail
		dpc.State = status
		return status
	}

	// Check for the availability of IP configuration.
	if !m.checkIfMgmtPortsHaveIPandDNS() {
		// Still waiting for IP or DNS.
		if elapsed < waitForIPDNSRetries*m.dpcTestDuration {
			m.Log.Noticef("DPC verify: no IP/DNS: will retry (waiting for %v): "+
				"%v for %+v\n", elapsed, err, dpc)
			status = types.DPCStateIPDNSWait
			dpc.State = status
			return status
		}
		m.Log.Errorf("DPC verify: no IP/DNS: exceeded timeout (waited for %v): "+
			"%v for %+v\n", elapsed, err, dpc)
		dpc.RecordFailure(unwrapPortsNotReady(err).Error())
		status = types.DPCStateFail
		dpc.State = status
		return status
	}

	// Check for the readiness of uplink ports as signaled by the connectivity tester.
	// There might be a delay between IP/DNS configuration being submitted
	// and having a full effect on the connectivity testing.
	// For example, the Go resolver reloads resolv.conf at most once per 5 seconds.
	// See: https://github.com/golang/go/blob/release-branch.go1.18/src/net/dnsclient_unix.go#L362-L366
	// This means that a recent update of resolv.conf (not older than 5 seconds),
	// might not have been yet loaded and used by the connectivity test.
	notReadyErr, notReady := err.(*conntester.PortsNotReady)
	if notReady {
		if elapsed < waitForIPDNSRetries*m.dpcTestDuration {
			m.Log.Noticef("DPC verify: ports %v are not ready: will retry (waiting for %v): "+
				"%v for %+v\n", notReadyErr.Ports, elapsed, err, dpc)
			status = types.DPCStateIPDNSWait
			dpc.State = status
			return status
		}
		m.Log.Errorf("DPC verify: ports %v are not ready: exceeded timeout (waited for %v): "+
			"%v for %+v\n", notReadyErr.Ports, elapsed, err, dpc)
		dpc.RecordFailure(unwrapPortsNotReady(err).Error())
		status = types.DPCStateFailWithIPAndDNS
		dpc.State = status
		return status
	}

	m.Log.Errorf("DPC verify: %s\n", err)
	dpc.RecordFailure(err.Error())
	dpc.LastIPAndDNS = dpc.LastFailed
	status = types.DPCStateFailWithIPAndDNS
	dpc.State = status
	return status
}

func (m *DpcManager) testConnectivityToCloud(ctx context.Context) error {
	dpc := m.currentDPC()
	if dpc == nil {
		err := errors.New("device port config is not applied")
		m.Log.Warnf("testConnectivityToCloud: %v", err)
		return err
	}

	withNetTrace := m.traceNextConnTest()
	intfStatusMap, tracedProbes, err := m.ConnTester.TestConnectivity(
		m.deviceNetStatus, withNetTrace)
	dpc.UpdatePortStatusFromIntfStatusMap(intfStatusMap)
	if err == nil {
		dpc.State = types.DPCStateSuccess
		dpc.TestResults.RecordSuccess()
	}
	_ = m.PubDummyDevicePortConfig.Publish(dpc.PubKey(), *dpc)
	m.publishDPCL() // publish updated port errors
	m.updateDNS()

	if err == nil {
		m.Log.Functionf("testConnectivityToCloud: Device cloud connectivity test passed.")
		m.dpcVerify.cloudConnWorks = true
		if withNetTrace {
			m.publishNetdump(true, tracedProbes)
		}
		// Restart DPC test timer for next slot.
		m.dpcTestTimer = time.NewTimer(m.dpcTestInterval)
		return nil
	}

	_, rtf := err.(*conntester.RemoteTemporaryFailure)
	if withNetTrace {
		m.publishNetdump(rtf, tracedProbes)
	}

	if !m.dpcVerify.cloudConnWorks && !rtf {
		// If previous cloud connectivity test also failed, it means
		// that the current DPC configuration stopped working.
		// In this case we start the process where device tries to
		// figure out a DevicePortConfig that works.
		// We avoid doing this for remoteTemporaryFailures
		if m.dpcVerify.inProgress {
			m.Log.Functionf("testConnectivityToCloud: Device port configuration list " +
				"verification in progress")
			// Connectivity to cloud is already being figured out.
			// We wait till the next cloud connectivity test slot.
		} else {
			m.Log.Functionf("testConnectivityToCloud: Triggering Device port "+
				"verification to resume cloud connectivity after error: %v", err)
			// Start DPC verification to find a working configuration
			m.restartVerify(ctx, "testConnectivityToCloud")
		}
	} else {
		// Restart DPC test timer for next slot.
		m.dpcTestTimer = time.NewTimer(m.dpcTestInterval)
		if rtf {
			// The fact that cloud replied with a status code shows that the cloud is UP,
			// but not functioning fully at this time. So, we mark the cloud connectivity
			// as UP for now.
			m.Log.Warnf("testConnectivityToCloud: remoteTemporaryFailure: %v", err)
			m.dpcVerify.cloudConnWorks = true
			return nil
		} else {
			m.Log.Functionf("testConnectivityToCloud: Device cloud connectivity test "+
				"restart timer due to error: %v", err)
			m.dpcVerify.cloudConnWorks = false
		}
	}
	return err
}

// Move to next index (including wrap around).
// Skip entries with LastFailed after LastSucceeded and a recent
// LastFailed (a minute or less).
// Also skip entries with no management IP addresses.
func (m *DpcManager) getNextTestableDPCIndex(start int) int {
	m.Log.Functionf("getNextTestableDPCIndex: start %d\n", start)
	// We want to wrap around, but should not keep looping around.
	// We do one loop of the entire list searching for a testable candidate.
	// If no suitable test candidate is found, we reset the test index to -1.
	dpcListLen := len(m.dpcList.PortConfigList)
	if dpcListLen == 0 {
		newIndex := -1
		m.Log.Functionf("getNextTestableDPCIndex: empty list; current index %d new %d\n",
			m.dpcList.CurrentIndex, newIndex)
		return newIndex
	}
	count := 0
	newIndex := start % dpcListLen
	for count < dpcListLen {
		if m.dpcList.PortConfigList[newIndex].IsDPCTestable(m.DpcMinTimeSinceFailure) {
			break
		}
		m.Log.Functionf("getNextTestableDPCIndex: DPC %v is not testable",
			m.dpcList.PortConfigList[newIndex])
		newIndex = (newIndex + 1) % dpcListLen
		count++
	}
	if count == dpcListLen {
		newIndex = -1
	}
	m.Log.Functionf("getNextTestableDPCIndex: current index %d new %d\n",
		m.dpcList.CurrentIndex, newIndex)
	return newIndex
}

func (m *DpcManager) rebuildCrucialIfs() {
	m.dpcVerify.crucialIfs = make(map[string]netmonitor.IfAttrs)
	ifNames, err := m.NetworkMonitor.ListInterfaces()
	if err != nil {
		m.Log.Errorf("rebuildCrucialIfs: %v", err)
		return
	}
	for _, ifName := range ifNames {
		if !m.isInterfaceCrucial(ifName) {
			continue
		}
		ifIndex, _, err := m.NetworkMonitor.GetInterfaceIndex(ifName)
		if err != nil {
			m.Log.Errorf("rebuildCrucialIfs: %v", err)
			continue
		}
		ifAttrs, err := m.NetworkMonitor.GetInterfaceAttrs(ifIndex)
		if err != nil {
			m.Log.Errorf("rebuildCrucialIfs: %v", err)
			continue
		}
		m.dpcVerify.crucialIfs[ifName] = ifAttrs
	}
}

// network interface is crucial if it's either part of current running DPC or
// is part of DPC at index 0 in DevicePortConfigList
func (m *DpcManager) isInterfaceCrucial(ifName string) bool {
	portConfigList := m.dpcList.PortConfigList
	currentIndex := m.dpcList.CurrentIndex
	if ifName == "" || currentIndex < 0 || currentIndex >= len(portConfigList) {
		return false
	}
	// Is part of DPC at CurrentIndex in DPCL?
	portStatus := portConfigList[currentIndex].GetPortByIfName(ifName)
	if portStatus != nil {
		return true
	}
	// Is part of DPC at index 0 in DPCL?
	portStatus = portConfigList[0].GetPortByIfName(ifName)
	if portStatus != nil {
		return true
	}
	return false
}

// Check if at least one management port in the given DeviceNetworkStatus
// have at least one IP address each and at least one DNS server.
func (m *DpcManager) checkIfMgmtPortsHaveIPandDNS() bool {
	mgmtPorts := types.GetMgmtPortsAny(m.deviceNetStatus, 0)
	if m.reconcileStatus.DNS.Error != nil {
		m.Log.Warnf("resolv.conf has error: %v", m.reconcileStatus.DNS.Error)
		return false
	}
	for _, port := range mgmtPorts {
		numAddrs, err := types.CountLocalIPv4AddrAnyNoLinkLocalIf(m.deviceNetStatus, port)
		if err != nil {
			m.Log.Errorf("CountLocalIPv4AddrAnyNoLinkLocalIf failed for %s: %v",
				port, err)
			continue
		}
		if numAddrs < 1 {
			m.Log.Tracef("No addresses on %s", port)
			continue
		}
		numDNSServers := types.CountDNSServers(m.deviceNetStatus, port)
		if numDNSServers < 1 {
			m.Log.Tracef("Have addresses but no DNS on %s", port)
			continue
		}
		// Also confirm that the global resolv.conf contains entries for this port.
		dnsServers := m.reconcileStatus.DNS.Servers[port]
		if len(dnsServers) == 0 {
			m.Log.Tracef("Have addresses but DNS config is not yet installed "+
				"for %s", port)
			continue
		}
		return true
	}
	return false
}

func (m *DpcManager) checkMgmtPortsPresence() (available, missing []string) {
	mgmtPorts := types.GetMgmtPortsAny(m.deviceNetStatus, 0)
	for _, ifName := range mgmtPorts {
		_, exists, _ := m.NetworkMonitor.GetInterfaceIndex(ifName)
		if exists {
			available = append(available, ifName)
		} else {
			missing = append(missing, ifName)
		}
	}
	return available, missing
}

// If error returned from connectivity test was wrapped into PortsNotReady,
// unwrap it before recording it into DeviceNetworkStatus and DPCL.
// PortsNotReady error type is only useful between ConnectivityTester and DPC
// Manager to determine next steps in the connectivity testing process,
// but otherwise in wider context it produces somewhat confusing error
// message for users.
func unwrapPortsNotReady(err error) error {
	if pnrErr, isPNRErr := err.(*conntester.PortsNotReady); isPNRErr {
		return pnrErr.Unwrap()
	}
	return err
}
