// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager

import (
	"context"
	"fmt"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// processWwanStatus handles the latest state data published by the wwan service.
func (m *DpcManager) processWwanStatus(ctx context.Context, status types.WwanStatus) {
	dpc := m.currentDPC()
	if dpc != nil && (dpc.Key != status.DPCKey || dpc.TimePriority != status.DPCTimestamp) {
		// Obsolete status (not for currently used DPC).
		m.Log.Noticef("Skipping obsolete wwan status (for DPC: %s/%v, expecting: %s/%v)",
			status.DPCKey, status.DPCTimestamp, dpc.Key, dpc.TimePriority)
		return
	}
	if m.rsConfig.ChangeRequestedAt.After(status.RSConfigTimestamp) {
		// Obsolete status (not for the latest radio silence config).
		m.Log.Noticef("Skipping obsolete wwan status (for RS timestamp: %v, expecting: %v)",
			status.RSConfigTimestamp, m.rsConfig.ChangeRequestedAt)
		return
	}

	netName := func(modem types.WwanNetworkStatus) string {
		netName := modem.LogicalLabel
		if netName == "" {
			netName = modem.PhysAddrs.Interface
		}
		return netName
	}

	status.DoSanitize()
	changed := !m.wwanStatus.Equal(status)
	if changed {
		m.Log.Functionf("Have new wwan status: %v", m.wwanStatus)
	}
	wasInProgress := m.rsStatus.ChangeInProgress
	m.wwanStatus = status

	if m.rsStatus.ChangeInProgress {
		var errMsgs []string
		if m.rsStatus.ConfigError != "" {
			errMsgs = append(errMsgs, m.rsStatus.ConfigError)
		}
		for _, network := range status.Networks {
			if network.ConfigError != "" {
				errMsgs = append(errMsgs, netName(network)+": "+network.ConfigError)
			}
		}
		// Imposed is set to false below if any modem is not in the radio-off mode.
		m.rsStatus.Imposed = m.rsConfig.Imposed
		if m.rsStatus.Imposed {
			for _, network := range status.Networks {
				if network.Module.OpMode != types.WwanOpModeRadioOff {
					// Failed to turn off the radio
					m.Log.Warnf("Modem %s (network: %s) is not in the radio-off operational state",
						network.Module.Name, netName(network))
					m.rsStatus.Imposed = false // the actual state
					if network.ConfigError == "" {
						errMsgs = append(errMsgs,
							fmt.Sprintf("%s: modem %s is not in the radio-off operational state",
								netName(network), network.Module.Name))
					}
				}
			}
		}
		m.rsStatus.ConfigError = strings.Join(errMsgs, "\n")
		m.rsStatus.ChangeInProgress = false
		m.Log.Noticeln("Radio-silence state changing operation has finalized (as seen by nim)")
	}

	if changed || wasInProgress {
		if m.currentDPC() != nil {
			changedDPC := m.setDiscoveredWwanIfNames(m.currentDPC())
			if changedDPC {
				m.publishDPCL()
			}
		}
		m.restartVerify(ctx, "wwan status changed")
		m.updateDNS()
	}
}

// react to changed radio-silence configuration
func (m *DpcManager) doUpdateRadioSilence(ctx context.Context, newRS types.RadioSilence) {
	var errMsgs []string
	if !newRS.ChangeRequestedAt.After(m.rsConfig.ChangeRequestedAt) {
		return
	}

	// ChangeInProgress is enabled below if wwan config changes.
	m.rsStatus.ChangeInProgress = false
	m.rsStatus.ChangeRequestedAt = newRS.ChangeRequestedAt
	m.rsStatus.ConfigError = ""

	if newRS.ConfigError != "" {
		// Do not apply if configuration is marked as invalid by zedagent.
		// Keep RadioSilence.Imposed unchanged.
		errMsgs = append(errMsgs, newRS.ConfigError)
	} else {
		// Valid configuration, try to apply.
		wasImposed := m.rsConfig.Imposed
		m.rsConfig = newRS

		// update RF state for wwan and wlan
		m.reconcileStatus = m.DpcReconciler.Reconcile(ctx, m.reconcilerArgs())
		if m.reconcileStatus.RS.ConfigError != "" {
			errMsgs = append(errMsgs, m.reconcileStatus.RS.ConfigError)
			m.rsStatus.Imposed = m.reconcileStatus.RS.Imposed // should be false
		} else if wasImposed != newRS.Imposed {
			m.rsStatus.ChangeInProgress = true // waiting for status update from wwan service
			m.Log.Noticef("Triggering radio-silence state change to: %s", m.rsConfig)
		}
	}

	m.rsStatus.ConfigError = strings.Join(errMsgs, "\n")
	m.updateDNS()
}

// Handle cellular modems referenced in the device model by USB or PCI addresses
// but without interface name included.
// Use status published by the wwan microservice to learn the name of the interface
// created by the kernel for the modem data-path.
func (m *DpcManager) setDiscoveredWwanIfNames(dpc *types.DevicePortConfig) bool {
	var changed bool
	ifNames := make(map[string]string) // interface name -> logical label
	currentDPC := m.currentDPC()
	for i := range dpc.Ports {
		port := &dpc.Ports[i]
		if port.WirelessCfg.WType != types.WirelessTypeCellular {
			continue
		}
		wwanNetStatus := m.wwanStatus.GetNetworkStatus(port.Logicallabel)
		if wwanNetStatus != nil && wwanNetStatus.PhysAddrs.Interface != "" {
			ifNames[wwanNetStatus.PhysAddrs.Interface] = port.Logicallabel
			if port.IfName != wwanNetStatus.PhysAddrs.Interface {
				changed = true
			}
		} else if port.IfName == "" && currentDPC != nil && currentDPC != dpc {
			// Maybe we received new DPC while modem status is not yet available.
			// See if we can get interface name from the current DPC.
			currentPortConfig := currentDPC.LookupPortByLogicallabel(port.Logicallabel)
			if currentPortConfig != nil && currentPortConfig.IfName != "" &&
				currentPortConfig.USBAddr == port.USBAddr &&
				currentPortConfig.PCIAddr == port.PCIAddr {
				if _, used := ifNames[currentPortConfig.IfName]; !used {
					ifNames[currentPortConfig.IfName] = port.Logicallabel
					changed = true
				}
			}
		}
	}
	if !changed {
		return false
	}
	updatedPorts := make([]types.NetworkPortConfig, len(dpc.Ports))
	// First see if any wwan modem has changed interface name.
	for i := range dpc.Ports {
		port := &dpc.Ports[i]
		updatedPorts[i] = *port // copy
		if port.IfName != "" {
			if port2 := ifNames[port.IfName]; port2 != "" && port2 != port.Logicallabel {
				// This interface name was taken by port2.
				updatedPorts[i].IfName = ""
				m.Log.Noticef("Interface name %s was taken from port %s by port %s",
					port.IfName, port.Logicallabel, port2)
			}
		}
		for ifName, port2 := range ifNames {
			if port.Logicallabel == port2 {
				updatedPorts[i].IfName = ifName
			}
		}
	}
	dpc.Ports = updatedPorts
	return true
}
