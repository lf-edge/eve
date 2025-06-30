// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func (m *DpcManager) makeLastResortDPC() (types.DevicePortConfig, error) {
	config := types.DevicePortConfig{}
	config.Key = LastResortKey
	config.Version = types.DPCIsMgmt
	// Set to the lowest priority possible.
	config.TimePriority = time.Unix(0, 0)
	ifNames, err := m.NetworkMonitor.ListInterfaces()
	if err != nil {
		err = fmt.Errorf("makeLastResortDPC: Failed to list interfaces: %v", err)
		return config, err
	}
	for _, ifName := range ifNames {
		ifIndex, _, err := m.NetworkMonitor.GetInterfaceIndex(ifName)
		if err != nil {
			m.Log.Errorf("makeLastResortDPC: failed to get interface index: %v", err)
			continue
		}
		ifAttrs, err := m.NetworkMonitor.GetInterfaceAttrs(ifIndex)
		if err != nil {
			m.Log.Errorf("makeLastResortDPC: failed to get interface attrs: %v", err)
			continue
		}
		if !m.includeLastResortPort(ifAttrs) {
			continue
		}
		port := types.NetworkPortConfig{
			IfName:       ifName,
			Phylabel:     ifName,
			Logicallabel: ifName,
			IsMgmt:       true,
			IsL3Port:     true,
			DhcpConfig: types.DhcpConfig{
				Dhcp: types.DhcpTypeClient,
				Type: types.NetworkTypeIPv4, // Dual-stack, IPv4 preferred
			},
		}
		config.Ports = append(config.Ports, port)
	}
	config.DoSanitize(m.Log, types.DPCSanitizeArgs{
		SanitizeSharedLabels: true,
	})
	return config, nil
}

func (m *DpcManager) includeLastResortPort(ifAttrs netmonitor.IfAttrs) bool {
	ifName := ifAttrs.IfName
	exclude := strings.HasPrefix(ifName, "vif") ||
		strings.HasPrefix(ifName, "nbu") ||
		strings.HasPrefix(ifName, "nbo") ||
		strings.HasPrefix(ifName, "wlan") ||
		strings.HasPrefix(ifName, "wwan") ||
		strings.HasPrefix(ifName, "keth")
	if exclude {
		return false
	}
	if m.isInterfaceAssigned(ifName) {
		return false
	}
	if ifAttrs.IsLoopback || !ifAttrs.WithBroadcast || ifAttrs.Enslaved {
		return false
	}

	switch ifAttrs.IfType {
	case "device":
		return true
	case "bridge":
		// Was this originally an ethernet interface turned into a bridge?
		_, exists, _ := m.NetworkMonitor.GetInterfaceIndex("k" + ifName)
		return exists
	case "can", "vcan":
		return false
	}

	return false
}

func (m *DpcManager) isInterfaceAssigned(ifName string) bool {
	ib := m.adapters.LookupIoBundleIfName(ifName)
	if ib == nil {
		return false
	}
	if ib.UsedByUUID != nilUUID {
		return true
	}
	return false
}

func (m *DpcManager) updateLastResortOnIntfChange(
	ctx context.Context, ifChange netmonitor.IfChange) {
	if m.lastResort == nil {
		return
	}
	includePort := m.includeLastResortPort(ifChange.Attrs)
	port := m.lastResort.LookupPortByIfName(ifChange.Attrs.IfName)
	if port == nil && includePort {
		m.addOrUpdateLastResortDPC(ctx, fmt.Sprintf("interface %s should be included",
			ifChange.Attrs.IfName))
	}
}

func (m *DpcManager) addOrUpdateLastResortDPC(ctx context.Context, reason string) {
	dpc, err := m.makeLastResortDPC()
	if err != nil {
		m.Log.Error(err)
		return
	}
	if m.lastResort != nil && m.lastResort.MostlyEqual(&dpc) {
		return
	}
	m.Log.Noticef("Adding/updating last-resort DPC, reason: %v", reason)
	m.lastResort = &dpc
	m.doAddDPC(ctx, dpc)
}
