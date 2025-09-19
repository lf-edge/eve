// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// loadLpsConfig initializes or updates the map of locally-submitted port
// configurations (`m.lpsConfig`) using the given DevicePortConfig.
// Each port entry is stored under its logical label.
// The applied flag and err are cleared to zero values (fresh load).
func (m *DpcManager) loadLpsConfig(dpc types.DevicePortConfig) {
	// Reset existing map
	m.lpsConfig = make(map[string]*lpsPortConfig)

	for _, port := range dpc.Ports {
		label := port.Logicallabel
		if label == "" {
			// Skip ports without a logical label.
			// This should be unreachable.
			continue
		}
		m.lpsConfig[label] = &lpsPortConfig{
			config:  port,
			applied: false,
			err:     nil,
		}
	}
}

// revertLpsConfig resets the state of all locally-submitted port configurations
// by clearing the `applied` and `err` runtime attributes. The configuration
// itself remains stored, but its status is reset as if it has not yet been processed.
func (m *DpcManager) revertLpsConfig() {
	for _, cfg := range m.lpsConfig {
		cfg.applied = false
		cfg.err = nil
	}
}

// areAllMgmtPortUsingLpsConfig checks whether all management ports in the
// current base DPC are using locally-submitted configuration from LPS.
// This check is used to prevent fallback to controller/fallback config
// when all management ports have been overridden by LPS-provided configuration.
func (m *DpcManager) areAllMgmtPortUsingLpsConfig() bool {
	baseDPC := m.getCurrentBaseDPCRef()
	if baseDPC == nil {
		return false
	}

	var mgmtPortCount int
	for _, port := range baseDPC.Ports {
		if !port.IsMgmt {
			continue
		}
		mgmtPortCount++

		lpsPortCfg, hasLPSConfig := m.lpsConfig[port.Logicallabel]
		if !hasLPSConfig || !lpsPortCfg.applied {
			return false
		}
	}

	// Return true only if there is at least one management port.
	return mgmtPortCount > 0
}

// getPortLpsConfigErr returns the error associated with the locally submitted
// configuration for the given port (identified by its logical label).
// If no LPS configuration exists for the port or the error is cleared, it returns nil.
func (m *DpcManager) getPortLpsConfigErr(portLabel string) error {
	if cfg, hasLPSConfig := m.lpsConfig[portLabel]; hasLPSConfig {
		return cfg.err
	}
	return nil
}

// mergeWithLpsConfig merges the given DevicePortConfig (typically received
// from the controller) with the locally submitted configuration stored in
// m.lpsConfig. For each port in the input DPC, if there is a corresponding
// locally submitted config and the controller allows local modifications
// (`AllowLocalModifications == true`), then the local config is used instead.
// In this case, the port entry in m.lpsConfig is marked as applied=true and
// err=nil. If local modifications are not allowed, the controller config is
// kept, and the entry is marked as applied=false with err set to a descriptive
// error. Any locally submitted ports not present in the controller-provided DPC
// are marked as applied=false and err=nil, effectively ignored.
// The function returns a new DevicePortConfig with the merged results.
func (m *DpcManager) mergeWithLpsConfig(dpc types.DevicePortConfig) types.DevicePortConfig {
	mergedDPC := dpc
	mergedDPC.Ports = nil

	// Reset to the base configuration first, removing any previously merged LPS changes.
	m.revertLpsConfig()

	// Process all ports from controller DPC.
	for _, port := range dpc.Ports {
		label := port.Logicallabel
		lpsCfg, hasLPSConfig := m.lpsConfig[label]
		if !hasLPSConfig {
			// No local config, keep controller config.
			mergedDPC.Ports = append(mergedDPC.Ports, port)
			continue
		}
		if !port.AllowLocalModifications {
			// Keep controller config, flag LPS config with permission error.
			mergedDPC.Ports = append(mergedDPC.Ports, port)
			lpsCfg.err = fmt.Errorf("local modifications not permitted for port %q",
				label)
			continue
		}
		if port.WirelessCfg.WType != lpsCfg.config.WirelessCfg.WType {
			// Keep controller config, reject LPS config due to type mismatch.
			mergedDPC.Ports = append(mergedDPC.Ports, port)
			lpsCfg.err = fmt.Errorf(
				"LPS configuration for port %q rejected: wireless type mismatch "+
					"(controller=%v, LPS=%v)", label, port.WirelessCfg.WType,
				lpsCfg.config.WirelessCfg.WType)
			continue
		}
		// Use the local config.
		mergedPort := port // copy port addresses, usage, cost, L2 config
		mergedPort.MTU = lpsCfg.config.MTU
		mergedPort.DhcpConfig = lpsCfg.config.DhcpConfig
		mergedPort.ProxyConfig = lpsCfg.config.ProxyConfig
		mergedPort.WirelessCfg = lpsCfg.config.WirelessCfg
		mergedPort.IgnoreDhcpNtpServers = lpsCfg.config.IgnoreDhcpNtpServers
		mergedPort.IgnoreDhcpIPAddresses = lpsCfg.config.IgnoreDhcpIPAddresses
		mergedPort.IgnoreDhcpGateways = lpsCfg.config.IgnoreDhcpGateways
		mergedPort.IgnoreDhcpDNSConfig = lpsCfg.config.IgnoreDhcpDNSConfig
		mergedPort.ConfigSource = lpsCfg.config.ConfigSource
		mergedPort.InvalidConfig = lpsCfg.config.InvalidConfig
		mergedPort.TestResults = lpsCfg.config.TestResults
		mergedDPC.Ports = append(mergedDPC.Ports, mergedPort)
		lpsCfg.applied = true
		lpsCfg.err = nil
	}
	return mergedDPC
}
