// Copyright (c) 2017-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// RT testing config facility.
//
// Since the controller does not yet send RTIntent / CacheSizeBytes /
// MemBandwidthPercent fields, this file provides a local persistent
// override mechanism for testing RT and RDT isolation on a live node.
//
// Behaviour:
//   - Every time a domain is activated, its identity (UUID, DisplayName)
//     is written to /persist/rt/domain-config.json if it is not already
//     present. New entries get default (disabled) values for all RT fields.
//   - Before a domain is activated the file is read and any non-default
//     RT/RDT values found for that UUID are applied to the DomainConfig
//     that is about to be used.
//
// Workflow for the operator:
//  1. Boot the node, start all apps normally (entries appear in the file).
//  2. Edit /persist/rt/domain-config.json by hand — set rt_intent, cache
//     size, MBA percentage for the domains that need it.
//  3. Reboot the node (or restart the app). On next activation the values
//     are picked up automatically.
//
// Note on cpus_pinned: setting rt_intent=true automatically implies
// CPUsPinned=true — the operator never needs to set cpus_pinned
// separately. The field in the JSON is informational only: it reflects
// whether the controller originally requested pinning, or whether it
// was auto-derived from rt_intent on the last activation.

package domainmgr

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// vmModeString returns a human-readable name for VmMode since the type
// does not have a String() method.
func vmModeString(m types.VmMode) string {
	switch m {
	case types.PV:
		return "PV"
	case types.HVM:
		return "HVM"
	case types.Filler:
		return "Filler"
	case types.FML:
		return "FML"
	case types.NOHYPER:
		return "NOHYPER"
	case types.LEGACY:
		return "LEGACY"
	default:
		return fmt.Sprintf("Unknown(%d)", m)
	}
}

const (
	rtConfigDir  = "/persist/rt"
	rtConfigFile = "/persist/rt/domain-config.json"
)

// RTDomainEntry is one domain's RT/RDT testing overrides.
// JSON field names are kept short and human-friendly because the
// operator is expected to edit this file by hand.
//
// The operator only needs to edit three fields:
//
//	rt_intent            — master switch, implies CPU pinning
//	cache_size_bytes     — L3 CAT reservation (requires rt_intent + HW)
//	mem_bandwidth_percent — MBA throttle 1-100 (requires rt_intent + HW)
//
// All other fields are informational and auto-populated.
type RTDomainEntry struct {
	// --- Informational (auto-populated, do not edit) ---

	// DisplayName helps the operator identify the domain.
	DisplayName string `json:"display_name"`

	// UUID is stored for documentation; the map key is the UUID.
	UUID string `json:"uuid"`

	// VCpus shows how many vCPUs the domain has.
	VCpus int `json:"vcpus"`

	// VirtualizationMode is e.g. "NOHYPER", "HVM".
	VirtualizationMode string `json:"virtualization_mode"`

	// CPUsPinned is informational — reflects the effective pinning
	// state. It is automatically set to true when rt_intent is true.
	// The operator should NOT set this manually; set rt_intent instead.
	CPUsPinned bool `json:"cpus_pinned"`

	// --- Editable RT/RDT fields below ---

	// RTIntent activates topology-aware CPU allocation.
	// When true, CPUs are allocated from the same NUMA / L3 domain
	// and CPU pinning is forced on. This is the master RT switch.
	RTIntent bool `json:"rt_intent"`

	// CacheSizeBytes is the desired L3 cache reservation in bytes.
	// 0 means no L3 CAT isolation.
	// Requires rt_intent=true and hardware L3 CAT support.
	CacheSizeBytes uint64 `json:"cache_size_bytes"`

	// MemBandwidthPercent is the desired MBA throttle (1-100).
	// 0 means no MBA throttling.
	// Requires rt_intent=true and hardware MBA support.
	MemBandwidthPercent uint32 `json:"mem_bandwidth_percent"`

	// RTPriority is the SCHED_FIFO priority to set on the container's
	// init process (1-99). 0 means do not call sched_setscheduler —
	// the app is expected to set its own RT priorities via CAP_SYS_NICE.
	// Typical value: 95 (above threaded IRQ handlers at 50, below
	// migration/N at 99). Requires rt_intent=true.
	RTPriority int `json:"rt_priority"`
}

// RTDomainConfig is the top-level structure persisted to disk.
type RTDomainConfig struct {
	// Comment is a human-readable note stored in the JSON for the
	// operator's benefit.
	Comment string `json:"_comment,omitempty"`

	// Domains is keyed by UUID string.
	Domains map[string]*RTDomainEntry `json:"domains"`
}

// rtConfigMu serialises all reads and writes to the config file.
var rtConfigMu sync.Mutex

// loadRTConfig reads and parses the persistent RT config file.
// If the file does not exist an empty config is returned (no error).
func loadRTConfig() (*RTDomainConfig, error) {
	rtConfigMu.Lock()
	defer rtConfigMu.Unlock()
	return loadRTConfigLocked()
}

func loadRTConfigLocked() (*RTDomainConfig, error) {
	data, err := os.ReadFile(rtConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return newEmptyRTConfig(), nil
		}
		return nil, fmt.Errorf("failed to read %s: %w", rtConfigFile, err)
	}
	var cfg RTDomainConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", rtConfigFile, err)
	}
	if cfg.Domains == nil {
		cfg.Domains = make(map[string]*RTDomainEntry)
	}
	return &cfg, nil
}

func newEmptyRTConfig() *RTDomainConfig {
	return &RTDomainConfig{
		Comment: "EVE RT/RDT testing overrides. " +
			"Set rt_intent=true and optionally cache_size_bytes / mem_bandwidth_percent / rt_priority per domain, then reboot. " +
			"rt_intent=true automatically pins CPUs to the same NUMA/L3 domain. " +
			"rt_priority=0 (default) lets the app set its own RT priorities via CAP_SYS_NICE; " +
			"rt_priority=1..99 sets SCHED_FIFO on the init process (95 recommended).",
		Domains: make(map[string]*RTDomainEntry),
	}
}

// saveRTConfigLocked writes the config to disk atomically (write-tmp + rename).
// Caller must hold rtConfigMu.
func saveRTConfigLocked(cfg *RTDomainConfig) error {
	if err := os.MkdirAll(rtConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", rtConfigDir, err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal RT config: %w", err)
	}
	data = append(data, '\n')
	tmp := rtConfigFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, rtConfigFile); err != nil {
		return fmt.Errorf("failed to rename %s -> %s: %w", tmp, rtConfigFile, err)
	}
	return nil
}

// ensureDomainInRTConfig adds a domain entry to the persistent config
// file if it does not already exist. Existing entries are never modified
// so that hand-edited values survive reboots and app restarts.
func ensureDomainInRTConfig(config types.DomainConfig) {
	rtConfigMu.Lock()
	defer rtConfigMu.Unlock()

	uuidStr := config.UUIDandVersion.UUID.String()

	cfg, err := loadRTConfigLocked()
	if err != nil {
		log.Errorf("ensureDomainInRTConfig: %v (will create fresh)", err)
		cfg = newEmptyRTConfig()
	}

	if _, exists := cfg.Domains[uuidStr]; exists {
		// Already present — do NOT overwrite operator edits.
		return
	}

	// Reflect the effective pinning state: RTIntent forces pinning on.
	effectivePinned := config.VmConfig.CPUsPinned || config.VmConfig.RTIntent

	entry := &RTDomainEntry{
		DisplayName:         config.DisplayName,
		UUID:                uuidStr,
		VCpus:               config.VCpus,
		VirtualizationMode:  vmModeString(config.VirtualizationMode),
		CPUsPinned:          effectivePinned,
		RTIntent:            config.VmConfig.RTIntent,
		CacheSizeBytes:      config.VmConfig.CacheSizeBytes,
		MemBandwidthPercent: config.VmConfig.MemBandwidthPercent,
		RTPriority:          config.VmConfig.RTPriority,
	}
	cfg.Domains[uuidStr] = entry

	if err := saveRTConfigLocked(cfg); err != nil {
		log.Errorf("ensureDomainInRTConfig: failed to save: %v", err)
		return
	}
	log.Noticef("ensureDomainInRTConfig: added %s (%s) to %s",
		config.DisplayName, uuidStr, rtConfigFile)
}

// applyRTConfigOverrides reads the persistent RT config and applies any
// non-default RT/RDT values to the supplied DomainConfig before the
// domain is activated. The original config from the controller is not
// modified on disk — only the in-memory copy used for this activation.
//
// Setting rt_intent=true in the file automatically forces CPUsPinned=true
// in the config — the operator never needs to set cpus_pinned manually.
//
// Returns true if any field was overridden.
func applyRTConfigOverrides(config *types.DomainConfig) bool {
	cfg, err := loadRTConfig()
	if err != nil {
		log.Errorf("applyRTConfigOverrides: %v — proceeding without overrides", err)
		return false
	}

	uuidStr := config.UUIDandVersion.UUID.String()
	entry, exists := cfg.Domains[uuidStr]
	if !exists {
		return false
	}

	changed := false

	// --- RTIntent is the master switch ---
	if entry.RTIntent && !config.VmConfig.RTIntent {
		log.Noticef("applyRTConfigOverrides: %s (%s): setting RTIntent=true (from %s)",
			config.DisplayName, uuidStr, rtConfigFile)
		config.VmConfig.RTIntent = true
		changed = true
	}

	// --- Cache and bandwidth only matter when RTIntent is on ---
	if entry.CacheSizeBytes > 0 && config.VmConfig.CacheSizeBytes != entry.CacheSizeBytes {
		log.Noticef("applyRTConfigOverrides: %s (%s): setting CacheSizeBytes=%d (from %s)",
			config.DisplayName, uuidStr, entry.CacheSizeBytes, rtConfigFile)
		config.VmConfig.CacheSizeBytes = entry.CacheSizeBytes
		changed = true
	}

	if entry.MemBandwidthPercent > 0 && config.VmConfig.MemBandwidthPercent != entry.MemBandwidthPercent {
		log.Noticef("applyRTConfigOverrides: %s (%s): setting MemBandwidthPercent=%d (from %s)",
			config.DisplayName, uuidStr, entry.MemBandwidthPercent, rtConfigFile)
		config.VmConfig.MemBandwidthPercent = entry.MemBandwidthPercent
		changed = true
	}

	// --- RT priority override ---
	if entry.RTPriority > 0 && config.VmConfig.RTPriority != entry.RTPriority {
		if entry.RTPriority < 1 || entry.RTPriority > 99 {
			log.Errorf("applyRTConfigOverrides: %s (%s): ignoring invalid rt_priority=%d (must be 1-99)",
				config.DisplayName, uuidStr, entry.RTPriority)
		} else {
			log.Noticef("applyRTConfigOverrides: %s (%s): setting RTPriority=%d (from %s)",
				config.DisplayName, uuidStr, entry.RTPriority, rtConfigFile)
			config.VmConfig.RTPriority = entry.RTPriority
			changed = true
		}
	}

	// --- RTIntent always implies CPUsPinned ---
	// This is the canonical place where the implication is enforced.
	// The operator never has to set cpus_pinned in the JSON.
	if config.VmConfig.RTIntent {
		log.Noticef("applyRTConfigOverrides: %s (%s): forcing CPUsPinned=true (implied by RTIntent)",
			config.DisplayName, uuidStr)
		config.VmConfig.CPUsPinned = true
		changed = true
	}

	return changed
}

// removeFromRTConfig removes a domain entry from the persistent config.
// This is intentionally NOT called on domain delete — stale entries are
// harmless and the operator may want them to survive app re-deployment.
// Provided as a utility if explicit cleanup is ever needed.
func removeFromRTConfig(uuidStr string) {
	rtConfigMu.Lock()
	defer rtConfigMu.Unlock()

	cfg, err := loadRTConfigLocked()
	if err != nil {
		log.Warnf("removeFromRTConfig: %v", err)
		return
	}

	if _, exists := cfg.Domains[uuidStr]; !exists {
		return
	}

	delete(cfg.Domains, uuidStr)
	if err := saveRTConfigLocked(cfg); err != nil {
		log.Errorf("removeFromRTConfig: failed to save: %v", err)
		return
	}
	log.Noticef("removeFromRTConfig: removed %s from %s", uuidStr, rtConfigFile)
}

// getRTConfigPath returns the path to the RT config file (for logging / diagnostics).
func getRTConfigPath() string {
	return filepath.Clean(rtConfigFile)
}
