// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

func writePinningEntryForTest(t *testing.T, id uuid.UUID, e *PinningEntry) {
	t.Helper()
	e.UUID = id.String()
	cfg := &PinningConfig{Domains: map[string]*PinningEntry{id.String(): e}}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(pinConfigFile, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func fullPCPUs() *PolicyOptions { return &PolicyOptions{FullPCPUsOnly: true} }

func TestPinningPolicy_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	pinConfigDir = dir
	pinConfigFile = filepath.Join(dir, "config.json")

	id := uuid.NewV5(uuid.NamespaceOID, "vm1")
	var cfg types.DomainConfig
	cfg.DisplayName = "vm1"
	cfg.UUIDandVersion.UUID = id
	cfg.VmConfig.VCpus = 4

	// Non-pinned VM => default cpu_policy "none" => legacy (found=false).
	ensureDomainInPinningConfig(cfg)
	if _, _, found, _ := lookupPinningPolicy(id); found {
		t.Fatalf("default 'none' entry => policy found must be false")
	}

	// whole-core-smt = static + full-pcpus-only, threads_per_core default (2),
	// strict NUMA.
	writePinningEntryForTest(t, id, &PinningEntry{
		CPUPolicy:          "static",
		PolicyOptions:      fullPCPUs(),
		NUMATopologyPolicy: "single-numa-node",
	})
	if mode, numa, found, _ := lookupPinningPolicy(id); !found ||
		mode != cpuallocator.ModeWholeCoreSMT || numa != cpuallocator.NUMALocal {
		t.Fatalf("want whole-core-smt/single-numa-node/found, got mode=%v numa=%v found=%v", mode, numa, found)
	}

	// one-per-core = static + full-pcpus-only + threads_per_core 1, numa none.
	writePinningEntryForTest(t, id, &PinningEntry{
		CPUPolicy:          "static",
		PolicyOptions:      fullPCPUs(),
		ThreadsPerCore:     1,
		NUMATopologyPolicy: "none",
	})
	if mode, numa, found, _ := lookupPinningPolicy(id); !found ||
		mode != cpuallocator.ModeOnePerCore || numa != cpuallocator.NUMAAllowCross {
		t.Fatalf("want one-per-core/none/found, got mode=%v numa=%v found=%v", mode, numa, found)
	}
}

// static without full-pcpus-only, and cpu_policy none, both fall back to legacy
// exclusive pinning (found=false).
func TestPinningPolicy_LegacyMappings(t *testing.T) {
	dir := t.TempDir()
	pinConfigDir = dir
	pinConfigFile = filepath.Join(dir, "config.json")
	id := uuid.NewV5(uuid.NamespaceOID, "legacy")

	writePinningEntryForTest(t, id, &PinningEntry{CPUPolicy: "static"}) // no full-pcpus-only
	if _, _, found, _ := lookupPinningPolicy(id); found {
		t.Fatalf("static without full-pcpus-only must be legacy (found=false)")
	}
	writePinningEntryForTest(t, id, &PinningEntry{CPUPolicy: "none", PolicyOptions: fullPCPUs()})
	if _, _, found, _ := lookupPinningPolicy(id); found {
		t.Fatalf("cpu_policy none must be legacy (found=false) regardless of options")
	}
}

// Unset numa_topology_policy defaults to best-effort.
func TestPinningPolicy_NUMADefaultBestEffort(t *testing.T) {
	dir := t.TempDir()
	pinConfigDir = dir
	pinConfigFile = filepath.Join(dir, "config.json")
	id := uuid.NewV5(uuid.NamespaceOID, "be")
	writePinningEntryForTest(t, id, &PinningEntry{CPUPolicy: "static", PolicyOptions: fullPCPUs()})
	if _, numa, _, _ := lookupPinningPolicy(id); numa != cpuallocator.NUMABestEffort {
		t.Fatalf("unset numa_topology_policy must default to best-effort, got %v", numa)
	}
}

// A pinned VM's default entry is static-but-not-full-pcpus-only, i.e. legacy
// exclusive pinning (found=false) -- preserving today's behavior.
func TestPinningPolicy_PinnedDefaultIsLegacy(t *testing.T) {
	dir := t.TempDir()
	pinConfigDir = dir
	pinConfigFile = filepath.Join(dir, "config.json")
	id := uuid.NewV5(uuid.NamespaceOID, "pinned")
	var cfg types.DomainConfig
	cfg.DisplayName = "pinned"
	cfg.UUIDandVersion.UUID = id
	cfg.VmConfig.VCpus = 2
	cfg.VmConfig.CPUsPinned = true
	ensureDomainInPinningConfig(cfg)
	if _, _, found, _ := lookupPinningPolicy(id); found {
		t.Fatalf("pinned VM default must be legacy (found=false)")
	}
}

func TestPinningPolicy_AbsentIsLegacy(t *testing.T) {
	dir := t.TempDir()
	pinConfigDir = dir
	pinConfigFile = filepath.Join(dir, "config.json")
	if _, _, found, _ := lookupPinningPolicy(uuid.NewV5(uuid.NamespaceOID, "none")); found {
		t.Fatalf("absent VM must be legacy (found=false)")
	}
}

func TestIOPlacement(t *testing.T) {
	dir := t.TempDir()
	pinConfigDir = dir
	pinConfigFile = filepath.Join(dir, "config.json")

	id := uuid.NewV5(uuid.NamespaceOID, "iovm")
	// absent entry => default dedicated
	if got := lookupIOPlacement(id); got != "dedicated" {
		t.Fatalf("absent => dedicated, got %q", got)
	}
	writePinningEntryForTest(t, id, &PinningEntry{
		CPUPolicy: "static", PolicyOptions: fullPCPUs(), IOPlacement: "housekeeping",
	})
	if got := lookupIOPlacement(id); got != "housekeeping" {
		t.Fatalf("explicit housekeeping, got %q", got)
	}
	writePinningEntryForTest(t, id, &PinningEntry{
		CPUPolicy: "static", PolicyOptions: fullPCPUs(), IOPlacement: "",
	})
	if got := lookupIOPlacement(id); got != "dedicated" {
		t.Fatalf("empty io_placement => dedicated, got %q", got)
	}
}
