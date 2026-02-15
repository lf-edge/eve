// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package rdtmanager provides Intel RDT (Resource Director Technology) isolation
// for RT containers. It manages CLOS (Class of Service) allocation, L3 cache way
// mask accounting, CLOS 0 shrinking for true cache partitioning, MBA (Memory
// Bandwidth Allocation), PID-level isolation via the OS/resctrl interface, and
// monitoring of cache occupancy and memory bandwidth.
//
// The RDT Manager is a singleton that owns the pqos library lifecycle. It is
// initialized once during domainmgr startup and provides ApplyIsolation /
// ReleaseIsolation hooks that are called between container Create and Start.
package rdtmanager

import (
	"fmt"
	"math/bits"
	"sync"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"

	"github.com/intel/intel-cmt-cat/lib/go/pqos"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

var (
	log *base.LogObject

	// Singleton RDTManager instance.  The underlying libpqos C library
	// uses process-wide state and cannot be re-initialized after
	// pqos_fini(), so both the PQoS handle and the RDTManager that owns
	// it must live for the entire process lifetime.
	singletonOnce sync.Once
	singleton     *RDTManager
)

// SetLog sets the logger for the rdtmanager package.
func SetLog(l *base.LogObject) {
	log = l
}

func logFunctionf(format string, args ...interface{}) {
	if log != nil {
		log.Noticef(format, args...)
	} else {
		logrus.Infof(format, args...)
	}
}

func logWarnf(format string, args ...interface{}) {
	if log != nil {
		log.Warnf(format, args...)
	} else {
		logrus.Warnf(format, args...)
	}
}

func logErrorf(format string, args ...interface{}) {
	if log != nil {
		log.Errorf(format, args...)
	} else {
		logrus.Errorf(format, args...)
	}
}

// CLOSState tracks CLOS allocation for one L3 CAT domain.
// Each L3 CAT domain has its own independent set of CLOS IDs.
type CLOSState struct {
	// L3CATID identifies this L3 CAT domain
	L3CATID uint
	// MBAID identifies the MBA domain (usually 1:1 with L3CATID)
	MBAID uint
	// NumCLOS is the number of available CLOS IDs (from l3Cap.NumClasses)
	NumCLOS uint
	// NumWays is the number of cache ways in this domain
	NumWays uint
	// WaySize is bytes per way
	WaySize uint64
	// MinCBMBits is the minimum number of contiguous bits in a CBM
	MinCBMBits uint
	// UsedCLOS maps CLOS ID → domain UUID. CLOS 0 is always reserved.
	UsedCLOS map[uint]uuid.UUID
	// WayAllocation tracks way index → owner UUID. uuid.Nil = shared/CLOS 0.
	WayAllocation []uuid.UUID
	// CLOS0Mask is the current bitmask for CLOS 0 (shrinks as ways are allocated)
	CLOS0Mask uint64
	// FullMask is the bitmask with all ways set (e.g. 0xFFFFF for 20 ways)
	FullMask uint64
}

// RDTDomainState tracks RDT resources allocated to one container.
type RDTDomainState struct {
	// UUID of the container domain
	UUID uuid.UUID
	// DomainName is the human-readable container name
	DomainName string
	// L3CATID is the L3 CAT domain this container's CLOS belongs to
	L3CATID uint
	// CLOSID is the CLOS ID assigned to this container
	CLOSID uint
	// WayMask is the L3 cache way bitmask assigned
	WayMask uint64
	// NumWaysAllocated is the number of cache ways allocated
	NumWaysAllocated uint
	// MBAPercent is the MBA throttle percentage (0 = no limit)
	MBAPercent uint
	// ShimPID is the containerd-shim PID associated with this CLOS
	ShimPID int
	// MonGroup is the pqos monitoring group handle (may be nil)
	MonGroup *pqos.MonData
}

// RDTMetrics contains monitoring data for one domain.
type RDTMetrics struct {
	UUID              uuid.UUID
	LLCOccupancyBytes uint64
	MBMLocalBps       uint64
	MBMTotalBps       uint64
	MBMRemoteBps      uint64
	LLCMissRate       float64
	IPC               float64
	Timestamp         time.Time
}

// RDTCapabilities is a subset of capabilities for external consumption.
type RDTCapabilities struct {
	RDTSupport      bool
	L3CATSupport    bool
	L3CATNumClasses uint
	L3CATNumWays    uint
	L3CATWaySize    uint64
	L2CATSupport    bool
	MBASupport      bool
	MBAGranularity  uint
	CMTSupport      bool
	MBMSupport      bool
}

// RDTManager is the central component that owns the pqos library lifecycle
// and manages CLOS allocation, way mask accounting, MBA programming, PID
// association, and monitoring.
type RDTManager struct {
	mu          sync.Mutex
	pqosInst    *pqos.PQoS
	initialized bool

	// Hardware capabilities (immutable after init)
	l3Cap   *pqos.L3CACapability
	mbaCap  *pqos.MBACapability
	monCap  *pqos.MonCapability
	cpuInfo *pqos.CPUInfo

	// Per-L3-domain CLOS state
	closState map[uint]*CLOSState // keyed by L3CATID

	// Per-domain (container) tracking
	domains map[uuid.UUID]*RDTDomainState

	// Monitoring
	monGroups     map[uuid.UUID]*pqos.MonData
	monTicker     *time.Ticker
	monStop       chan struct{}
	latestMetrics map[uuid.UUID]*RDTMetrics
}

// GetRDTManager returns the process-wide singleton RDTManager.
// The instance is created lazily on first call; subsequent calls always
// return the same pointer.  This guarantees that the underlying libpqos
// C library (which cannot be re-initialized after pqos_fini()) is
// initialized exactly once and kept alive for the entire process.
//
// Call Init() on the returned manager if it has not been initialized yet.
func GetRDTManager() *RDTManager {
	singletonOnce.Do(func() {
		singleton = &RDTManager{
			closState:     make(map[uint]*CLOSState),
			domains:       make(map[uuid.UUID]*RDTDomainState),
			monGroups:     make(map[uuid.UUID]*pqos.MonData),
			latestMetrics: make(map[uuid.UUID]*RDTMetrics),
		}
	})
	return singleton
}

// NewRDTManager is a deprecated alias for GetRDTManager.
// It exists only to ease migration of callers — it returns the same
// process-wide singleton and never allocates a second instance.
func NewRDTManager() *RDTManager {
	return GetRDTManager()
}

// Init initializes the pqos library with OS interface and discovers
// hardware capabilities. This must be called once at startup.
func (m *RDTManager) Init() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initialized {
		return nil
	}

	// 1. Initialize pqos with OS interface (resctrl)
	m.pqosInst = pqos.GetInstance()
	cfg := &pqos.Config{
		Interface: pqos.InterOS,
		Verbose:   pqos.LogVerbosityDefault,
	}
	if err := m.pqosInst.Init(cfg); err != nil {
		return fmt.Errorf("pqos init failed: %w", err)
	}

	// 2. Discover capabilities
	//
	// Do NOT call m.pqosInst.Fini() on any error path below.  The pqos
	// instance is a process-wide singleton backed by libpqos which
	// cannot be re-initialized after pqos_fini().  Calling Fini() here
	// would permanently break the library for the rest of the process
	// and leave every future container in CLOS 0.
	cap, err := m.pqosInst.GetCapability()
	if err != nil {
		return fmt.Errorf("pqos get capability failed: %w", err)
	}

	cpuInfo, err := cap.GetCPUInfo()
	if err != nil {
		return fmt.Errorf("pqos get CPU info failed: %w", err)
	}
	m.cpuInfo = cpuInfo

	// L3 CAT
	if cap.HasL3CA() {
		l3Cap, err := cap.GetL3CA()
		if err == nil {
			m.l3Cap = l3Cap
			logFunctionf("RDT L3 CAT: %d classes, %d ways, %d bytes/way",
				l3Cap.NumClasses, l3Cap.NumWays, l3Cap.WaySize)
		} else {
			logWarnf("RDT L3 CAT detected but GetL3CA failed: %v", err)
		}
	}

	// MBA
	if cap.HasMBA() {
		mbaCap, err := cap.GetMBA()
		if err == nil {
			m.mbaCap = mbaCap
			logFunctionf("RDT MBA: %d classes, step=%d, linear=%v",
				mbaCap.NumClasses, mbaCap.ThrottleStep, mbaCap.IsLinear)
		} else {
			logWarnf("RDT MBA detected but GetMBA failed: %v", err)
		}
	}

	// Monitoring
	if cap.HasMon() {
		monCap, err := cap.GetMon()
		if err == nil {
			m.monCap = monCap
			logFunctionf("RDT Monitoring: maxRMID=%d, %d events",
				monCap.MaxRMID, monCap.NumEvents)
		}
	}

	// 3. Get minimum CBM bits
	var minCBMBits uint = 1
	if m.l3Cap != nil {
		minBits, err := m.pqosInst.L3CAGetMinCBMBits()
		if err == nil && minBits > 0 {
			minCBMBits = minBits
		}
	}

	// 4. Initialize per-L3-domain CLOS state
	if m.l3Cap != nil {
		l3CATIDs := cpuInfo.GetL3CATIDs()
		for _, l3id := range l3CATIDs {
			fullMask := (uint64(1) << m.l3Cap.NumWays) - 1

			// Read actual CLOS 0 mask from hardware instead of
			// assuming it equals fullMask.  After a domainmgr
			// restart the hardware may still carry narrowed masks
			// from a previous run.
			clos0Mask := fullMask
			cas, err := m.pqosInst.L3CAGet(l3id, m.l3Cap.NumClasses)
			if err == nil {
				for _, ca := range cas {
					if ca.ClassID == 0 {
						clos0Mask = ca.WaysMask
						break
					}
				}
			} else {
				logWarnf("RDT L3 domain %d: failed to read CLOS 0 mask from hardware: %v (using fullMask)", l3id, err)
			}

			// Find the MBA ID for this L3 CAT domain
			var mbaID uint
			for _, core := range cpuInfo.Cores {
				if core.L3CATID == l3id {
					mbaID = core.MBAID
					break
				}
			}

			m.closState[l3id] = &CLOSState{
				L3CATID:       l3id,
				MBAID:         mbaID,
				NumCLOS:       m.l3Cap.NumClasses,
				NumWays:       m.l3Cap.NumWays,
				WaySize:       uint64(m.l3Cap.WaySize),
				MinCBMBits:    minCBMBits,
				UsedCLOS:      map[uint]uuid.UUID{0: {}}, // CLOS 0 reserved
				WayAllocation: make([]uuid.UUID, m.l3Cap.NumWays),
				CLOS0Mask:     clos0Mask,
				FullMask:      fullMask,
			}

			logFunctionf("RDT L3 domain %d: %d CLOS, %d ways, %d bytes/way, fullMask=0x%x, clos0Mask=0x%x, minCBM=%d",
				l3id, m.l3Cap.NumClasses, m.l3Cap.NumWays, m.l3Cap.WaySize,
				fullMask, clos0Mask, minCBMBits)
		}
	}

	// 5. Start monitoring goroutine
	m.startMonitoring()

	m.initialized = true
	logFunctionf("RDT Manager initialized: L3CAT=%v MBA=%v MON=%v",
		m.l3Cap != nil, m.mbaCap != nil, m.monCap != nil)

	return nil
}

// IsInitialized returns whether the RDT Manager has been initialized.
func (m *RDTManager) IsInitialized() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.initialized
}

// HasL3CAT returns whether L3 Cache Allocation Technology is available.
func (m *RDTManager) HasL3CAT() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.l3Cap != nil
}

// HasMBA returns whether Memory Bandwidth Allocation is available.
func (m *RDTManager) HasMBA() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mbaCap != nil
}

// GetCapabilities returns the RDT capabilities for external reporting.
func (m *RDTManager) GetCapabilities() RDTCapabilities {
	m.mu.Lock()
	defer m.mu.Unlock()

	caps := RDTCapabilities{}
	if m.l3Cap != nil {
		caps.RDTSupport = true
		caps.L3CATSupport = true
		caps.L3CATNumClasses = m.l3Cap.NumClasses
		caps.L3CATNumWays = m.l3Cap.NumWays
		caps.L3CATWaySize = uint64(m.l3Cap.WaySize)
	}
	if m.mbaCap != nil {
		caps.RDTSupport = true
		caps.MBASupport = true
		caps.MBAGranularity = m.mbaCap.ThrottleStep
	}
	if m.monCap != nil {
		// Check for specific monitoring features
		for _, ev := range m.monCap.Events {
			if ev.Type == pqos.MonEventL3Occup {
				caps.CMTSupport = true
			}
			if ev.Type == pqos.MonEventLMemBW || ev.Type == pqos.MonEventTMemBW {
				caps.MBMSupport = true
			}
		}
	}
	return caps
}

// PopulateCapabilities fills in the RDT fields of a types.Capabilities struct.
func (m *RDTManager) PopulateCapabilities(caps *types.Capabilities) {
	rdtCaps := m.GetCapabilities()
	caps.RDTSupport = rdtCaps.RDTSupport
	caps.L3CATSupport = rdtCaps.L3CATSupport
	caps.L3CATNumClasses = rdtCaps.L3CATNumClasses
	caps.L3CATNumWays = rdtCaps.L3CATNumWays
	caps.L3CATWaySize = rdtCaps.L3CATWaySize
	caps.L2CATSupport = rdtCaps.L2CATSupport
	caps.MBASupport = rdtCaps.MBASupport
	caps.MBAGranularity = rdtCaps.MBAGranularity
	caps.CMTSupport = rdtCaps.CMTSupport
	caps.MBMSupport = rdtCaps.MBMSupport
}

// ApplyIsolation applies RDT isolation for a container. This must be called
// after containerd task creation (shim PID known) but before task Start.
//
// The sequence:
//  1. Allocate a CLOS ID from the L3 CAT domain
//  2. Compute a contiguous way mask from CacheSizeBytes
//  3. Mark ways as used in the allocation tracker
//  4. Shrink CLOS 0 to exclude allocated ways (true partitioning)
//  5. Program the new CLOS with the allocated way mask
//  6. Apply MBA if requested
//  7. Associate the containerd-shim PID with this CLOS (children inherit)
//  8. Start monitoring for this PID
//  9. Record state for later cleanup
//
// If any step fails, all previous steps are rolled back.
func (m *RDTManager) ApplyIsolation(
	domUUID uuid.UUID,
	domName string,
	shimPID int,
	l3catID uint,
	cacheBytes uint64,
	mbaPct uint32,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.initialized {
		return fmt.Errorf("RDT manager not initialized")
	}
	if m.l3Cap == nil {
		return fmt.Errorf("L3 CAT not available")
	}

	cs, ok := m.closState[l3catID]
	if !ok {
		return fmt.Errorf("unknown L3 CAT domain %d", l3catID)
	}

	// Check for duplicate
	if _, exists := m.domains[domUUID]; exists {
		return fmt.Errorf("RDT isolation already applied for %s", domUUID)
	}

	// 1. Allocate a CLOS ID
	closID, err := m.allocateCLOS(l3catID, domUUID)
	if err != nil {
		return fmt.Errorf("CLOS allocation failed: %w", err)
	}

	// 2. Compute way mask from requested bytes
	wayMask, numWays, err := m.computeWayMask(l3catID, cacheBytes)
	if err != nil {
		m.freeCLOS(l3catID, closID)
		return fmt.Errorf("way mask computation failed: %w", err)
	}

	// 3. Mark ways as used
	m.markWays(l3catID, domUUID, wayMask)

	// 4. Shrink CLOS 0 to exclude allocated ways
	oldCLOS0Mask := cs.CLOS0Mask
	cs.CLOS0Mask &^= wayMask
	err = m.pqosInst.L3CASet(l3catID, []pqos.L3CA{
		{ClassID: 0, WaysMask: cs.CLOS0Mask},
	})
	if err != nil {
		// Rollback: restore CLOS 0 mask, unmark ways, free CLOS
		cs.CLOS0Mask = oldCLOS0Mask
		m.unmarkWays(l3catID, domUUID)
		m.freeCLOS(l3catID, closID)
		return fmt.Errorf("failed to shrink CLOS 0: %w", err)
	}

	// 5. Program the new CLOS with the allocated way mask
	err = m.pqosInst.L3CASet(l3catID, []pqos.L3CA{
		{ClassID: closID, WaysMask: wayMask},
	})
	if err != nil {
		// Rollback: restore CLOS 0
		cs.CLOS0Mask = oldCLOS0Mask
		_ = m.pqosInst.L3CASet(l3catID, []pqos.L3CA{
			{ClassID: 0, WaysMask: cs.CLOS0Mask},
		})
		m.unmarkWays(l3catID, domUUID)
		m.freeCLOS(l3catID, closID)
		return fmt.Errorf("failed to program CLOS %d: %w", closID, err)
	}

	// 6. Apply MBA if requested
	actualMBAPct := uint(0)
	if mbaPct > 0 && mbaPct < 100 && m.mbaCap != nil {
		actual, mbaErr := m.applyMBA(l3catID, closID, mbaPct)
		if mbaErr != nil {
			logWarnf("MBA set failed for CLOS %d: %v (continuing without MBA)", closID, mbaErr)
			// MBA failure is non-fatal — cache isolation still works
		} else {
			actualMBAPct = actual
		}
	}

	// 7. Associate the containerd-shim PID with this CLOS
	// All child processes (the actual container) will inherit this association
	err = m.pqosInst.AllocAssocSetPID(shimPID, closID)
	if err != nil {
		// Rollback everything
		m.rollbackIsolation(l3catID, closID, wayMask, oldCLOS0Mask, domUUID)
		return fmt.Errorf("PID %d association with CLOS %d failed: %w", shimPID, closID, err)
	}

	// 8. Start monitoring for this PID (non-fatal if it fails)
	var monGroup *pqos.MonData
	if m.monCap != nil {
		events := uint(pqos.MonEventL3Occup | pqos.MonEventLMemBW | pqos.MonEventTMemBW)
		monGroup, err = m.pqosInst.MonStartPIDs([]int{shimPID}, events)
		if err != nil {
			logWarnf("RDT monitoring start failed for PID %d: %v", shimPID, err)
			monGroup = nil
			// Non-fatal — isolation still works
		}
	}

	// 9. Record state
	m.domains[domUUID] = &RDTDomainState{
		UUID:             domUUID,
		DomainName:       domName,
		L3CATID:          l3catID,
		CLOSID:           closID,
		WayMask:          wayMask,
		NumWaysAllocated: numWays,
		MBAPercent:       actualMBAPct,
		ShimPID:          shimPID,
		MonGroup:         monGroup,
	}
	if monGroup != nil {
		m.monGroups[domUUID] = monGroup
	}

	logFunctionf("RDT isolation applied for %s: CLOS=%d, L3CATID=%d, ways=0x%x (%d ways, %d bytes), MBA=%d%%, PID=%d",
		domName, closID, l3catID, wayMask, numWays, uint64(numWays)*cs.WaySize, mbaPct, shimPID)

	return nil
}

// ReleaseIsolation releases RDT resources for a container.
// This should be called during container teardown/cleanup.
func (m *RDTManager) ReleaseIsolation(domUUID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.domains[domUUID]
	if !ok {
		return nil // nothing to release
	}

	cs, ok := m.closState[state.L3CATID]
	if !ok {
		logErrorf("RDT release: unknown L3 domain %d for %s", state.L3CATID, state.DomainName)
		delete(m.domains, domUUID)
		return nil
	}

	// 1. Stop monitoring
	if state.MonGroup != nil {
		if err := m.pqosInst.MonStop(state.MonGroup); err != nil {
			logWarnf("RDT monitoring stop failed for %s: %v", state.DomainName, err)
		}
		delete(m.monGroups, domUUID)
	}
	delete(m.latestMetrics, domUUID)

	// 2. Release PID association (PID may already be gone, that's OK)
	_ = m.pqosInst.AllocReleasePID([]int{state.ShimPID})

	// 3. Reset CLOS to full mask (so it doesn't restrict anything)
	_ = m.pqosInst.L3CASet(state.L3CATID, []pqos.L3CA{
		{ClassID: state.CLOSID, WaysMask: cs.FullMask},
	})

	// 4. Restore CLOS 0 mask — add the freed ways back
	cs.CLOS0Mask |= state.WayMask
	_ = m.pqosInst.L3CASet(state.L3CATID, []pqos.L3CA{
		{ClassID: 0, WaysMask: cs.CLOS0Mask},
	})

	// 5. Free way tracking
	m.unmarkWays(state.L3CATID, domUUID)

	// 6. Free CLOS ID
	m.freeCLOS(state.L3CATID, state.CLOSID)

	// 7. Remove state
	delete(m.domains, domUUID)

	logFunctionf("RDT isolation released for %s: CLOS=%d, ways=0x%x",
		state.DomainName, state.CLOSID, state.WayMask)

	return nil
}

// GetDomainState returns the current RDT state for a domain, or nil if
// no isolation is active.
func (m *RDTManager) GetDomainState(domUUID uuid.UUID) *RDTDomainState {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.domains[domUUID]
	if !ok {
		return nil
	}
	// Return a copy
	cp := *state
	return &cp
}

// GetMetrics returns the latest RDT metrics for a domain, or nil if not available.
func (m *RDTManager) GetMetrics(domUUID uuid.UUID) *RDTMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	metrics, ok := m.latestMetrics[domUUID]
	if !ok {
		return nil
	}
	cp := *metrics
	return &cp
}

// PopulateDomainStatus fills in the RDT fields of a DomainStatus struct.
func (m *RDTManager) PopulateDomainStatus(domUUID uuid.UUID, status *types.DomainStatus) {
	state := m.GetDomainState(domUUID)
	if state == nil {
		return
	}

	m.mu.Lock()
	cs, ok := m.closState[state.L3CATID]
	m.mu.Unlock()

	status.L3CATID = state.L3CATID
	status.RDTCLOSID = state.CLOSID
	status.RDTCacheWayMask = state.WayMask
	if ok {
		status.RDTCacheAllocBytes = uint64(state.NumWaysAllocated) * cs.WaySize
	}
	status.RDTMBAPercent = uint32(state.MBAPercent)
	status.RDTActive = true
}

// PopulateDomainMetric fills in the RDT fields of a DomainMetric struct.
func (m *RDTManager) PopulateDomainMetric(domUUID uuid.UUID, metric *types.DomainMetric) {
	metrics := m.GetMetrics(domUUID)
	if metrics == nil {
		return
	}
	metric.LLCOccupancyBytes = metrics.LLCOccupancyBytes
	metric.MBMLocalBytesPerSec = metrics.MBMLocalBps
	metric.MBMTotalBytesPerSec = metrics.MBMTotalBps
	metric.LLCMissRate = metrics.LLCMissRate
}

// RecoverFromCrash resets all CLOS allocations and re-applies isolation
// for running domains. Called on restart if pillar crashed mid-operation.
func (m *RDTManager) RecoverFromCrash(runningDomains []RunningDomain) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.initialized || m.l3Cap == nil {
		return nil
	}

	logFunctionf("RDT crash recovery: resetting all CLOS allocations")

	// 1. Reset all CLOS to defaults
	if err := m.pqosInst.AllocReset(); err != nil {
		return fmt.Errorf("CLOS reset failed: %w", err)
	}

	// 2. Reinitialize CLOS state
	m.reinitCLOSState()

	// 3. Clear all domain tracking
	m.domains = make(map[uuid.UUID]*RDTDomainState)
	m.monGroups = make(map[uuid.UUID]*pqos.MonData)
	m.latestMetrics = make(map[uuid.UUID]*RDTMetrics)

	// 4. Re-apply isolation for each running domain
	for _, dom := range runningDomains {
		if dom.CacheSizeBytes > 0 || dom.MemBandwidthPercent > 0 {
			err := m.applyIsolationLocked(
				dom.UUID, dom.Name, dom.PID, dom.L3CATID,
				dom.CacheSizeBytes, dom.MemBandwidthPercent)
			if err != nil {
				logErrorf("RDT recovery: failed to re-apply for %s: %v", dom.Name, err)
				// Continue with other domains
			}
		}
	}

	return nil
}

// RunningDomain describes a domain that was running before a crash,
// used for crash recovery.
type RunningDomain struct {
	UUID                uuid.UUID
	Name                string
	PID                 int
	L3CATID             uint
	CacheSizeBytes      uint64
	MemBandwidthPercent uint32
}

// BuildTopology constructs a TopologyInfo from the pqos capabilities
// discovered during Init(). This keeps the CGO dependency (pqos) isolated
// inside the rdtmanager package so that domainmgr does not need to import
// the pqos package directly.
func (m *RDTManager) BuildTopology() (*cpuallocator.TopologyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.initialized {
		return nil, fmt.Errorf("RDT manager not initialized")
	}

	cap, err := m.pqosInst.GetCapability()
	if err != nil {
		return nil, fmt.Errorf("failed to get pqos capability: %w", err)
	}

	return cpuallocator.BuildTopologyFromPQoS(cap)
}

// Fini releases RDT allocations and stops monitoring but intentionally
// does NOT call pqos.Fini().  The underlying libpqos C library uses
// process-wide state and cannot be re-initialized after pqos_fini(),
// so the PQoS handle must stay alive for the entire process lifetime.
func (m *RDTManager) Fini() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.initialized {
		return
	}

	// Stop monitoring
	if m.monStop != nil {
		close(m.monStop)
	}
	if m.monTicker != nil {
		m.monTicker.Stop()
	}

	// Stop all monitoring groups
	for _, group := range m.monGroups {
		if group != nil {
			_ = m.pqosInst.MonStop(group)
		}
	}

	// Reset allocations
	if m.l3Cap != nil {
		_ = m.pqosInst.AllocReset()
	}

	// NOTE: we deliberately do NOT call m.pqosInst.Fini().
	// libpqos cannot be re-initialized after pqos_fini(); doing so
	// would leave the singleton permanently broken and every future
	// container would silently land in CLOS 0.

	m.initialized = false
	logFunctionf("RDT Manager shut down (pqos library kept alive)")
}

// --- Internal methods ---

// allocateCLOS finds the first unused CLOS ID (starting from 1) in the
// given L3 CAT domain and assigns it to the given domain UUID.
func (m *RDTManager) allocateCLOS(l3catID uint, domUUID uuid.UUID) (uint, error) {
	cs := m.closState[l3catID]

	for id := uint(1); id < cs.NumCLOS; id++ {
		if _, used := cs.UsedCLOS[id]; !used {
			cs.UsedCLOS[id] = domUUID
			return id, nil
		}
	}

	return 0, fmt.Errorf("no available CLOS in L3 domain %d (max %d, %d in use)",
		l3catID, cs.NumCLOS, len(cs.UsedCLOS))
}

// freeCLOS releases a CLOS ID back to the pool.
func (m *RDTManager) freeCLOS(l3catID uint, closID uint) {
	cs := m.closState[l3catID]
	if closID != 0 {
		delete(cs.UsedCLOS, closID)
	}
}

// computeWayMask computes a contiguous way bitmask for the requested cache
// size in bytes. Ways are allocated from the TOP (high bits) downward,
// leaving CLOS 0 the BOTTOM (low bits). This avoids fragmentation.
func (m *RDTManager) computeWayMask(l3catID uint, requestedBytes uint64) (uint64, uint, error) {
	cs := m.closState[l3catID]

	if cs.WaySize == 0 {
		return 0, 0, fmt.Errorf("L3 domain %d has zero way size", l3catID)
	}

	// Calculate number of ways needed (round up)
	numWaysNeeded := uint((requestedBytes + cs.WaySize - 1) / cs.WaySize)
	if numWaysNeeded < cs.MinCBMBits {
		numWaysNeeded = cs.MinCBMBits
	}
	if numWaysNeeded > cs.NumWays {
		return 0, 0, fmt.Errorf("requested %d bytes (%d ways) exceeds total %d ways in L3 domain %d",
			requestedBytes, numWaysNeeded, cs.NumWays, l3catID)
	}

	// Safety: ensure CLOS 0 retains at least MinCBMBits ways
	currentCLOS0Ways := uint(bits.OnesCount64(cs.CLOS0Mask))
	if currentCLOS0Ways < numWaysNeeded+cs.MinCBMBits {
		return 0, 0, fmt.Errorf(
			"allocating %d ways would leave CLOS 0 with %d ways (minimum %d) in L3 domain %d",
			numWaysNeeded, currentCLOS0Ways-numWaysNeeded, cs.MinCBMBits, l3catID)
	}

	// Find highest contiguous block of free ways (scan from top down)
	freeCount := uint(0)
	startWay := uint(0)
	found := false

	for i := int(cs.NumWays) - 1; i >= 0; i-- {
		if cs.WayAllocation[i] == (uuid.UUID{}) {
			freeCount++
			if freeCount >= numWaysNeeded {
				startWay = uint(i)
				found = true
				break
			}
		} else {
			freeCount = 0 // must be contiguous
		}
	}

	if !found {
		return 0, 0, fmt.Errorf("cannot find %d contiguous free ways in L3 domain %d (fragmented)",
			numWaysNeeded, l3catID)
	}

	// Build contiguous bitmask
	var mask uint64
	for i := startWay; i < startWay+numWaysNeeded; i++ {
		mask |= 1 << i
	}

	return mask, numWaysNeeded, nil
}

// markWays records which ways are owned by the given domain UUID.
func (m *RDTManager) markWays(l3catID uint, domUUID uuid.UUID, wayMask uint64) {
	cs := m.closState[l3catID]
	for i := uint(0); i < cs.NumWays; i++ {
		if wayMask&(1<<i) != 0 {
			cs.WayAllocation[i] = domUUID
		}
	}
}

// unmarkWays clears way ownership for the given domain UUID.
func (m *RDTManager) unmarkWays(l3catID uint, domUUID uuid.UUID) {
	cs := m.closState[l3catID]
	for i := uint(0); i < cs.NumWays; i++ {
		if cs.WayAllocation[i] == domUUID {
			cs.WayAllocation[i] = uuid.UUID{}
		}
	}
}

// applyMBA sets the MBA throttle for a CLOS, rounding to the nearest hardware step.
func (m *RDTManager) applyMBA(l3catID uint, closID uint, requestedPct uint32) (uint, error) {
	if m.mbaCap == nil {
		return 0, fmt.Errorf("MBA not supported")
	}

	cs := m.closState[l3catID]

	// Round to nearest step
	step := uint32(m.mbaCap.ThrottleStep)
	if step == 0 {
		step = 10 // default
	}
	actualPct := ((requestedPct + step/2) / step) * step
	if actualPct < step {
		actualPct = step
	}
	if actualPct > 100 {
		actualPct = 100
	}

	actual, err := m.pqosInst.MBASet(cs.MBAID, []pqos.MBA{
		{ClassID: closID, MBMax: uint(actualPct)},
	})
	if err != nil {
		return 0, fmt.Errorf("MBA set failed for CLOS %d: %w", closID, err)
	}

	var resultPct uint
	if len(actual) > 0 {
		resultPct = actual[0].MBMax
	} else {
		resultPct = uint(actualPct)
	}

	logFunctionf("MBA set for CLOS %d on L3 domain %d: requested=%d%%, rounded=%d%%, actual=%d%%",
		closID, l3catID, requestedPct, actualPct, resultPct)
	return resultPct, nil
}

// rollbackIsolation reverses a partial ApplyIsolation on failure.
func (m *RDTManager) rollbackIsolation(
	l3catID uint,
	closID uint,
	wayMask uint64,
	originalCLOS0Mask uint64,
	domUUID uuid.UUID,
) {
	cs := m.closState[l3catID]

	// Restore CLOS 0 mask
	cs.CLOS0Mask = originalCLOS0Mask
	_ = m.pqosInst.L3CASet(l3catID, []pqos.L3CA{
		{ClassID: 0, WaysMask: cs.CLOS0Mask},
	})

	// Reset the CLOS mask to full (harmless default)
	_ = m.pqosInst.L3CASet(l3catID, []pqos.L3CA{
		{ClassID: closID, WaysMask: cs.FullMask},
	})

	// Unmark ways
	m.unmarkWays(l3catID, domUUID)

	// Free CLOS
	m.freeCLOS(l3catID, closID)
}

// applyIsolationLocked is the same as ApplyIsolation but assumes the mutex is held.
// Used internally by RecoverFromCrash.
func (m *RDTManager) applyIsolationLocked(
	domUUID uuid.UUID,
	domName string,
	shimPID int,
	l3catID uint,
	cacheBytes uint64,
	mbaPct uint32,
) error {
	cs, ok := m.closState[l3catID]
	if !ok {
		return fmt.Errorf("unknown L3 CAT domain %d", l3catID)
	}

	closID, err := m.allocateCLOS(l3catID, domUUID)
	if err != nil {
		return err
	}

	wayMask, numWays, err := m.computeWayMask(l3catID, cacheBytes)
	if err != nil {
		m.freeCLOS(l3catID, closID)
		return err
	}

	m.markWays(l3catID, domUUID, wayMask)

	oldCLOS0Mask := cs.CLOS0Mask
	cs.CLOS0Mask &^= wayMask
	if err := m.pqosInst.L3CASet(l3catID, []pqos.L3CA{{ClassID: 0, WaysMask: cs.CLOS0Mask}}); err != nil {
		cs.CLOS0Mask = oldCLOS0Mask
		m.unmarkWays(l3catID, domUUID)
		m.freeCLOS(l3catID, closID)
		return err
	}

	if err := m.pqosInst.L3CASet(l3catID, []pqos.L3CA{{ClassID: closID, WaysMask: wayMask}}); err != nil {
		cs.CLOS0Mask = oldCLOS0Mask
		_ = m.pqosInst.L3CASet(l3catID, []pqos.L3CA{{ClassID: 0, WaysMask: cs.CLOS0Mask}})
		m.unmarkWays(l3catID, domUUID)
		m.freeCLOS(l3catID, closID)
		return err
	}

	actualMBAPct := uint(0)
	if mbaPct > 0 && mbaPct < 100 && m.mbaCap != nil {
		actual, mbaErr := m.applyMBA(l3catID, closID, mbaPct)
		if mbaErr == nil {
			actualMBAPct = actual
		}
	}

	if err := m.pqosInst.AllocAssocSetPID(shimPID, closID); err != nil {
		m.rollbackIsolation(l3catID, closID, wayMask, oldCLOS0Mask, domUUID)
		return err
	}

	var monGroup *pqos.MonData
	if m.monCap != nil {
		events := uint(pqos.MonEventL3Occup | pqos.MonEventLMemBW | pqos.MonEventTMemBW)
		monGroup, _ = m.pqosInst.MonStartPIDs([]int{shimPID}, events)
	}

	m.domains[domUUID] = &RDTDomainState{
		UUID:             domUUID,
		DomainName:       domName,
		L3CATID:          l3catID,
		CLOSID:           closID,
		WayMask:          wayMask,
		NumWaysAllocated: numWays,
		MBAPercent:       actualMBAPct,
		ShimPID:          shimPID,
		MonGroup:         monGroup,
	}
	if monGroup != nil {
		m.monGroups[domUUID] = monGroup
	}

	logFunctionf("RDT recovery: applied isolation for %s: CLOS=%d, ways=0x%x", domName, closID, wayMask)
	return nil
}

// reinitCLOSState resets all per-L3-domain CLOS tracking to the initial state.
func (m *RDTManager) reinitCLOSState() {
	for l3id, cs := range m.closState {
		cs.UsedCLOS = map[uint]uuid.UUID{0: {}} // Reserve CLOS 0
		cs.WayAllocation = make([]uuid.UUID, cs.NumWays)
		cs.CLOS0Mask = cs.FullMask
		m.closState[l3id] = cs
	}
}

// --- Monitoring ---

// startMonitoring starts a background goroutine that periodically polls
// RDT monitoring counters for all tracked domains.
func (m *RDTManager) startMonitoring() {
	m.monTicker = time.NewTicker(5 * time.Second)
	m.monStop = make(chan struct{})

	go func() {
		for {
			select {
			case <-m.monTicker.C:
				m.pollMetrics()
			case <-m.monStop:
				return
			}
		}
	}()
}

// pollMetrics collects monitoring data from all active monitoring groups.
func (m *RDTManager) pollMetrics() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.monGroups) == 0 {
		return
	}

	// Collect valid monitoring groups
	type groupEntry struct {
		uuid  uuid.UUID
		group *pqos.MonData
	}
	var entries []groupEntry
	var groups []*pqos.MonData

	for domUUID, g := range m.monGroups {
		if g != nil && g.Valid {
			entries = append(entries, groupEntry{uuid: domUUID, group: g})
			groups = append(groups, g)
		}
	}

	if len(groups) == 0 {
		return
	}

	// Poll all groups at once
	if err := m.pqosInst.MonPoll(groups); err != nil {
		logWarnf("RDT monitoring poll failed: %v", err)
		return
	}

	// Extract metrics per domain
	now := time.Now()
	for _, entry := range entries {
		g := entry.group
		if !g.Valid {
			// Group became invalid (container may have exited)
			logWarnf("RDT monitoring group invalid for %s, cleaning up", entry.uuid)
			delete(m.monGroups, entry.uuid)
			continue
		}

		metrics := &RDTMetrics{
			UUID:              entry.uuid,
			LLCOccupancyBytes: g.GetLLCOccupancy(),
			MBMLocalBps:       g.GetMBMLocalBandwidth(),
			MBMTotalBps:       g.GetMBMTotalBandwidth(),
			MBMRemoteBps:      g.GetMBMRemoteBandwidth(),
			LLCMissRate:       g.GetLLCMissRate(),
			IPC:               g.GetIPC(),
			Timestamp:         now,
		}
		m.latestMetrics[entry.uuid] = metrics
	}
}
