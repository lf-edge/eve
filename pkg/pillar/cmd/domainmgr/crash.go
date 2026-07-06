// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Crash handling for KVM/qemu domains. domainmgr owns the crash lifecycle
// end-to-end: it detects a mode-A crash (guest KVM_RUN -EFAULT ->
// RUN_STATE_INTERNAL_ERROR, surfaced as a DomainCrashEvent by the hypervisor),
// captures the guest core BEFORE any teardown, then applies policy (mark BROKEN
// and tear down, or hold for inspection). Mode-B (qemu process fatal signal)
// cores are written by the kernel via core_pattern and picked up on death.

package domainmgr

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/qemudump"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// cgroupUnlimited: memory.limit_in_bytes uses a near-max value for "no limit";
// treat any absurdly large limit as unlimited so we fall back to system RAM.
const cgroupUnlimited = uint64(1) << 62

// cgroupMemBase is the v1 memory-cgroup root as seen in pillar's mounted host fs.
const cgroupMemBase = "/hostfs/sys/fs/cgroup/memory/"

// compressorAvailMem returns the memory available to the dump compressor: the
// smallest headroom (limit-usage) across pillar's whole cgroup ancestry
// (/eve, /eve/services, /eve/services/pillar) and system MemAvailable. The zstd
// window is anonymous memory charged to pillar's cgroup, so it must fit the
// tightest binding cgroup — a parent can be loose while a child is nearly full
// (that OOM-killed zedbox). When a cgroup is unlimited, system RAM is the real
// bound. Returns 0 (=> minimum window) if nothing can be determined.
func compressorAvailMem() uint64 {
	// This reads cgroup-v1 memory accounting. On a non-v1 (v2/unified) host the
	// v1 files are absent, so we cannot learn pillar's cgroup headroom; sizing the
	// window from system RAM could then exceed the cgroup limit and OOM-kill
	// zedbox. Floor to the minimum window instead until cgroup-v2 is supported.
	if _, err := os.Stat(cgroupMemBase); err != nil {
		return 0
	}
	avail := uint64(math.MaxUint64)
	for _, g := range []string{"eve", "eve/services", "eve/services/pillar"} {
		if h, ok := cgroupHeadroom(cgroupMemBase + g); ok && h < avail {
			avail = h
		}
	}
	if sys := sysMemAvailableBytes(); sys > 0 && sys < avail {
		avail = sys
	}
	if avail == uint64(math.MaxUint64) {
		return 0
	}
	return avail
}

// cgroupHeadroom returns limit-usage for a v1 memory cgroup dir. ok is false if
// the cgroup can't be read or is effectively unlimited (not a binding
// constraint); a full cgroup returns (0, true).
func cgroupHeadroom(dir string) (uint64, bool) {
	limit, err1 := readUint64File(dir + "/memory.limit_in_bytes")
	usage, err2 := readUint64File(dir + "/memory.usage_in_bytes")
	if err1 != nil || err2 != nil || limit >= cgroupUnlimited {
		return 0, false
	}
	if usage >= limit {
		return 0, true
	}
	return limit - usage, true
}

func readUint64File(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

// sysMemAvailableBytes returns /proc/meminfo MemAvailable in bytes, or 0.
func sysMemAvailableBytes() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "MemAvailable:" {
			if kb, perr := strconv.ParseUint(fields[1], 10, 64); perr == nil {
				return kb * 1024
			}
			return 0
		}
	}
	return 0
}

const (
	// qemuDumpKeepPerDomain is the per-domain rotation ring size K.
	qemuDumpKeepPerDomain = 3
	// pauseOnCrashTimeout auto-releases a held domain.
	pauseOnCrashTimeout = 30 * time.Minute
	// stagingOrphanMaxAge: raw cores older than this in the staging dir are
	// orphans (real ones are picked up promptly) and get reaped opportunistically.
	stagingOrphanMaxAge = time.Hour

	crashGiB = 1 << 30
)

// qemuDumpDir is the encrypted-vault directory holding qemu/guest dumps.
var qemuDumpDir = filepath.Join(types.SealedDirName, "qemu-trace")

// captureResult is handed from the async guest-core capture goroutine back to
// the per-domain runHandler.
type captureResult struct {
	dumpPath string
	err      error
}

// setupDumpManager builds the vault-backed dump-storage manager and installs
// the host core_pattern so qemu process cores (mode B) land in the vault. Call
// after the vault is unlocked. On failure it logs and returns a usable manager
// anyway where possible; crash dumps are best-effort and must never be fatal to
// device management.
func setupDumpManager() *qemudump.Manager {
	var total uint64
	if us, err := diskmetrics.PersistUsageStat(log); err == nil {
		total = us.Total
	} else {
		log.Errorf("crash-dump: PersistUsageStat failed, using conservative caps: %v", err)
	}
	// Global cap min(20 GiB, 25% of /persist); floor max(4 GiB, 10%).
	globalCap := uint64(20 * crashGiB)
	if q := total / 4; total > 0 && q < globalCap {
		globalCap = q
	}
	floor := uint64(4 * crashGiB)
	if f := total / 10; f > floor {
		floor = f
	}

	mgr := qemudump.NewManager(qemudump.Config{
		Dir:            qemuDumpDir,
		KeepPerDomain:  qemuDumpKeepPerDomain,
		PerDomainQuota: globalCap,
		GlobalCap:      globalCap,
		FreeSpaceFloor: floor,
		Concurrency:    1,
		Space: func() (free, total uint64, err error) {
			us, err := diskmetrics.PersistUsageStat(log)
			if err != nil {
				return 0, 0, err
			}
			return us.Free, us.Total, nil
		},
		// AvailMem bounds the zstd window, which is anonymous memory charged to
		// pillar's /eve/services cgroup. Sizing it from system RAM alone
		// OOM-kills zedbox on a tight cgroup; sizing it from the cgroup alone
		// over-allocates when the cgroup is unlimited. So use the smaller of the
		// cgroup headroom and system MemAvailable — whichever actually binds.
		AvailMem: compressorAvailMem,
		Log:      log.Noticef,
	})

	if err := qemudump.InstallDefaultCorePattern(qemuDumpDir); err != nil {
		log.Errorf("crash-dump: failed to install core_pattern: %v", err)
	} else {
		log.Noticef("crash-dump: core_pattern -> %s", qemudump.CorePattern(qemuDumpDir))
	}
	// Drop any raw cores orphaned in the staging dir by a previous boot (their
	// qemu pid is gone), so staging stays bounded.
	if err := mgr.SweepStaging(); err != nil {
		log.Errorf("crash-dump: sweep orphaned staging cores: %v", err)
	}
	return mgr
}

// crashFrozen reports whether crash handling has frozen reconcile for the
// domain: while set, no teardown, restart, or config-driven change may proceed
// (a dump is in flight, or the domain is held for inspection).
func crashFrozen(status *types.DomainStatus) bool {
	return status.CrashState == types.CrashCaptureInProgress ||
		status.CrashState == types.CrashHeld
}

// beginCrashCapture starts capture-first handling of a mode-A crash: it freezes
// reconcile and launches a child goroutine that streams the guest core into the
// vault. The goroutine only reads qemu (never tears down and never touches
// createSema), so it cannot stall the watchdog or block other domains. Policy
// is applied by finishCrashCapture once the result arrives on captureDone.
func beginCrashCapture(ctx *domainContext, status *types.DomainStatus,
	ev types.DomainCrashEvent, captureDone chan<- captureResult) {

	log.Warnf("crash-dump: domain %s crashed (runState=%s); capturing guest core before teardown",
		status.Key(), ev.RunState)
	status.CrashState = types.CrashCaptureInProgress
	status.CrashRunState = ev.RunState
	publishDomainStatus(ctx, status)

	if ctx.dumpMgr == nil || !ctx.qemuGuestCore {
		captureDone <- captureResult{}
		return
	}

	key := status.Key()
	snapshot := *status // immutable copy for the reader goroutine
	mgr := ctx.dumpMgr
	go func() {
		w, err := mgr.NewDump(key, qemudump.KindGuestCore)
		if err != nil {
			captureDone <- captureResult{err: err}
			return
		}
		dumpErr := hyper.Task(&snapshot).DumpGuestMemory(snapshot.DomainName, w)
		closeErr := w.Close()
		if dumpErr != nil {
			captureDone <- captureResult{err: dumpErr}
			return
		}
		captureDone <- captureResult{dumpPath: w.Path(), err: closeErr}
	}()
}

// finishCrashCapture records the capture outcome and applies crash policy.
func finishCrashCapture(ctx *domainContext, status *types.DomainStatus, res captureResult) {
	if res.err != nil {
		log.Errorf("crash-dump: guest core for %s failed: %v", status.Key(), res.err)
	} else if res.dumpPath != "" {
		status.GuestCoreDumpPath = res.dumpPath
		status.LastDumpTaken = true
		log.Warnf("crash-dump: guest core for %s written to %s", status.Key(), res.dumpPath)
	}
	status.CrashState = types.CrashCaptured

	// Report a precise, mode-A message to the controller.
	msg := "guest VM crashed (guest core capture failed)"
	if status.LastDumpTaken {
		msg = "guest VM crashed, guest core saved"
	}

	if ctx.qemuPauseOnCrash {
		holdCrashedDomain(ctx, status, msg)
		return
	}
	brokenAndTeardown(ctx, status, msg)
}

// holdCrashedDomain keeps qemu alive and frozen for live inspection until an
// operator releases it or the timeout expires.
func holdCrashedDomain(ctx *domainContext, status *types.DomainStatus, msg string) {
	status.CrashState = types.CrashHeld
	status.HoldUntil = time.Now().Add(pauseOnCrashTimeout)
	status.State = types.BROKEN
	if ctx.qemuGdb {
		// Surface the gdbstub for the operator (only exposed when debug.qemu.gdb
		// was set at domain start). Mirrors gdbSocketPath in the hypervisor.
		status.GdbSocket = filepath.Join("/run/hypervisor/kvm", status.DomainName, "gdb")
	}
	status.SetErrorNow(msg + "; held for inspection (debug.qemu.pause.on.crash), qemu left alive")
	log.Warnf("crash-dump: holding domain %s for inspection until %s",
		status.Key(), status.HoldUntil.Format(time.RFC3339))
	publishDomainStatus(ctx, status)
}

// brokenAndTeardown clears the freeze, marks the domain BROKEN, and tears down
// qemu via the normal lifecycle.
func brokenAndTeardown(ctx *domainContext, status *types.DomainStatus, errMsg string) {
	status.CrashState = types.CrashNone
	status.Activated = false
	status.State = types.BROKEN
	status.SetErrorNow(errMsg)
	if err := hyper.Task(status).Delete(status.DomainName); err != nil {
		log.Errorf("crash-dump: delete domain %s: %v", status.DomainName, err)
	}
	if err := hyper.Task(status).Cleanup(status.DomainName); err != nil {
		log.Errorf("crash-dump: cleanup domain %s: %v", status.DomainName, err)
	}
	status.DomainId = 0
	publishDomainStatus(ctx, status)
}

// maybeReleaseHold releases a held (pause-on-crash) domain once its timeout
// expires, then tears it down.
func maybeReleaseHold(ctx *domainContext, status *types.DomainStatus) {
	if status.CrashState != types.CrashHeld || time.Now().Before(status.HoldUntil) {
		return
	}
	log.Warnf("crash-dump: pause-on-crash hold for %s expired; releasing", status.Key())
	brokenAndTeardown(ctx, status, "crash inspection hold expired; domain recovered")
}

// pickupProcessCore compresses a kernel-written qemu process core (mode B) into
// the vault, if one is waiting for this domain's qemu pid, and returns the .zst
// path ("" if none / not a qemu domain / on error). Call while DomainId still
// holds the dead qemu's pid.
func pickupProcessCore(ctx *domainContext, status *types.DomainStatus) string {
	if ctx.dumpMgr == nil || status.DomainId == 0 {
		return ""
	}
	log.Noticef("crash-dump: checking for qemu process core of %s (pid %d)",
		status.Key(), status.DomainId)
	p, err := ctx.dumpMgr.PickupProcessCore(status.Key(), status.DomainId)
	if err != nil {
		log.Errorf("crash-dump: pickup qemu process core for %s: %v", status.Key(), err)
		return ""
	}
	if p != "" {
		status.GuestCoreDumpPath = p
		log.Warnf("crash-dump: qemu process core for %s written to %s", status.Key(), p)
	}
	// A crash event is when staging can grow, so reap any orphaned raw cores now
	// (never-picked-up cores would otherwise linger unbounded until reboot).
	if err := ctx.dumpMgr.SweepStagingStale(stagingOrphanMaxAge); err != nil {
		log.Errorf("crash-dump: sweep stale staging cores: %v", err)
	}
	return p
}
