// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// EVE-kvm <-> EVE-k boot-disk conversion driven from baseosmgr.
//
// A cross-flavor base-OS update is allowed (only when the device has no
// volumes; see the IsHVTypeKube/IsVersionHVTypeKube seam in handlebaseos.go)
// but the EVE-k partition geometry — a 2 GB ESP plus two 10 GB IMG partitions —
// may not yet exist on an older device. maybeConvert drives the standalone
// storage-resizer binary (via the diskconvert library) to repartition the boot
// disk before the A/B install, recording progress on BaseOsStatus so zedagent
// reports it as ZDEVICE_STATE_CONVERTING + sub_state.

package baseosmgr

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/diskconvert"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

// resizeFailedMarkerName is the file storage-init's resize_abort writes on the
// CONFIG partition when an offline shrink/grow aborts (see
// pkg/storage-init/storage-resize.sh). baseosmgr reads it to report the decline
// and to avoid re-arming a conversion that already failed under this EVE version.
const resizeFailedMarkerName = "resize-failed.json"

// resizeFailedMarker is the JSON contract of resize-failed.json. EveRelease is
// the EVE version the failed conversion ran under (the retry gate); the offline
// resizer is the running image's, so a retry under the same version fails
// identically. PersistRecreated records whether the abort also wiped /persist.
type resizeFailedMarker struct {
	EveRelease       string `json:"eve_release"`
	Step             string `json:"step"`
	RC               string `json:"rc"`
	TS               string `json:"ts"`
	PersistRecreated bool   `json:"persist_recreated"`
	// Detail is the underlying tool message that caused the abort (e.g. the
	// resize2fs/e2fsck stderr line), so the decline names the real reason instead
	// of a bare rc. Optional; older markers without it decline as before.
	Detail string `json:"detail"`
}

// declineReason builds the operator-facing BaseOsStatus.Error text, calling out
// the underlying tool message (when captured) and whether workloads were lost
// (persist recreated) vs preserved.
func (m resizeFailedMarker) declineReason() string {
	persist := "/persist preserved"
	if m.PersistRecreated {
		persist = "/persist was recreated (workloads lost; device identity restored from backup)"
	}
	reason := fmt.Sprintf("boot-disk conversion failed (%s, rc=%s) under EVE %s",
		m.Step, m.RC, m.EveRelease)
	if m.Detail != "" {
		reason += ": " + m.Detail
	}
	return reason + "; " + persist +
		"; not retrying until the EVE version changes or the update is withdrawn"
}

// readResizeFailedMarker reads resize-failed.json from the mounted CONFIG
// partition. Returns false if it is absent or unparseable.
func readResizeFailedMarker(mountDir string) (resizeFailedMarker, bool) {
	var m resizeFailedMarker
	b, err := os.ReadFile(filepath.Join(mountDir, resizeFailedMarkerName))
	if err != nil {
		return m, false
	}
	if err := json.Unmarshal(b, &m); err != nil {
		log.Warnf("readResizeFailedMarker: parse %s: %v", resizeFailedMarkerName, err)
		return m, false
	}
	return m, true
}

// runtimeConfigDir is the read-only tmpfs overlay of the CONFIG partition that
// the rest of EVE reads at runtime. The marker is cleared here too (not just on
// the partition) so the two never diverge -- confusing when debugging. PCR14 was
// already measured by the onboot measure-config app, so the overlay clear is for
// consistency, not the vault seal.
const runtimeConfigDir = "/config"

// eveVersionFile is the path runningEveRelease reads; a var so tests can point it
// at a temp file.
var eveVersionFile = types.EveVersionFile

// runningEveRelease returns the version of the currently running EVE image, or
// "" if it cannot be read. The caller treats "" as a match (conservatively
// declines) rather than risk re-arming a conversion that reboot-loops.
func runningEveRelease() string {
	b, err := os.ReadFile(eveVersionFile)
	if err != nil {
		log.Warnf("runningEveRelease: %v", err)
		return ""
	}
	return strings.TrimSpace(string(b))
}

// markerVerdict decides what to do given a resize-failed marker (present=ok) and
// the running EVE version, with no I/O so it is unit-testable. A non-empty
// declineReason means a prior failure under this running image: report it and do
// not re-arm (a retry would fail identically). clearStale means the marker is
// from a different EVE version (the running image changed and may carry a fixed
// resizer): clear it and proceed. An unreadable running version ("") is treated
// as a match, so an ambiguous state declines rather than risk a reboot loop.
func markerVerdict(m resizeFailedMarker, ok bool, running string) (declineReason string, clearStale bool) {
	if !ok {
		return "", false
	}
	if running == "" || running == m.EveRelease {
		return m.declineReason(), false
	}
	return "", true
}

// baseOsTargetChanged reports whether the conversion target image differs between
// two BaseOsConfig revisions. A new target is a fresh attempt, so a pending
// resize-failure marker should be cleared; a modify that only flips Activate or
// bumps RetryUpdateCounter must not.
func baseOsTargetChanged(oldCfg, newCfg types.BaseOsConfig) bool {
	return oldCfg.BaseOsVersion != newCfg.BaseOsVersion ||
		oldCfg.ContentTreeUUID != newCfg.ContentTreeUUID
}

// removeMarkerFile removes path if present; an already-absent file is not an error.
func removeMarkerFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// resizeFailedMarkerPresent cheaply checks the read-only /config overlay for the
// marker, so callers can skip the CONFIG-partition mount + overlay remount when
// there is nothing to clear.
func resizeFailedMarkerPresent() bool {
	_, err := os.Stat(filepath.Join(runtimeConfigDir, resizeFailedMarkerName))
	return err == nil
}

// removeResizeFailedMarkerFromOverlay removes the marker from the runtime /config
// tmpfs overlay, remounting it rw then back to ro around the delete -- the same
// approach cmd/monitor uses to update /config. Best-effort.
func removeResizeFailedMarkerFromOverlay() error {
	if err := syscall.Mount("none", runtimeConfigDir, "tmpfs", syscall.MS_REMOUNT, ""); err != nil {
		return fmt.Errorf("remount %s rw: %w", runtimeConfigDir, err)
	}
	rmErr := removeMarkerFile(filepath.Join(runtimeConfigDir, resizeFailedMarkerName))
	if err := syscall.Mount("none", runtimeConfigDir, "tmpfs", syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		if rmErr != nil {
			return rmErr
		}
		return fmt.Errorf("remount %s ro: %w", runtimeConfigDir, err)
	}
	return rmErr
}

// clearResizeFailedMarker removes the marker from BOTH the CONFIG partition (the
// durable copy the next boot rebuilds /config from) and the runtime /config tmpfs
// overlay, so the two never diverge. Used when the conversion target changes or
// is withdrawn. Best-effort; logs failures.
func clearResizeFailedMarker() {
	if err := withConfigPartitionRW(func(mountDir string) error {
		return removeMarkerFile(filepath.Join(mountDir, resizeFailedMarkerName))
	}); err != nil {
		log.Warnf("clearResizeFailedMarker: partition: %v", err)
	}
	if err := removeResizeFailedMarkerFromOverlay(); err != nil {
		log.Warnf("clearResizeFailedMarker: overlay: %v", err)
	}
}

// convertResizerBinary is where the storage-resizer binary lives in the pillar
// container; it is built into both the pillar and storage-init images (the
// eve-storage-resizer linuxkit package is COPYd to this path).
const convertResizerBinary = "/usr/bin/storage-resizer"

// advanceSubState moves the reported conversion sub-state forward only. The
// DeviceSubState enum is ordered chronologically, so a re-entrant maybeConvert
// (the no-shrink grow path re-checks as proceed on the next update) never rolls
// the sub-state back to an earlier phase. Aborts reset it explicitly via the
// error branches, which also clear Converting.
func advanceSubState(status *types.BaseOsStatus, s types.DeviceSubState) {
	if s > status.ConvertSubState {
		status.ConvertSubState = s
	}
}

// maybeConvert runs one boot-disk conversion step for a cross-flavor update and
// reports whether the A/B install may proceed.
//
// It returns true when the boot disk already has, or now has, the EVE-k
// geometry and the caller should continue with the install. It returns false
// when the install must wait: a reboot was requested for the offline shrink, or
// the conversion cannot proceed (insufficient space, or an error). In the false
// case it has already updated and published BaseOsStatus, so the caller should
// treat status as changed and return.
func maybeConvert(ctx *baseOsMgrContext, status *types.BaseOsStatus) bool {
	bootDisk, err := bootDiskFromCurrentPartition()
	if err != nil {
		errStr := fmt.Sprintf("conversion: cannot determine boot disk: %s", err)
		log.Error(errStr)
		status.Converting = false
		status.ConvertSubState = types.DEVICE_SUBSTATE_UNSPECIFIED
		status.SetErrorNow(errStr)
		publishBaseOsStatus(ctx, status)
		return false
	}

	// The backup and the shrink flag file must be written to the CONFIG partition
	// itself: the runtime /config is a read-only tmpfs RAM copy that storage-init
	// remounts read-only, so a write there is lost on the reboot the shrink relies
	// on. Mount the partition read-write and point the resizer at it (the same
	// approach the monitor agent uses to update /config). The check/grow steps do
	// not write /config, but mounting unconditionally keeps the one /config-writing
	// step (backup) covered without first probing the decision.
	var res diskconvert.Result
	var runErr error
	var declineReason string
	var clearedStale bool
	mountErr := withConfigPartitionRW(func(mountDir string) error {
		// A prior offline shrink/grow that aborted under this running image left a
		// resize-failed.json marker (storage-init's resize_abort). markerVerdict
		// decides: decline (re-arming would fail identically and reboot-loop), or
		// clear a marker from a different EVE version (the running image changed and
		// may carry a fixed resizer) and proceed.
		m, ok := readResizeFailedMarker(mountDir)
		var clearStale bool
		declineReason, clearStale = markerVerdict(m, ok, runningEveRelease())
		if declineReason != "" {
			return nil
		}
		if clearStale {
			// Remove from the partition now (we are mounted); the /config overlay is
			// cleared after this mount closes so the two stay consistent.
			if err := removeMarkerFile(filepath.Join(mountDir, resizeFailedMarkerName)); err != nil {
				log.Warnf("maybeConvert: clear stale %s (partition): %v", resizeFailedMarkerName, err)
			} else {
				clearedStale = true
				log.Noticef("maybeConvert: cleared stale %s (marker %s != running)", resizeFailedMarkerName, m.EveRelease)
			}
		}
		c := &diskconvert.Converter{
			Runner: diskconvert.BinaryRunner{
				Binary:    convertResizerBinary,
				BackupDir: filepath.Join(mountDir, "backup-persist"),
				FlagFile:  filepath.Join(mountDir, "repartition-inprogress"),
			},
			PersistLabel: "P3",
		}
		res, runErr = c.Run(bootDisk)
		return nil
	})
	if mountErr != nil {
		errStr := fmt.Sprintf("conversion: cannot access CONFIG partition: %s", mountErr)
		log.Error(errStr)
		status.Converting = false
		status.ConvertSubState = types.DEVICE_SUBSTATE_UNSPECIFIED
		status.SetErrorNow(errStr)
		publishBaseOsStatus(ctx, status)
		return false
	}
	if clearedStale {
		// Keep the /config overlay consistent with the partition we just cleared.
		if err := removeResizeFailedMarkerFromOverlay(); err != nil {
			log.Warnf("maybeConvert: clear stale %s (overlay): %v", resizeFailedMarkerName, err)
		}
	}
	// A prior failure under this EVE version: report the decline, do not re-arm.
	if declineReason != "" {
		log.Error(declineReason)
		status.Converting = false
		status.ConvertSubState = types.DEVICE_SUBSTATE_UNSPECIFIED
		status.SetErrorNow(declineReason)
		publishBaseOsStatus(ctx, status)
		return false
	}
	log.Functionf("maybeConvert(%s): decision=%s outcome=%s reason=%q target=%q err=%v",
		bootDisk, res.Decision, res.Outcome, res.Reason, res.ShrinkTarget, runErr)

	switch res.Outcome {
	case diskconvert.OutcomeProceed:
		// Geometry is (now) EVE-k. A cross-flavor conversion is still in
		// progress: keep Converting set so the A/B install and the reboot into
		// the target image are reported as CONVERTING (doBaseOsActivate advances
		// the sub-state to INSTALLING / REBOOTING_TO_TARGET). The boot into the
		// new flavor rebuilds BaseOsStatus without Converting, which clears it.
		// Publish only on the first transition (or to clear a stale error) to
		// avoid flapping on repeated status updates of an already-EVE-k disk.
		if !status.Converting || status.HasError() {
			status.Converting = true
			status.ClearError()
			publishBaseOsStatus(ctx, status)
		}
		return true

	case diskconvert.OutcomeRebootForRepartition:
		// The /config repartition flag is written (plus the identity backup on the
		// shrink path). Advance the sub-state so nodeagent (subscribed to
		// BaseOsStatus) performs a graceful reboot into the offline resize
		// (shrink+grow, or grow-only); the conversion re-evaluates on the next boot.
		status.Converting = true
		status.ConvertSubState = types.DEVICE_SUBSTATE_CONVERT_REBOOTING_TO_RESIZE
		status.ClearError()
		publishBaseOsStatus(ctx, status)
		return false

	case diskconvert.OutcomeInsufficient:
		errStr := fmt.Sprintf("conversion not possible: %s", res.Reason)
		log.Error(errStr)
		status.Converting = false
		status.ConvertSubState = types.DEVICE_SUBSTATE_UNSPECIFIED
		status.SetErrorNow(errStr)
		publishBaseOsStatus(ctx, status)
		return false

	default:
		errStr := fmt.Sprintf("conversion failed: %v", runErr)
		log.Error(errStr)
		status.Converting = false
		status.ConvertSubState = types.DEVICE_SUBSTATE_UNSPECIFIED
		status.SetErrorNow(errStr)
		publishBaseOsStatus(ctx, status)
		return false
	}
}

// withConfigPartitionRW mounts the CONFIG partition read-write at a temp dir
// under /run, calls fn with that dir, then unmounts. The conversion backup and
// the shrink flag file have to be written here, on the real partition, because
// the runtime /config is a read-only tmpfs RAM copy whose writes do not survive
// the reboot into the offline shrink. Mirrors cmd/monitor/monitor.go, which
// writes the server file the same way. Returns the mount error (fn not run), or
// fn's error, or the unmount error; the caller here lets fn always succeed and
// captures the resizer result via closure variables.
func withConfigPartitionRW(fn func(mountDir string) error) error {
	out, err := base.Exec(log, "/sbin/findfs", "PARTLABEL=CONFIG").Output()
	if err != nil {
		return fmt.Errorf("findfs PARTLABEL=CONFIG: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	devicePath := strings.TrimSpace(string(out))
	if devicePath == "" {
		return fmt.Errorf("no CONFIG partition found")
	}
	mountDir, err := os.MkdirTemp("/run", "convert-config-")
	if err != nil {
		return fmt.Errorf("create temp mount dir: %w", err)
	}
	if err := syscall.Mount(devicePath, mountDir, "vfat", 0, "iocharset=iso8859-1"); err != nil {
		_ = os.RemoveAll(mountDir) // never mounted, safe to remove
		return fmt.Errorf("mount CONFIG partition %s: %w", devicePath, err)
	}
	fnErr := fn(mountDir)
	// Only remove the mountpoint once it is actually unmounted; RemoveAll on a
	// still-mounted dir would delete files on the CONFIG partition.
	if umountErr := syscall.Unmount(mountDir, 0); umountErr != nil {
		if fnErr != nil {
			return fnErr
		}
		return fmt.Errorf("unmount CONFIG partition %s: %w", mountDir, umountErr)
	}
	_ = os.RemoveAll(mountDir)
	return fnErr
}

// bootDiskFromCurrentPartition returns the whole-disk device (e.g. /dev/sda)
// holding the current root partition.
func bootDiskFromCurrentPartition() (string, error) {
	partDev := zboot.GetPartitionDevname(zboot.GetCurrentPartition())
	if partDev == "" {
		return "", fmt.Errorf("empty devname for current partition")
	}
	return parentDisk(partDev)
}

// parentDisk maps a partition device (e.g. /dev/sda2, /dev/mmcblk0p3) to its
// whole-disk device (e.g. /dev/sda, /dev/mmcblk0) using lsblk's PKNAME, which
// is robust across sd*/mmcblk*/nvme*/vd* naming conventions.
func parentDisk(partDev string) (string, error) {
	out, err := base.Exec(log, "lsblk", "-ndo", "PKNAME", partDev).Output()
	if err != nil {
		return "", fmt.Errorf("lsblk PKNAME %s: %w", partDev, err)
	}
	pk := strings.TrimSpace(string(out))
	if pk == "" {
		return "", fmt.Errorf("no parent disk for %s", partDev)
	}
	return "/dev/" + pk, nil
}
