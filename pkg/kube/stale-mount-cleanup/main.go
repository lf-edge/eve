// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// stale-mount-cleanup detects and clears stale Longhorn CSI block volume
// staging mounts. It runs as a daemon inside the kube container, which shares
// the kubelet mount namespace and can see /var/lib/kubelet/...
//
// A stale staging mount occurs when a Longhorn iSCSI session is replaced
// (engine restart, auto-salvage) without NodeUnstageVolume being called. The
// old bind mount references a deleted device inode while the live
// /dev/longhorn/<pv> device has a new minor number. Longhorn's restageRequired
// check only calls IsMountPoint (which returns true for stale bind mounts), so
// kubelet never retriggers NodeStageVolume and every NodePublishVolume attempt
// fails with a misleading ENOENT against the publish path.
//
// Detection signals:
//
//	nlink==0     : device inode deleted (shows as //deleted in findmnt)
//	Rdev mismatch: iSCSI session replaced; live device has a different minor
//
// A stale condition must persist for staleThreshold before the mount is
// cleared. This avoids a TOCTOU race where NodeStageVolume completes a fresh
// bind mount between detection and unmount: if Longhorn fixes the condition
// itself, it will clear within seconds and the daemon will log the
// self-resolution without unmounting.
package main

import (
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	logPrefix      = "stale-mount-cleanup"
	csiStagingBase = "/var/lib/kubelet/plugins/kubernetes.io/csi/volumeDevices/staging"
	scanInterval   = 15 * time.Second
	staleThreshold = 2 * scanInterval
	logfileDir     = "/persist/kubelog/"
	logfile        = logfileDir + logPrefix + ".log"
	logMaxSize     = 10 // MB
	logMaxBackups  = 3
	logMaxAge      = 365 // days
)

func main() {
	if _, err := os.Stat(logfileDir); os.IsNotExist(err) {
		if err := os.MkdirAll(logfileDir, 0755); err != nil {
			return
		}
	}
	logFile := &lumberjack.Logger{
		Filename:   logfile,
		MaxSize:    logMaxSize,
		MaxBackups: logMaxBackups,
		MaxAge:     logMaxAge,
		Compress:   true,
		LocalTime:  true,
	}
	log.SetOutput(logFile)
	defer logFile.Close()

	log.Printf(logPrefix+": starting")
	firstSeenStale := make(map[string]time.Time)
	for {
		cleanStaleStagingMounts(firstSeenStale)
		time.Sleep(scanInterval)
	}
}

func cleanStaleStagingMounts(firstSeenStale map[string]time.Time) {
	entries, err := os.ReadDir(csiStagingBase)
	if err != nil {
		// Base dir absent — kubelet not yet started or no block volumes ever staged.
		return
	}

	seen := make(map[string]bool)

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pvName := e.Name()
		stagingFile := filepath.Join(csiStagingBase, pvName, pvName)

		stagedInfo, err := os.Stat(stagingFile)
		if err != nil {
			continue
		}
		stagedSys := stagedInfo.Sys().(*syscall.Stat_t)

		longhornDev := filepath.Join("/dev/longhorn", pvName)

		// Signal 1: nlink==0 — the device inode was deleted.
		// Gate on Longhorn: only act if /dev/longhorn/<pv> exists, confirming
		// this is a Longhorn-provisioned volume.
		stale := stagedSys.Nlink == 0
		if stale {
			if _, err := os.Stat(longhornDev); err != nil {
				stale = false
			}
		}

		if !stale {
			// Signal 2: Rdev mismatch with the live Longhorn device — the iSCSI
			// session was replaced (new device minor) without NodeUnstageVolume.
			if liveInfo, err := os.Stat(longhornDev); err == nil {
				liveSys := liveInfo.Sys().(*syscall.Stat_t)
				if stagedSys.Rdev != liveSys.Rdev {
					stale = true
					log.Printf(logPrefix+": PV %s staged rdev %d != live rdev %d",
						pvName, stagedSys.Rdev, liveSys.Rdev)
				}
			}
		}

		if !stale {
			if first, ok := firstSeenStale[pvName]; ok {
				// Condition cleared before threshold — Longhorn resolved it.
				log.Printf(logPrefix+": PV %s stale condition self-resolved after %s, skipping unmount",
					pvName, time.Since(first).Round(time.Second))
				delete(firstSeenStale, pvName)
			}
			continue
		}

		seen[pvName] = true

		first, known := firstSeenStale[pvName]
		if !known {
			// Condition 1: first time we see this PV as stale.
			firstSeenStale[pvName] = time.Now()
			log.Printf(logPrefix+": PV %s first observed stale (nlink=%d), waiting %s before unmount",
				pvName, stagedSys.Nlink, staleThreshold)
			continue
		}

		if time.Since(first) < staleThreshold {
			continue
		}

		// Condition 3: stale for longer than threshold — unmount.
		log.Printf(logPrefix+": PV %s stale for %s (nlink=%d), unmounting",
			pvName, time.Since(first).Round(time.Second), stagedSys.Nlink)
		if err := syscall.Unmount(stagingFile, syscall.MNT_DETACH); err != nil {
			log.Printf(logPrefix+": umount failed for %s: %v", stagingFile, err)
		} else {
			log.Printf(logPrefix+": cleared stale staging for PV %s", pvName)
			delete(firstSeenStale, pvName)
		}
	}

	// Clean up tracking for PVs whose staging directories have disappeared.
	for pvName := range firstSeenStale {
		if !seen[pvName] {
			log.Printf(logPrefix+": PV %s staging directory gone, dropping stale tracking", pvName)
			delete(firstSeenStale, pvName)
		}
	}
}
