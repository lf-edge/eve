// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

// Rename volumes in /persist from old format (appinst+sha) to new format (volumeID) and move to /persist/vault for both VM and OCI volumes.

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/containerd"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"

	uuid "github.com/satori/go.uuid"
)

func convertPersistVolumes(ctxPtr *ucContext) error {
	log.Functionf("convertPersistVolumes()")
	checkpointFile := ctxPtr.configCheckpointFile()
	if !fileutils.FileExists(log, checkpointFile) {
		// This error always happens on first boot of a device.
		// In that case there is nothing to convert.
		errStr := fmt.Sprintf("No checkpoint file in %s", checkpointFile)
		log.Errorf(errStr)
		return errors.New(errStr)
	}
	latch, err := inhaleLatch(ctxPtr.ps) // XXX override dir in pubsub?
	if err != nil {
		log.Errorf("inhaleLatch failed: %s", err)
		// Proceed since not all volumes depend on the latch
	}
	pr, err := parseConfig(checkpointFile)
	if err != nil {
		return err
	}
	pr.propagateInfo()
	pr.applyLatch(latch)

	oldVMVolumesDir := ctxPtr.imgDir()
	oldOCIVolumesDir := ctxPtr.preparedDir()
	newVolumesDir := ctxPtr.volumesDir()
	newExists := fileutils.DirExists(log, newVolumesDir)
	oldVMExists := fileutils.DirExists(log, oldVMVolumesDir)
	oldOCIExists := fileutils.DirExists(log, oldOCIVolumesDir)
	if !newExists {
		log.Functionf("Creating new %s", newVolumesDir)
		if err := os.MkdirAll(newVolumesDir, 0700); err != nil {
			return err
		}
	}
	log.Functionf("new %t oldVM %t oldOCI %t", newExists, oldVMExists,
		oldOCIExists)
	var old1, old2 []oldVolume
	if oldVMExists {
		old1 = scanDir(oldVMVolumesDir, false)
	}
	if oldOCIExists {
		old2 = scanDir(oldOCIVolumesDir, true)
	}
	old := append(old1, old2...)
	log.Tracef("Found %d oldVolumes: %+v", len(old), old)
	for i, ov := range old {
		dlvr := pr.lookupDriveAndVolumeRef(ov.appInstID, ov.sha256)
		if dlvr == nil {
			log.Errorf("old %d dlvr not found for uuid %s sha %s",
				i, ov.appInstID, ov.sha256)
			continue
		}
		log.Functionf("DLVR %d used by appInst %s, path %s",
			i, ov.appInstID, ov.pathname)
		// Note that we get the generationCounter from the volumeRef
		// which is most likely zero even if the old volume had a
		// non-zero purgeCounter
		newPath := fmt.Sprintf("%s/%s#%d.%s", newVolumesDir,
			dlvr.volumeID, dlvr.generationCounter, ov.format)
		log.Functionf("DLVR %d volumeID %s generationCounter %d, purgeCounter %d, format %s, new path %s",
			i, dlvr.volumeID, dlvr.generationCounter,
			dlvr.purgeCounter, ov.format, newPath)
		if dlvr.sha256 != ov.sha256 {
			log.Errorf("DLVR %d sha mismatch %s vs %s",
				i, dlvr.sha256, ov.sha256)
			continue
		}
		maybeMove(ov.pathname, ov.modTime, newPath, ctxPtr.noFlag)
	}
	return nil
}

// If newPath doesn't exist, then move.
// If newPath exists, then this could be due to a downgrade followed by an upgrade
// and this get called on the upgrade.
// When the device was downgraded to code which uses the old directories, then
// if would have recreated the volumes in the old directories. Our assumption
// is that such a downgrade was a mistake or failure, and that we want to use
// the file which was originally placed in the new directory.
//
// If noFlag is set we just log and no file system modifications.
func maybeMove(oldPath string, oldModTime time.Time, newPath string, noFlag bool) {
	info, err := os.Stat(newPath)
	if err == nil {
		newModTime := info.ModTime()
		if newModTime.After(oldModTime) {
			log.Functionf("New file %s newer than old %s: %s vs. %s. Not replaced",
				newPath, oldPath,
				oldModTime.Format(time.RFC3339Nano),
				newModTime.Format(time.RFC3339Nano))
			return
		}
		// This happens since the raw/qcow2 image would have been
		// modified by the app instance when booting in the downgraded state.
		log.Warnf("New file %s newer than old %s: %s vs. %s. Not replaced",
			newPath, oldPath,
			oldModTime.Format(time.RFC3339Nano),
			newModTime.Format(time.RFC3339Nano))
		return
	}
	if noFlag {
		log.Functionf("Persist layout dryrun from %s to %s",
			oldPath, newPath)
	} else {
		log.Functionf("Moving %s to %s: %t", oldPath, newPath, !noFlag)
		// Can not rename between vault directories so we
		// have to copy and delete.
		fi, err := os.Stat(oldPath)
		if err != nil {
			log.Errorf("stat failed: %s", err)
			return
		}
		if fi.IsDir() {
			if err := fileutils.CopyDir(oldPath, newPath); err != nil {
				log.Errorf("cp old to new failed: %s", err)
			} else {
				err := os.RemoveAll(oldPath)
				if err != nil {
					log.Errorf("Remove old failed: %s", err)
				}
			}
			// For containers we save the old basename in a file
			if err := containerd.SaveSnapshotID(oldPath, newPath); err != nil {
				log.Errorf("maybeMove: exception while saving snapshotID: %s", err.Error())
			}
		} else {
			// Must copy due to fscrypt
			// Use atomic rename
			copyRenameDelete(oldPath, newPath)
		}
	}
}

// From the AppInstanceConfig protbuf message.
// driveAndVolume has one entry per <app,drive> based on the old Drive API
// thus multiple per app instance if the instance has multiple drives
// We fill in volumeID and generationCounter from the volumeRef API
type driveAndVolumeRef struct {
	appInstID         uuid.UUID
	imageID           uuid.UUID // From drive in API
	imageName         string    // Only used in debug loh
	sha256            string    // If not set will be picked from latch
	purgeCounter      uint32    // Set from purge.counter for the first volume
	volumeID          uuid.UUID // From volumeRef in API
	generationCounter int64     // From volumeRef in API
}

// From the Volume protobuf message
type volumeInfo struct {
	volumeID          uuid.UUID
	contentTreeID     uuid.UUID // Not same as ImageID?
	generationCounter int64
	imageURL          string // From ContentTree
	sha256            string // From ContentTree
}

// From the ContentTree protobuf message
type contentTree struct {
	contentTreeID     uuid.UUID
	relativeURL       string
	displayName       string
	sha256            string
	generationCounter int64
}

// propagateInfo takes missing info from contentTree etc to fill in volumeInfo
func (pr *parseResult) propagateInfo() {
	for i := range pr.volumes {
		vi := &pr.volumes[i]
		ct := pr.lookupContentTree(vi.contentTreeID)
		if ct == nil {
			continue
		}
		if vi.sha256 == "" {
			log.Functionf("volume[%d] volumeID %s setting sha from ctID %s: %s",
				i, vi.volumeID, vi.contentTreeID, ct.sha256)
			vi.sha256 = ct.sha256
		}
		if vi.imageURL == "" {
			log.Functionf("volume[%d] volumeID %s setting imageURL from ctID %s: %s",
				i, vi.volumeID, vi.contentTreeID, ct.relativeURL)
			vi.imageURL = ct.relativeURL
		}
	}
}

// applyLatch takes missing info from contentTree etc to fill in volumeInfo
func (pr *parseResult) applyLatch(l latch) {
	for i := range pr.appInsts {
		davr := &pr.appInsts[i]
		aih := l.lookup(davr.appInstID, davr.imageID, davr.purgeCounter)
		if aih == nil {
			continue
		}
		if davr.sha256 == "" {
			log.Functionf("app inst[%d] appInstID %s imageID %s purge %d setting sha: %s",
				i, davr.appInstID, davr.imageID,
				davr.purgeCounter, aih.Hash)
			davr.sha256 = aih.Hash
		}
	}
}

// parseAppRwVolumeName - Returns rwImgDirname, sha256, uuidStr, purgeCounter, format
// Copied from the old one in volumemgr, but added returning of format string
func parseAppRwVolumeName(image string, isContainer bool) (string, string, string, uint32, string) {
	// VolumeSha is provided by the controller - it can be uppercase
	// or lowercase.
	var re1 *regexp.Regexp
	var re2 *regexp.Regexp
	var format string
	if isContainer {
		re1 = regexp.MustCompile(`(.+)/([0-9A-Fa-f]+)-([0-9a-fA-F\-]+)#([0-9]+)`)
		format = "container"
	} else {
		re1 = regexp.MustCompile(`(.+)/([0-9A-Fa-f]+)-([0-9a-fA-F\-]+)#([0-9]+)\.(.+)`)
	}
	if re1.MatchString(image) {
		// With purgeCounter
		parsedStrings := re1.FindStringSubmatch(image)
		count, err := strconv.ParseUint(parsedStrings[4], 10, 32)
		if err != nil {
			log.Error(err)
			count = 0
		}
		if !isContainer {
			format = parsedStrings[5]
		}
		return parsedStrings[1], parsedStrings[2], parsedStrings[3],
			uint32(count), format
	}
	// Without purgeCounter
	if isContainer {
		re2 = regexp.MustCompile(`(.+)/([0-9A-Fa-f]+)-([0-9a-fA-F\-]+)`)
	} else {
		re2 = regexp.MustCompile(`(.+)/([0-9A-Fa-f]+)-([0-9a-fA-F\-]+)\.([^\.]+)`)
	}
	if !re2.MatchString(image) {
		log.Errorf("AppRwVolumeName %s doesn't match pattern", image)
		return "", "", "", 0, format
	}
	parsedStrings := re2.FindStringSubmatch(image)
	if !isContainer {
		format = parsedStrings[4]
	}
	return parsedStrings[1], parsedStrings[2], parsedStrings[3], 0, format
}
