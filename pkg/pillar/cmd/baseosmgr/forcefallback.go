// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"strconv"

	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

const (
	// checkpointDirname - location of forcefallbackfile
	// XXX move to locationconst.go?
	checkpointDirname     = types.PersistDir + "/checkpoint"
	forcefallbackFilename = checkpointDirname + "/forceFallbackCounter"
)

// handle zedagent status events to look if the ForceFallbackCounter changes

func handleZedAgentStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleZedAgentStatusImpl(ctxArg, key, statusArg)
}

func handleZedAgentStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleZedAgentStatusImpl(ctxArg, key, statusArg)
}

func handleZedAgentStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctxPtr := ctxArg.(*baseOsMgrContext)
	status := statusArg.(types.ZedAgentStatus)
	handleForceFallback(ctxPtr, status)
	log.Functionf("handleZedAgentStatusImpl(%s) done", key)
}

func handleZedAgentStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	// do nothing
	log.Functionf("handleZedAgentStatusDelete(%s) done", key)
}

// handleForceFallback checks if we have a file with a ForceFallbackCounter
// and if so, if the counter has changed.
// If it has, then if the current partition is active, the other partition is
// unused and the other partition has some non-empty EVE version string,
// then it will mark the other partition as Updating.
// This update to ZbootStatus will make nodeagent trigger a reboot.
func handleForceFallback(ctxPtr *baseOsMgrContext, status types.ZedAgentStatus) {

	counter, found := readForceFallbackCounter()
	if !found {
		// Just write the current value
		log.Functionf("Saving initial ForceFallbackCounter %d",
			status.ForceFallbackCounter)
		writeForceFallbackCounter(status.ForceFallbackCounter)
		return
	}
	if counter == status.ForceFallbackCounter {
		log.Functionf("No change to ForceFallbackCounter %d", counter)
		return
	}
	log.Noticef("Handle ForceFallbackCounter update from %d to %d",
		counter, status.ForceFallbackCounter)

	curPartName := zboot.GetCurrentPartition()
	partStatus := getZbootStatus(ctxPtr, curPartName)
	if partStatus == nil {
		log.Warnf("No current partition status for %s; ignoring ForceFallback",
			curPartName)
		return
	}
	if partStatus.PartitionState != "active" {
		log.Warnf("Current partition state %s not active; ignoring ForceFallback",
			partStatus.PartitionState)
		return
	}
	shortVerCurPart := partStatus.ShortVersion
	otherPartName := zboot.GetOtherPartition()
	partStatus = getZbootStatus(ctxPtr, otherPartName)
	if partStatus == nil {
		log.Warnf("No other partition status for %s; ignoring ForceFallback",
			otherPartName)
		return
	}
	shortVerOtherPart := partStatus.ShortVersion
	if shortVerOtherPart == "" {
		log.Warnf("Other partition has no version; ignoring ForceFallback")
		return
	}
	if partStatus.PartitionState != "unused" {
		log.Warnf("Other partition state %s not unused; ignoring ForceFallback",
			partStatus.PartitionState)
		return
	}
	log.Noticef("ForceFallback from %s to %s",
		shortVerCurPart, shortVerOtherPart)

	zboot.SetOtherPartitionStateUpdating(log)
	updateAndPublishZbootStatus(ctxPtr,
		partStatus.PartitionLabel, false)
	baseOsStatus := lookupBaseOsStatusByPartLabel(ctxPtr, partStatus.PartitionLabel)
	if baseOsStatus != nil {
		baseOsSetPartitionInfoInStatus(ctxPtr, baseOsStatus,
			partStatus.PartitionLabel)
		publishBaseOsStatus(ctxPtr, baseOsStatus)
	}
	writeForceFallbackCounter(status.ForceFallbackCounter)
}

// readForceFallbackCounter reads the persistent file
// If the file doesn't exist or doesn't contain an integer it returns false
func readForceFallbackCounter() (int, bool) {
	c, parsed := fileutils.ReadSavedCounter(log, forcefallbackFilename)
	return int(c), parsed
}

// writeForceFallbackCounter writes the persistent file
// Errors are logged but otherwise ignored
func writeForceFallbackCounter(fallbackCounter int) {
	b := []byte(strconv.Itoa(fallbackCounter))
	err := fileutils.WriteRename(forcefallbackFilename, b)
	if err != nil {
		log.Errorf("writeForceFallbackCounter write: %s", err)
	}
}
