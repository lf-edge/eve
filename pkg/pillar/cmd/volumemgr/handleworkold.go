// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

// Interface to worker to run the create and destroy in separate goroutines

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/worker"
	log "github.com/sirupsen/logrus"
)

// InitHandleWorkOld returns an object with a MsgChan to be used in the main select loop
// When something is received on that channel the select loop should call HandleWorkResult
func InitHandleWorkOld(ctx *volumemgrContext) *worker.Worker {
	// A small channel depth; work will be processed as FIFO
	// XXX a worker pool might make sense to avoid smaller jobs blocked
	// behind larger jobs
	worker := worker.NewWorker(volumeWorkerOld, ctx, 5)
	return worker
}

// HandleWorkResultOld processes what comes out of the select loop
func HandleWorkResultOld(ctx *volumemgrContext, res worker.WorkResult) {
	d := res.Description.(volumeWorkDescriptionOld)
	vres := volumeWorkResult{
		WorkResult:    res,
		FileLocation:  d.FileLocation,
		VolumeCreated: d.VolumeCreated,
	}
	addVolumeWorkResult(ctx, res.Key, vres)
	updateStatus(ctx, d.status.ObjType, d.status.BlobSha256,
		d.status.VolumeID)
}

// The work we feed into the go routine. Only one of create and destroy is set
type volumeWorkDescriptionOld struct {
	create  bool
	destroy bool
	status  types.OldVolumeStatus
	// Used for results
	FileLocation  string
	VolumeCreated bool
}

// MaybeAddWorkCreateOld checks if the Key is in the map of pending work
// and if not kicks of a worker and adds it
// XXX defer if busy?
func MaybeAddWorkCreateOld(ctx *volumemgrContext, status *types.OldVolumeStatus) {
	log.Infof("MaybeAddWorkCreateOld(%s)", status.Key())
	if lookupPendingCreate(ctx, status.Key()) {
		log.Infof("MaybeAddWorkCreateOld(%s) found", status.Key())
		return
	}
	d := volumeWorkDescriptionOld{
		create: true,
		status: *status,
	}
	w := worker.Work{Key: status.Key(), Description: d}
	// XXX could check a return and not add...
	ctx.workerOld.Submit(w)
	// XXX success - add
	addPendingCreate(ctx, status.Key())
	log.Infof("MaybeAddWorkCreateOld(%s) done", status.Key())
}

// DeleteWorkCreateOld is called by user when work is done
func DeleteWorkCreateOld(ctx *volumemgrContext, status *types.OldVolumeStatus) {
	log.Infof("DeleteWorkCreateOld(%s)", status.Key())
	if !lookupPendingCreate(ctx, status.Key()) {
		log.Infof("DeleteWorkCreateOld(%s) NOT found", status.Key())
		return
	}
	deletePendingCreate(ctx, status.Key())
	log.Infof("DeleteWorkCreate(%s) done", status.Key())
}

// MaybeAddWorkDestroyOld checks if the Key is in the map of pending work
// and if not kicks of a worker and adds it
// XXX defer if busy?
func MaybeAddWorkDestroyOld(ctx *volumemgrContext, status *types.OldVolumeStatus) {
	log.Infof("MaybeAddWorkDestroyOld(%s)", status.Key())
	if lookupPendingDestroy(ctx, status.Key()) {
		log.Infof("MaybeAddWorkDestroyOld(%s) found", status.Key())
		return
	}
	d := volumeWorkDescriptionOld{
		destroy: true,
		status:  *status,
	}
	w := worker.Work{Key: status.Key(), Description: d}
	// XXX could check a return and not add...
	ctx.workerOld.Submit(w)
	// XXX success - add
	addPendingDestroy(ctx, status.Key())
	log.Infof("MaybeAddWorkDestroyOld(%s) done", status.Key())
}

// DeleteWorkDestroyOld is called by user when work is done
func DeleteWorkDestroyOld(ctx *volumemgrContext, status *types.OldVolumeStatus) {
	log.Infof("DeleteWorkDestroyOld(%s)", status.Key())
	if !lookupPendingDestroy(ctx, status.Key()) {
		log.Infof("DeleteWorkDestroyOld(%s) NOT found", status.Key())
		return
	}
	deletePendingDestroy(ctx, status.Key())
	log.Infof("DeleteWorkDestroyOld(%s) done", status.Key())
}

func volumeWorkerOld(ctxPtr interface{}, w worker.Work) worker.WorkResult {
	ctx := ctxPtr.(*volumemgrContext)
	d := w.Description.(volumeWorkDescriptionOld)
	var volumeCreated bool
	var fileLocation string
	var err error
	if d.create {
		volumeCreated, fileLocation, err = createOldVolume(ctx, d.status)
	} else if d.destroy {
		volumeCreated, fileLocation, err = destroyOldVolume(ctx, d.status)
	}
	d.VolumeCreated = volumeCreated
	d.FileLocation = fileLocation
	result := worker.WorkResult{
		Key:         w.Key,
		Description: d,
	}
	if err != nil {
		result.Error = err
		result.ErrorTime = time.Now()
	}
	return result
}
