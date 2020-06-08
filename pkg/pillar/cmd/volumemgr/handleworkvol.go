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

// InitHandleWorkVol returns an object with a MsgChan to be used in the main select loop
// When something is received on that channel the select loop should call HandleWorkResultVol
func InitHandleWorkVol(ctx *volumemgrContext) *worker.Worker {
	// A small channel depth; work will be processed as FIFO
	// XXX a worker pool might make sense to avoid smaller jobs blocked
	// behind larger jobs
	worker := worker.NewWorker(volumeWorkerVol, ctx, 5)
	return worker
}

// HandleWorkResultVol processes what comes out of the select loop
func HandleWorkResultVol(ctx *volumemgrContext, res worker.WorkResult) {
	d := res.Description.(volumeWorkDescriptionVol)
	vres := volumeWorkResult{
		WorkResult:    res,
		FileLocation:  d.FileLocation,
		VolumeCreated: d.VolumeCreated,
	}
	addVolumeWorkResult(ctx, res.Key, vres)
	updateVolumeStatus(ctx, d.status.VolumeID)
}

// The work we feed into the go routine. Only one of create and destroy is set
type volumeWorkDescriptionVol struct {
	create  bool
	destroy bool
	status  types.VolumeStatus
	// Used for results
	FileLocation  string
	VolumeCreated bool
}

// MaybeAddWorkCreateVol checks if the Key is in the map of pending work
// and if not kicks of a worker and adds it
// XXX defer if busy?
func MaybeAddWorkCreateVol(ctx *volumemgrContext, status *types.VolumeStatus) {
	log.Infof("MaybeAddWorkCreateVol(%s)", status.Key())
	if lookupPendingCreate(ctx, status.Key()) {
		log.Infof("MaybeAddWorkCreateVol(%s) found", status.Key())
		return
	}
	d := volumeWorkDescriptionVol{
		create: true,
		status: *status,
	}
	w := worker.Work{Key: status.Key(), Description: d}
	// XXX could check a return and not add...
	ctx.workerVol.Submit(w)
	// XXX success - add
	addPendingCreate(ctx, status.Key())
	log.Infof("MaybeAddWorkCreateVol(%s) done", status.Key())
}

// DeleteWorkCreateVol is called by user when work is done
func DeleteWorkCreateVol(ctx *volumemgrContext, status *types.VolumeStatus) {
	log.Infof("DeleteWorkCreateVol(%s)", status.Key())
	if !lookupPendingCreate(ctx, status.Key()) {
		log.Infof("DeleteWorkCreateVol(%s) NOT found", status.Key())
		return
	}
	deletePendingCreate(ctx, status.Key())
	log.Infof("DeleteWorkCreateVol(%s) done", status.Key())
}

// MaybeAddWorkDestroyVol checks if the Key is in the map of pending work
// and if not kicks of a worker and adds it
// XXX defer if busy?
func MaybeAddWorkDestroyVol(ctx *volumemgrContext, status *types.VolumeStatus) {
	log.Infof("MaybeAddWorkDestroyVol(%s)", status.Key())
	if lookupPendingDestroy(ctx, status.Key()) {
		log.Infof("MaybeAddWorkDestroyVol(%s) found", status.Key())
		return
	}
	d := volumeWorkDescriptionVol{
		destroy: true,
		status:  *status,
	}
	w := worker.Work{Key: status.Key(), Description: d}
	// XXX could check a return and not add...
	ctx.workerVol.Submit(w)
	// XXX success - add
	addPendingDestroy(ctx, status.Key())
	log.Infof("MaybeAddWorkDestroyVol(%s) done", status.Key())
}

// DeleteWorkDestroyVol is called by user when work is done
func DeleteWorkDestroyVol(ctx *volumemgrContext, status *types.VolumeStatus) {
	log.Infof("DeleteWorkDestroyVol(%s)", status.Key())
	if !lookupPendingDestroy(ctx, status.Key()) {
		log.Infof("DeleteWorkDestroyVol(%s) NOT found", status.Key())
		return
	}
	deletePendingDestroy(ctx, status.Key())
	log.Infof("DeleteWorkDestroyVol(%s) done", status.Key())
}

func volumeWorkerVol(ctxPtr interface{}, w worker.Work) worker.WorkResult {
	ctx := ctxPtr.(*volumemgrContext)
	d := w.Description.(volumeWorkDescriptionVol)
	var volumeCreated bool
	var fileLocation string
	var err error
	if d.create {
		volumeCreated, fileLocation, err = createVolume(ctx, d.status)
	} else if d.destroy {
		volumeCreated, fileLocation, err = destroyVolume(ctx, d.status)
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
