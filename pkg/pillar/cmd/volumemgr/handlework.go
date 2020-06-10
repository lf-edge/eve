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

// InitHandleWork returns an object with a MsgChan to be used in the main select loop
// When something is received on that channel the select loop should call HandleWorkResult
func InitHandleWork(ctx *volumemgrContext) *worker.Worker {
	// A small channel depth; work will be processed as FIFO
	// XXX a worker pool might make sense to avoid smaller jobs blocked
	// behind larger jobs
	worker := worker.NewWorker(volumeWorker, ctx, 5)
	return worker
}

// HandleWorkResult processes what comes out of the select loop
func HandleWorkResult(ctx *volumemgrContext, res worker.WorkResult) {
	d := res.Description.(volumeWorkDescription)
	vres := volumeWorkResult{
		WorkResult:    res,
		FileLocation:  d.FileLocation,
		VolumeCreated: d.VolumeCreated,
	}
	addVolumeWorkResult(ctx, res.Key, vres)
	updateStatus(ctx, d.status.ObjType, d.status.BlobSha256,
		d.status.VolumeID)
}

// Map of pending work for create and destroy, respectively
var pendingCreateMap = make(map[string]bool)
var pendingDestroyMap = make(map[string]bool)

func lookupPendingCreate(ctx *volumemgrContext, key string) bool {
	res, ok := pendingCreateMap[key]
	return ok && res
}

func addPendingCreate(ctx *volumemgrContext, key string) {
	pendingCreateMap[key] = true
}

func deletePendingCreate(ctx *volumemgrContext, key string) {
	delete(pendingCreateMap, key)
}

func lookupPendingDestroy(ctx *volumemgrContext, key string) bool {
	res, ok := pendingDestroyMap[key]
	return ok && res
}

func addPendingDestroy(ctx *volumemgrContext, key string) {
	pendingDestroyMap[key] = true
}

func deletePendingDestroy(ctx *volumemgrContext, key string) {
	delete(pendingDestroyMap, key)
}

// The work we feed into the go routine. Only one of create and destroy is set
type volumeWorkDescription struct {
	create  bool
	destroy bool
	status  types.OldVolumeStatus
	// Used for results
	FileLocation  string
	VolumeCreated bool
}

// What we track for the result
type volumeWorkResult struct {
	worker.WorkResult // Error etc
	// Used to update VolumeStatus
	FileLocation  string
	VolumeCreated bool
}

// Map with the result
// Caller needs to do a delete after the lookup
var volumeWorkResultMap = make(map[string]volumeWorkResult)

func lookupVolumeWorkResult(ctx *volumemgrContext, key string) *volumeWorkResult {
	res, ok := volumeWorkResultMap[key]
	if ok {
		return &res
	} else {
		return nil
	}
}

func addVolumeWorkResult(ctx *volumemgrContext, key string, res volumeWorkResult) {
	volumeWorkResultMap[key] = res
}

func deleteVolumeWorkResult(ctx *volumemgrContext, key string) {
	delete(volumeWorkResultMap, key)
}

// MaybeAddWorkCreate checks if the Key is in the map of pending work
// and if not kicks of a worker and adds it
// XXX defer if busy?
func MaybeAddWorkCreate(ctx *volumemgrContext, status *types.OldVolumeStatus) {
	log.Infof("MaybeAddWorkCreate(%s)", status.Key())
	if lookupPendingCreate(ctx, status.Key()) {
		log.Infof("MaybeAddWorkCreate(%s) found", status.Key())
		return
	}
	d := volumeWorkDescription{
		create: true,
		status: *status,
	}
	w := worker.Work{Key: status.Key(), Description: d}
	// XXX could check a return and not add...
	ctx.worker.Submit(w)
	// XXX success - add
	addPendingCreate(ctx, status.Key())
	log.Infof("MaybeAddWorkCreate(%s) done", status.Key())
}

// DeleteWorkCreate is called by user when work is done
func DeleteWorkCreate(ctx *volumemgrContext, status *types.OldVolumeStatus) {
	log.Infof("DeleteWorkCreate(%s)", status.Key())
	if !lookupPendingCreate(ctx, status.Key()) {
		log.Infof("DeleteWorkCreate(%s) NOT found", status.Key())
		return
	}
	deletePendingCreate(ctx, status.Key())
	log.Infof("DeleteWorkCreate(%s) done", status.Key())
}

// MaybeAddWorkDestroy checks if the Key is in the map of pending work
// and if not kicks of a worker and adds it
// XXX defer if busy?
func MaybeAddWorkDestroy(ctx *volumemgrContext, status *types.OldVolumeStatus) {
	log.Infof("MaybeAddWorkDestroy(%s)", status.Key())
	if lookupPendingDestroy(ctx, status.Key()) {
		log.Infof("MaybeAddWorkDestroy(%s) found", status.Key())
		return
	}
	d := volumeWorkDescription{
		destroy: true,
		status:  *status,
	}
	w := worker.Work{Key: status.Key(), Description: d}
	// XXX could check a return and not add...
	ctx.worker.Submit(w)
	// XXX success - add
	addPendingDestroy(ctx, status.Key())
	log.Infof("MaybeAddWorkDestroy(%s) done", status.Key())
}

// DeleteWorkDestroy is called by user when work is done
func DeleteWorkDestroy(ctx *volumemgrContext, status *types.OldVolumeStatus) {
	log.Infof("DeleteWorkDestroy(%s)", status.Key())
	if !lookupPendingDestroy(ctx, status.Key()) {
		log.Infof("DeleteWorkDestroy(%s) NOT found", status.Key())
		return
	}
	deletePendingDestroy(ctx, status.Key())
	log.Infof("DeleteWorkDestroy(%s) done", status.Key())
}

func volumeWorker(ctxPtr interface{}, w worker.Work) worker.WorkResult {
	ctx := ctxPtr.(*volumemgrContext)
	d := w.Description.(volumeWorkDescription)
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
