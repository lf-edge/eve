// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

// Interface to worker to run the create and destroy in separate goroutines

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/worker"
)

// InitHandleWork returns an object with a MsgChan to be used in the main select loop
// When something is received on that channel the select loop should call HandleWorkResult
func InitHandleWork(ctx *volumemgrContext) *worker.Worker {
	// A small channel depth; work will be processed as FIFO
	// XXX a worker pool might make sense to avoid smaller jobs blocked
	// behind larger jobs
	worker := worker.NewWorker(log, volumemgrWorker, ctx, 5)
	return worker
}

// HandleWorkResult processes what comes out of the select loop
func HandleWorkResult(ctx *volumemgrContext, res worker.WorkResult) {
	d := res.Description
	switch d.(type) {
	case volumeWorkDescription:
		processVolumeWorkResult(ctx, res)
	case casIngestWorkDescription:
		processcasIngestWorkResult(ctx, res)
	}
}

// processVolumeWorkResult handle the work result that was a volume action
func processVolumeWorkResult(ctx *volumemgrContext, res worker.WorkResult) {
	d := res.Description.(volumeWorkDescription)
	vres := volumeWorkResult{
		WorkResult:    res,
		FileLocation:  d.FileLocation,
		VolumeCreated: d.VolumeCreated,
	}
	addVolumeWorkResult(ctx, res.Key, vres)
	updateVolumeStatus(ctx, d.status.VolumeID)
}

// processcasIngestWorkResult handle the work result that was a cas ingestion
func processcasIngestWorkResult(ctx *volumemgrContext, res worker.WorkResult) {
	d := res.Description.(casIngestWorkDescription)
	wres := casIngestWorkResult{
		WorkResult: res,
		loaded:     d.loaded,
	}
	addCasIngestWorkResult(ctx, res.Key, wres)
	// this might have changed, so we want to be careful about passing it; always look it up
	updateContentTreeByID(ctx, d.status.Key())
}

// Map of pending work for create and destroy, respectively
var pendingCreateMap = make(map[string]bool)
var pendingDestroyMap = make(map[string]bool)
var pendingLoadMap = make(map[string]bool)

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

func lookupPendingLoad(ctx *volumemgrContext, key string) bool {
	res, ok := pendingLoadMap[key]
	return ok && res
}

func addPendingLoad(ctx *volumemgrContext, key string) {
	pendingLoadMap[key] = true
}

func deletePendingLoad(ctx *volumemgrContext, key string) {
	delete(pendingLoadMap, key)
}

// volumeWorkDescription volume creation/deletion work we feed into the worker go routine.
// Only one of create and destroy is set
type volumeWorkDescription struct {
	create  bool
	destroy bool
	status  types.VolumeStatus
	// Used for results
	FileLocation  string
	VolumeCreated bool
}

// casIngestWorkDescription cas ingest work we feed into the worker go routine
type casIngestWorkDescription struct {
	status types.ContentTreeStatus
	// used for results
	loaded []string
}

// What we track for the result
type volumeWorkResult struct {
	worker.WorkResult // Error etc
	// Used to update VolumeStatus
	FileLocation  string
	VolumeCreated bool
}

// casIngestWorkResult result of ingesting
type casIngestWorkResult struct {
	worker.WorkResult // Error etc
	loaded            []string
}

// Map with the result
// Caller needs to do a delete after the lookup
var volumeWorkResultMap = make(map[string]volumeWorkResult)
var casIngestWorkResultMap = make(map[string]casIngestWorkResult)

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

func lookupCasIngestWorkResult(ctx *volumemgrContext, key string) *casIngestWorkResult {
	if res, ok := casIngestWorkResultMap[key]; ok {
		return &res
	}
	return nil
}

func addCasIngestWorkResult(ctx *volumemgrContext, key string, res casIngestWorkResult) {
	casIngestWorkResultMap[key] = res
}

func deleteCasIngestWorkResult(ctx *volumemgrContext, key string) {
	delete(casIngestWorkResultMap, key)
}

// MaybeAddWorkCreate checks if the Key is in the map of pending work
// and if not kicks of a worker and adds it
// XXX defer if busy?
func MaybeAddWorkCreate(ctx *volumemgrContext, status *types.VolumeStatus) {
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

// MaybeAddWorkLoad checks if the Key is in the map of pending work
// and if not kicks of a worker and adds it
// XXX defer if busy?
func MaybeAddWorkLoad(ctx *volumemgrContext, status *types.ContentTreeStatus) {
	key := status.Key()
	log.Infof("MaybeAddWorkLoad(%s)", key)
	if lookupPendingLoad(ctx, key) {
		log.Infof("MaybeAddWorkLoad(%s) found", key)
		return
	}
	d := casIngestWorkDescription{
		status: *status,
	}
	w := worker.Work{Key: key, Description: d}
	// XXX could check a return and not add...
	ctx.worker.Submit(w)
	// XXX success - add
	addPendingLoad(ctx, key)
	log.Infof("MaybeAddWorkLoad(%s) done", key)
}

// DeleteWorkCreate is called by user when work is done
func DeleteWorkCreate(ctx *volumemgrContext, status *types.VolumeStatus) {
	log.Infof("DeleteWorkCreate(%s)", status.Key())
	if !lookupPendingCreate(ctx, status.Key()) {
		log.Infof("DeleteWorkCreate(%s) NOT found", status.Key())
		return
	}
	deletePendingCreate(ctx, status.Key())
	log.Infof("DeleteWorkCreate(%s) done", status.Key())
}

// DeleteWorkLoad is called by user when work is done
func DeleteWorkLoad(ctx *volumemgrContext, key string) {
	log.Infof("DeleteWorkLoad(%s)", key)
	if !lookupPendingLoad(ctx, key) {
		log.Infof("DeleteWorkLoad(%s) NOT found", key)
		return
	}
	deletePendingLoad(ctx, key)
	log.Infof("DeleteWorkLoad(%s) done", key)
}

// MaybeAddWorkDestroy checks if the Key is in the map of pending work
// and if not kicks of a worker and adds it
// XXX defer if busy?
func MaybeAddWorkDestroy(ctx *volumemgrContext, status *types.VolumeStatus) {
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
func DeleteWorkDestroy(ctx *volumemgrContext, status *types.VolumeStatus) {
	log.Infof("DeleteWorkDestroy(%s)", status.Key())
	if !lookupPendingDestroy(ctx, status.Key()) {
		log.Infof("DeleteWorkDestroy(%s) NOT found", status.Key())
		return
	}
	deletePendingDestroy(ctx, status.Key())
	log.Infof("DeleteWorkDestroy(%s) done", status.Key())
}

// volumemgrWorker worker switchboard for different types of workers in volumemgr
func volumemgrWorker(ctxPtr interface{}, w worker.Work) worker.WorkResult {
	d := w.Description
	switch t := d.(type) {
	case volumeWorkDescription:
		return volumeWorker(ctxPtr, w)
	case casIngestWorkDescription:
		return casIngestWorker(ctxPtr, w)
	default:
		return worker.WorkResult{
			Key:         w.Key,
			Description: d,
			Error:       fmt.Errorf("unknown work description type %v", t),
			ErrorTime:   time.Now(),
		}
	}
}

// volumeWorker implementation of work.WorkFunction that create or deletes a volume
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

// casIngestWorker implementation of work.WorkFunction that loads blobs and an image into the CAS store
func casIngestWorker(ctxPtr interface{}, w worker.Work) worker.WorkResult {
	ctx := ctxPtr.(*volumemgrContext)
	d := w.Description.(casIngestWorkDescription)
	status := d.status

	log.Infof("casIngestWorker has blobs: %v", status.Blobs)
	blobStatuses := lookupBlobStatuses(ctx, status.Blobs...)

	// find the blobs we need to load and indicate that they are being loaded
	// The order here is important. As a safety check, IngestBlobsAndCreateImage
	// will not load any blobs that are of state LOADED or LOADING. If we set it to LOADING,
	// we will prevent it from being loaded. But we need to indicate to the rest of the world
	// that this blob is being loaded. So we do the following:
	//
	// 1. duplicate the BlobStatus to pass to IngestBlobsAndCreateImage
	// 2. update the original BlobStatus state and publish
	// 3. When we get the response, update the originals and publish

	// also keep track so we do not try to load duplicates
	found := map[string]bool{}
	loadBlobs := []types.BlobStatus{}
	root := blobStatuses[0]
	for _, blob := range blobStatuses {
		// be careful not to load the same Sha256 twice
		if _, ok := found[blob.Sha256]; ok {
			continue
		}
		found[blob.Sha256] = true
		if blob.State < types.LOADING {
			// Pay close attention: we copy the blob *before* changing it to loading.
			// We want everything else to know that it is LOADING, but not the routine to
			// ingest that we are about to call.
			loadBlobs = append(loadBlobs, *blob)
			blob.State = types.LOADING
			publishBlobStatus(ctx, blob)
		}
	}

	// load the blobs
	loadedBlobs, err := ctx.casClient.IngestBlobsAndCreateImage(status.ReferenceID(), *root, loadBlobs...)
	// loadedBlobs are BlobStatus for the ones we loaded; publicize their new states.
	for _, blob := range loadedBlobs {
		blob.State = types.LOADED
		publishBlobStatus(ctx, &blob)
		d.loaded = append(d.loaded, blob.Sha256)
	}
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
