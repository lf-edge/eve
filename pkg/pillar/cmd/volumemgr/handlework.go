// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

// Interface to worker to run the create and destroy in separate goroutines

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/worker"
)

const (
	workCreate  = "create"
	workIngest  = "ingest"
	workPrepare = "prepare"
)

// volumeWorkDescription volume creation/deletion work we feed into the worker go routine.
// Only one of create and destroy is set
type volumeWorkDescription struct {
	create  bool
	destroy bool
	prepare bool
	status  types.VolumeStatus
	// Used for results
	FileLocation  string
	VolumeCreated bool
	CreateTime    time.Time
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
	CreateTime    time.Time
}

// What we track for the result
type volumePrepareResult struct {
	worker.WorkResult // Error etc
}

// casIngestWorkResult result of ingesting
type casIngestWorkResult struct {
	worker.WorkResult // Error etc
	loaded            []string
}

// AddWorkCreate adds a Work job to create a volume
func AddWorkCreate(ctx *volumemgrContext, status *types.VolumeStatus) {
	d := volumeWorkDescription{
		create: true,
		status: *status,
	}
	w := worker.Work{Kind: workCreate, Key: status.Key(), Description: d}
	// Don't fail on errors to make idempotent (Submit returns an error if
	// the work was already submitted)
	done, err := ctx.worker.TrySubmit(w)
	if err != nil {
		log.Errorf("TrySubmit %s failed: %s", status.Key(), err)
	} else if !done {
		log.Fatalf("Failed to submit work due to queue length for %s",
			status.Key())
	}
}

// AddWorkLoad adds a Work job to load an image and blobs into CAS
func AddWorkLoad(ctx *volumemgrContext, status *types.ContentTreeStatus) {
	d := casIngestWorkDescription{
		status: *status,
	}
	w := worker.Work{Kind: workIngest, Key: status.Key(), Description: d}
	// Don't fail on errors to make idempotent (Submit returns an error if
	// the work was already submitted)
	done, err := ctx.worker.TrySubmit(w)
	if err != nil {
		log.Errorf("TrySubmit %s failed: %s", status.Key(), err)
	} else if !done {
		log.Fatalf("Failed to submit work due to queue length for %s",
			status.Key())
	}
}

// AddWorkPrepare adds a Work job to create a volume
func AddWorkPrepare(ctx *volumemgrContext, status *types.VolumeStatus) {
	d := volumeWorkDescription{
		prepare: true,
		status:  *status,
	}
	w := worker.Work{Kind: workPrepare, Key: status.Key(), Description: d}
	// Don't fail on errors to make idempotent (Submit returns an error if
	// the work was already submitted)
	done, err := ctx.worker.TrySubmit(w)
	if err != nil {
		log.Errorf("TrySubmit %s failed: %s", status.Key(), err)
	} else if !done {
		log.Fatalf("Failed to submit work due to queue length for %s",
			status.Key())
	}
}

// DeleteWorkCreate is called by user when work is done
func DeleteWorkCreate(ctx *volumemgrContext, status *types.VolumeStatus) {
	ctx.worker.Cancel(status.Key())
}

// DeleteWorkPrepare is called by user when work is done
func DeleteWorkPrepare(ctx *volumemgrContext, status *types.VolumeStatus) {
	ctx.worker.Cancel(status.Key())
}

// DeleteWorkLoad is called by user when work is done
func DeleteWorkLoad(ctx *volumemgrContext, key string) {
	ctx.worker.Cancel(key)
}

// AddWorkDestroy adds a Work job to destroy a volume
func AddWorkDestroy(ctx *volumemgrContext, status *types.VolumeStatus) {
	d := volumeWorkDescription{
		destroy: true,
		status:  *status,
	}
	w := worker.Work{Kind: workCreate, Key: status.Key(), Description: d}
	// Don't fail on errors to make idempotent (Submit returns an error if
	// the work was already submitted)
	done, err := ctx.worker.TrySubmit(w)
	if err != nil {
		log.Errorf("TrySubmit %s failed: %s", status.Key(), err)
	} else if !done {
		log.Fatalf("Failed to submit work due to queue length for %s",
			status.Key())
	}
}

// DeleteWorkDestroy cancels a job to destroy a volume
func DeleteWorkDestroy(ctx *volumemgrContext, status *types.VolumeStatus) {
	ctx.worker.Cancel(status.Key())
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
	if volumeCreated {
		d.CreateTime = time.Now()
	}
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

	log.Functionf("casIngestWorker has blobs: %v", status.Blobs)
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
		if blob.State == types.LOADING {
			loadBlobs = append(loadBlobs, *blob)
		}
	}

	// load the blobs
	loadedBlobs, err := ctx.casClient.IngestBlobsAndCreateImage(status.ReferenceID(), *root, loadBlobs...)
	// loadedBlobs are BlobStatus for the ones we loaded
	for _, blob := range loadedBlobs {
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

// volumePrepareWorker implementation of work.WorkFunction that prepares volume creation
func volumePrepareWorker(ctxPtr interface{}, w worker.Work) worker.WorkResult {
	ctx := ctxPtr.(*volumemgrContext)
	d := w.Description.(volumeWorkDescription)
	err := prepareVolume(ctx, d.status)
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

// processVolumeWorkResult handle the work result that was a volume action
func processVolumeWorkResult(ctxPtr interface{}, res worker.WorkResult) error {
	ctx := ctxPtr.(*volumemgrContext)
	d := res.Description.(volumeWorkDescription)
	updateVolumeStatus(ctx, d.status.VolumeID)
	return nil
}

// processVolumePrepareResult handle the work result that was a volume prepare action
func processVolumePrepareResult(ctxPtr interface{}, res worker.WorkResult) error {
	ctx := ctxPtr.(*volumemgrContext)
	d := res.Description.(volumeWorkDescription)
	updateVolumeStatus(ctx, d.status.VolumeID)
	return nil
}

// processCasIngestWorkResult handle the work result that was a cas ingestion
func processCasIngestWorkResult(ctxPtr interface{}, res worker.WorkResult) error {
	ctx := ctxPtr.(*volumemgrContext)
	d := res.Description.(casIngestWorkDescription)
	// loaded has the hashes of the blobs we loaded; publicise their new states.
	blobs := lookupBlobStatuses(ctx, d.loaded...)
	for _, blob := range blobs {
		blob.State = types.LOADED
		publishBlobStatus(ctx, blob)
	}
	updateStatusByBlob(ctx, d.status.Blobs...)
	return nil
}

// popasIngestWorkResult get the result exactly once
func popCasIngestWorkResult(ctx *volumemgrContext, key string) *casIngestWorkResult {
	res := ctx.worker.Pop(key)
	if res == nil {
		return nil
	}
	d := res.Description.(casIngestWorkDescription)
	return &casIngestWorkResult{
		WorkResult: *res,
		loaded:     d.loaded,
	}
}

// popVolumeWorkResult get the result exactly once
func popVolumeWorkResult(ctx *volumemgrContext, key string) *volumeWorkResult {
	res := ctx.worker.Pop(key)
	if res == nil {
		return nil
	}
	d := res.Description.(volumeWorkDescription)
	return &volumeWorkResult{
		WorkResult:    *res,
		FileLocation:  d.FileLocation,
		VolumeCreated: d.VolumeCreated,
		CreateTime:    d.CreateTime,
	}
}

// popVolumeWorkResult get the result exactly once
func popVolumePrepareResult(ctx *volumemgrContext, key string) *volumePrepareResult {
	res := ctx.worker.Pop(key)
	if res == nil {
		return nil
	}
	return &volumePrepareResult{
		WorkResult: *res,
	}
}
