// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

// Interface to worker to run the create and destroy in separate goroutines

import (
	"errors"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/volumehandlers"
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

// trySubmitWork hands one work item to the worker pool, distinguishing the
// benign idempotent case (a job with this key is already in progress) from a
// real refusal. Returns nil if the job is running or was accepted, and an
// error (a worker.PoolFullError when the pool is at maxWorkers) if nothing
// owns the work: the caller must then either retry later or not commit any
// state that assumes the job will run.
func trySubmitWork(ctx *volumemgrContext, w worker.Work) error {
	done, err := ctx.worker.TrySubmit(w)
	if err != nil {
		var inProgress *worker.JobInProgressError
		if errors.As(err, &inProgress) {
			log.Functionf("trySubmitWork(%s): job already in progress", w.Key)
			return nil
		}
		return err
	}
	if !done {
		// A pool never returns (false, nil); only a bare worker with a full
		// queue does, and volumemgr uses a pool.
		return fmt.Errorf("worker did not accept job %s", w.Key)
	}
	return nil
}

// AddWorkCreate adds a Work job to create a volume.
// Returns an error if the job could not be handed to the worker pool, in
// which case no worker owns it and the caller must arrange for a retry. A job
// already in progress for this key counts as success, so callers stay
// idempotent.
func AddWorkCreate(ctx *volumemgrContext, status *types.VolumeStatus) error {
	d := volumeWorkDescription{
		create: true,
		status: *status,
	}
	w := worker.Work{Kind: workCreate, Key: status.Key(), Description: d}
	if err := trySubmitWork(ctx, w); err != nil {
		log.Warnf("AddWorkCreate(%s): %v", status.Key(), err)
		return err
	}
	return nil
}

// AddWorkLoad adds a Work job to load an image and blobs into CAS.
// Returns an error if the job could not be handed to the worker pool, in
// which case no worker owns the content tree and the caller must undo
// whatever state it committed in anticipation of the load. A job that is
// already in progress for this key counts as success, so callers stay
// idempotent.
func AddWorkLoad(ctx *volumemgrContext, status *types.ContentTreeStatus) error {
	d := casIngestWorkDescription{
		status: *status,
	}
	w := worker.Work{Kind: workIngest, Key: status.Key(), Description: d}
	if err := trySubmitWork(ctx, w); err != nil {
		log.Warnf("AddWorkLoad(%s): %v", status.Key(), err)
		return err
	}
	if ctx.pendingIngest == nil {
		ctx.pendingIngest = make(map[string]bool)
	}
	ctx.pendingIngest[status.Key()] = true
	return nil
}

// ingestInFlightFor reports whether some content tree with an accepted, not
// yet completed CAS ingest job carries this blob. A blob sitting in LOADING
// that no in-flight job covers has lost its worker; treating such a blob as
// busy is what turns a refused submit into a permanent stall for every other
// content tree sharing it.
func ingestInFlightFor(ctx *volumemgrContext, sha string) bool {
	for key := range ctx.pendingIngest {
		ctStatus := ctx.LookupContentTreeStatus(key)
		if ctStatus == nil {
			continue
		}
		for _, blobSha := range ctStatus.Blobs {
			if blobSha == sha {
				return true
			}
		}
	}
	return false
}

// AddWorkPrepare adds a Work job to prepare creation of a volume.
// Returns an error if the job could not be handed to the worker pool (see
// AddWorkCreate); a job already in progress for this key counts as success.
func AddWorkPrepare(ctx *volumemgrContext, status *types.VolumeStatus) error {
	d := volumeWorkDescription{
		prepare: true,
		status:  *status,
	}
	w := worker.Work{Kind: workPrepare, Key: status.Key(), Description: d}
	if err := trySubmitWork(ctx, w); err != nil {
		log.Warnf("AddWorkPrepare(%s): %v", status.Key(), err)
		return err
	}
	return nil
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

// AddWorkDestroy adds a Work job to destroy a volume.
// Returns an error if the job could not be handed to the worker pool (see
// AddWorkCreate); a job already in progress for this key counts as success.
func AddWorkDestroy(ctx *volumemgrContext, status *types.VolumeStatus) error {
	d := volumeWorkDescription{
		destroy: true,
		status:  *status,
	}
	w := worker.Work{Kind: workCreate, Key: status.Key(), Description: d}
	if err := trySubmitWork(ctx, w); err != nil {
		log.Warnf("AddWorkDestroy(%s): %v", status.Key(), err)
		return err
	}
	return nil
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

	vcp := types.VolumeCreatePendingFromVolumeStatus(d.status)

	handler := volumehandlers.GetVolumeHandler(log, ctx, &d.status)

	if d.create {
		//set or update pending create operation
		_ = ctx.pubVolumeCreatePending.Publish(vcp.Key(), vcp)
		fileLocation, err = handler.CreateVolume()
		if err == nil {
			volumeCreated = true
			//in case of no error remove pending create operation
			_ = ctx.pubVolumeCreatePending.Unpublish(vcp.Key())
		}
	} else if d.destroy {
		if el, _ := ctx.pubVolumeCreatePending.Get(vcp.Key()); el != nil {
			// we are not worry about volume consistency here as we want to delete it
			// so remove pending create operation if exists
			_ = ctx.pubVolumeCreatePending.Unpublish(vcp.Key())
		}
		if d.status.FileLocation != "" {
			volumeCreated = d.status.State == types.CREATED_VOLUME
			fileLocation, err = handler.DestroyVolume()
			if err == nil {
				volumeCreated = false
			}
		}
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

	appImgName := status.ReferenceID()

	// load the blobs
	loadedBlobs, err := ctx.casClient.IngestBlobsAndCreateImage(appImgName, *root, loadBlobs...)
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
	err := volumehandlers.GetVolumeHandler(log, ctx, &d.status).PrepareVolume()
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
	if d.create {
		if !updateVolumeStatus(ctx, d.status.VolumeID) {
			//if it ends up after deleting of status we must do cleanup
			log.Warnf("processVolumeWorkResult: no status for %s after create, will delete", d.status.VolumeID)
			DeleteWorkCreate(ctx, &d.status)
			d.status.FileLocation = d.FileLocation
			d.status.SubState = types.VolumeSubStateDeleting
			if err := AddWorkDestroy(ctx, &d.status); err != nil {
				// There is no VolumeStatus left to retry from; the created
				// file stays behind until the init-time GC. Losing this
				// cleanup must not lose the result processing.
				log.Errorf("processVolumeWorkResult: destroy of orphaned %s not scheduled: %v",
					d.status.Key(), err)
			}
		}
	} else {
		status := ctx.LookupVolumeStatus(d.status.Key())
		if status == nil {
			log.Functionf("processVolumeWorkResult for %v, VolumeStatus not found", d.status.Key())
		} else {
			log.Functionf("processVolumeWorkResult for %v, VolumeStatus found", d.status.Key())
			updateVolumeStatusRefCount(ctx, status)
			maybeDeleteVolume(ctx, status)
		}
	}
	// This job's completion freed a slot in the shared worker pool: give any
	// volume or content tree whose submission was refused another chance.
	reevaluatePendingVolumes(ctx)
	reevaluatePendingContentTrees(ctx)
	return nil
}

// processVolumePrepareResult handle the work result that was a volume prepare action
func processVolumePrepareResult(ctxPtr interface{}, res worker.WorkResult) error {
	ctx := ctxPtr.(*volumemgrContext)
	d := res.Description.(volumeWorkDescription)
	updateVolumeStatus(ctx, d.status.VolumeID)
	// See processVolumeWorkResult: this frees a slot in the shared pool.
	reevaluatePendingVolumes(ctx)
	reevaluatePendingContentTrees(ctx)
	return nil
}

// processCasIngestWorkResult handle the work result that was a cas ingestion
func processCasIngestWorkResult(ctxPtr interface{}, res worker.WorkResult) error {
	ctx := ctxPtr.(*volumemgrContext)
	d := res.Description.(casIngestWorkDescription)
	delete(ctx.pendingIngest, d.status.Key())
	// loaded has the hashes of the blobs we loaded; publicise their new states.
	blobs := lookupBlobStatuses(ctx, d.loaded...)
	for _, blob := range blobs {
		blob.State = types.LOADED
		publishBlobStatus(ctx, blob)
	}
	updateStatusByBlob(ctx, d.status.Blobs...)
	// See processVolumeWorkResult: this frees a slot in the shared pool.
	reevaluatePendingVolumes(ctx)
	reevaluatePendingContentTrees(ctx)
	return nil
}

// popCasIngestWorkResult gets the result exactly once. A result whose job was
// submitted for different content than the tree now under this key is
// discarded: a content change makes handleContentTreeModify delete and
// recreate the tree, but Key() is the bare ContentID, so the recreated tree
// would otherwise consume the replaced tree's outcome -- typically a failed
// ingest of content that no longer exists, parking the new tree with a stale
// error. With the result discarded, the LOADING self-heal resubmits a fresh
// load once no job is in flight.
func popCasIngestWorkResult(ctx *volumemgrContext, status *types.ContentTreeStatus) *casIngestWorkResult {
	res := ctx.worker.Pop(status.Key())
	if res == nil {
		return nil
	}
	d := res.Description.(casIngestWorkDescription)
	if d.status.ContentSha256 != status.ContentSha256 ||
		d.status.RelativeURL != status.RelativeURL {
		log.Noticef("popCasIngestWorkResult(%s): discarding result of replaced content (sha %s url %s)",
			status.Key(), d.status.ContentSha256, d.status.RelativeURL)
		return nil
	}
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
