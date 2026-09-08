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
	// claimedBlobs are the blob sha256s this job -- and no concurrent job --
	// will load into the CAS, decided in the main event loop at submit time
	// (see AddWorkLoad).
	claimedBlobs []string
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
// real refusal. Returns (true, nil) if this submission was accepted,
// (false, nil) if a job with this key is already running, and an error (a
// worker.PoolFullError when the pool is at maxWorkers) if nothing owns the
// work: the caller must then either retry later or not commit any state that
// assumes the job will run.
func trySubmitWork(ctx *volumemgrContext, w worker.Work) (bool, error) {
	done, err := ctx.worker.TrySubmit(w)
	if err != nil {
		var inProgress *worker.JobInProgressError
		if errors.As(err, &inProgress) {
			log.Functionf("trySubmitWork(%s): job already in progress", w.Key)
			return false, nil
		}
		return false, err
	}
	if !done {
		// A pool never returns (false, nil); only a bare worker with a full
		// queue does, and volumemgr uses a pool.
		return false, fmt.Errorf("worker did not accept job %s", w.Key)
	}
	return true, nil
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
	if _, err := trySubmitWork(ctx, w); err != nil {
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
	if ctx.pendingIngest == nil {
		ctx.pendingIngest = make(map[string]bool)
	}
	if ctx.inflightBlobIngests == nil {
		ctx.inflightBlobIngests = make(map[string]string)
	}
	// Decide here, where BlobStatus is authoritative, exactly which blobs
	// this job will load: those in LOADING that no other in-flight job has
	// claimed. The worker must not select blobs itself from the stale copy it
	// is handed: two workers that each saw a shared blob in LOADING would
	// both ingest it, and the one finishing last can find the verified file
	// already deleted by the completion of the first (with the redundant
	// multi-hundred-MB writes as a bonus).
	var claimed []string
	seen := map[string]bool{}
	for _, blobSha := range status.Blobs {
		if seen[blobSha] {
			continue
		}
		seen[blobSha] = true
		blob := ctx.LookupBlobStatus(blobSha)
		if blob == nil || blob.State != types.LOADING {
			continue
		}
		if owner, ok := ctx.inflightBlobIngests[blobSha]; ok && owner != status.Key() {
			// Another job loads it; this tree waits on that job's result.
			continue
		}
		claimed = append(claimed, blobSha)
	}
	d := casIngestWorkDescription{
		status:       *status,
		claimedBlobs: claimed,
	}
	w := worker.Work{Kind: workIngest, Key: status.Key(), Description: d}
	accepted, err := trySubmitWork(ctx, w)
	if err != nil {
		log.Warnf("AddWorkLoad(%s): %v", status.Key(), err)
		return err
	}
	ctx.pendingIngest[status.Key()] = true
	if accepted {
		// Only a submission that was actually handed to a worker owns its
		// claims; when the key was already in progress, the running job keeps
		// loading whatever it claimed at its own submit time.
		for _, blobSha := range claimed {
			ctx.inflightBlobIngests[blobSha] = status.Key()
		}
	}
	return nil
}

// ingestInFlightFor reports whether some accepted, not yet completed CAS
// ingest job claimed this blob. A blob sitting in LOADING that no in-flight
// job covers has lost its worker; treating such a blob as busy is what turns
// a refused submit into a permanent stall for every other content tree
// sharing it.
func ingestInFlightFor(ctx *volumemgrContext, sha string) bool {
	_, ok := ctx.inflightBlobIngests[sha]
	return ok
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
	if _, err := trySubmitWork(ctx, w); err != nil {
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
	if _, err := trySubmitWork(ctx, w); err != nil {
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

// selectClaimedBlobs returns fresh copies of the blobs an ingest job claimed
// at submit time and still has to load. Re-reading BlobStatus here (rather
// than trusting the copy taken at submit time) keeps Path current; a claimed
// blob that meanwhile disappeared (its content tree was deleted) or was
// already loaded is skipped.
func selectClaimedBlobs(ctx *volumemgrContext, key string, claimedBlobs []string) []types.BlobStatus {
	loadBlobs := []types.BlobStatus{}
	for _, blobSha := range claimedBlobs {
		blob := ctx.LookupBlobStatus(blobSha)
		if blob == nil {
			log.Warnf("selectClaimedBlobs(%s): claimed blob %s disappeared, skipping",
				key, blobSha)
			continue
		}
		if blob.State == types.LOADED {
			continue
		}
		loadBlobs = append(loadBlobs, *blob)
	}
	return loadBlobs
}

// casIngestWorker implementation of work.WorkFunction that loads blobs and an image into the CAS store
func casIngestWorker(ctxPtr interface{}, w worker.Work) worker.WorkResult {
	ctx := ctxPtr.(*volumemgrContext)
	d := w.Description.(casIngestWorkDescription)
	status := d.status

	log.Functionf("casIngestWorker has blobs: %v, claimed: %v",
		status.Blobs, d.claimedBlobs)
	result := worker.WorkResult{
		Key:         w.Key,
		Description: d,
	}

	// Load exactly the blobs this job claimed at submit time (see
	// AddWorkLoad). Blobs of this tree claimed by a concurrent job are left
	// to that job; the tree waits for them through the per-blob states.
	loadBlobs := selectClaimedBlobs(ctx, status.Key(), d.claimedBlobs)

	// The first blob is always the root; the image reference is created from
	// its descriptor even when nothing is left to ingest.
	var root *types.BlobStatus
	if len(status.Blobs) > 0 {
		root = ctx.LookupBlobStatus(status.Blobs[0])
	}
	if root == nil {
		result.Error = fmt.Errorf("casIngestWorker(%s): root blob not found",
			status.Key())
		result.ErrorTime = time.Now()
		return result
	}

	appImgName := status.ReferenceID()

	// load the blobs
	loadedBlobs, err := ctx.casClient.IngestBlobsAndCreateImage(appImgName, *root, loadBlobs...)
	// loadedBlobs are BlobStatus for the ones we loaded
	for _, blob := range loadedBlobs {
		d.loaded = append(d.loaded, blob.Sha256)
	}
	result.Description = d
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
	key := d.status.Key()
	delete(ctx.pendingIngest, key)
	// Release this job's blob claims, whether it succeeded or not: a blob it
	// claimed but failed to load stays in LOADING with no owner, and the next
	// content tree to look at it takes the load over instead of waiting.
	for sha, owner := range ctx.inflightBlobIngests {
		if owner == key {
			delete(ctx.inflightBlobIngests, sha)
		}
	}
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
