// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/worker"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// fakeWorker implements worker.Worker with scripted TrySubmit results, so the
// submission-refused paths of doUpdateContentTree can be driven without a real
// pool. Only the methods the code under test touches do anything.
type fakeWorker struct {
	submitted  []worker.Work
	submitDone bool
	submitErr  error
	results    map[string]*worker.WorkResult
}

func newFakeWorker() *fakeWorker {
	return &fakeWorker{submitDone: true, results: map[string]*worker.WorkResult{}}
}

func (w *fakeWorker) NumPending() int                  { return 0 }
func (w *fakeWorker) NumResults() int                  { return 0 }
func (w *fakeWorker) MsgChan() <-chan worker.Processor { return nil }
func (w *fakeWorker) C() <-chan worker.Processor       { return nil }
func (w *fakeWorker) Submit(work worker.Work) error {
	_, err := w.TrySubmit(work)
	return err
}
func (w *fakeWorker) TrySubmit(work worker.Work) (bool, error) {
	w.submitted = append(w.submitted, work)
	if w.submitErr != nil {
		return false, w.submitErr
	}
	return w.submitDone, nil
}
func (w *fakeWorker) Cancel(key string) {}
func (w *fakeWorker) Done()             {}
func (w *fakeWorker) Pop(key string) *worker.WorkResult {
	res := w.results[key]
	delete(w.results, key)
	return res
}
func (w *fakeWorker) Peek(key string) *worker.WorkResult { return w.results[key] }

// newIngestTestCtx builds a volumemgrContext with in-memory pubsub topics and
// a fakeWorker: just enough for the VERIFIED->LOADING(ingest) transitions of
// doUpdateContentTree.
func newIngestTestCtx(t *testing.T) (*volumemgrContext, *fakeWorker) {
	t.Helper()
	logger := logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, "test-volumemgr", 0)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)
	pubContentTreeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ContentTreeStatus{},
	})
	if err != nil {
		t.Fatal(err)
	}
	pubBlobStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.BlobStatus{},
	})
	if err != nil {
		t.Fatal(err)
	}
	pubVolumeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumeStatus{},
	})
	if err != nil {
		t.Fatal(err)
	}
	subContentTreeConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "zedagent",
		TopicImpl: types.ContentTreeConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	wk := newFakeWorker()
	ctx := &volumemgrContext{
		pubContentTreeStatus: pubContentTreeStatus,
		pubBlobStatus:        pubBlobStatus,
		pubVolumeStatus:      pubVolumeStatus,
		subContentTreeConfig: subContentTreeConfig,
		worker:               wk,
		pendingIngest:        make(map[string]bool),
		inflightBlobIngests:  make(map[string]string),
	}
	return ctx, wk
}

// verifiedTree publishes one BlobStatus in the given state and returns a
// (published) ContentTreeStatus in VERIFIED that references it. Each call
// makes a distinct content tree; trees given the same sha share the blob.
func verifiedTree(ctx *volumemgrContext, name, sha string, blobState types.SwState) *types.ContentTreeStatus {
	blob := &types.BlobStatus{Sha256: sha, State: blobState, Path: "/some/path"}
	publishBlobStatus(ctx, blob)
	contentID, _ := uuid.NewV4()
	status := &types.ContentTreeStatus{
		ContentID:   contentID,
		DisplayName: name,
		State:       types.VERIFIED,
		Blobs:       []string{sha},
	}
	publishContentTreeStatus(ctx, status)
	return status
}

// TestRefusedIngestRevertsToVerified pins the fix for the field failure where
// a saturated worker pool made AddWorkLoad silently drop the CAS ingest after
// doUpdateContentTree had already committed the tree and its blobs to
// LOADING: nothing retried, no error was set, and the image was wedged until
// reboot. A refused submit must leave the tree (and the blobs it claimed) in
// VERIFIED so the re-evaluation paths retry it, and must surface a warning so
// the deferral is visible to the controller.
func TestRefusedIngestRevertsToVerified(t *testing.T) {
	ctx, wk := newIngestTestCtx(t)
	status := verifiedTree(ctx, "refused", "sha-refused", types.VERIFIED)

	wk.submitErr = &worker.PoolFullError{}
	changed, done := doUpdateContentTree(ctx, status)
	if !changed || done {
		t.Errorf("got (changed=%v,done=%v), want (true,false)", changed, done)
	}
	if status.State != types.VERIFIED {
		t.Errorf("tree state = %s, want VERIFIED", status.State)
	}
	if blob := ctx.LookupBlobStatus("sha-refused"); blob.State != types.VERIFIED {
		t.Errorf("blob state = %s, want VERIFIED (claim released)", blob.State)
	}
	if !status.HasError() || status.ErrorSeverity != types.ErrorSeverityWarning {
		t.Errorf("expected a warning on the status, got error=%q severity=%v",
			status.Error, status.ErrorSeverity)
	}
	if ctx.pendingIngest[status.Key()] {
		t.Error("refused job must not be recorded as in flight")
	}

	// A pool slot freed up: the same call now goes through, moves the tree to
	// LOADING, records the in-flight job and drops the deferral warning.
	wk.submitErr = nil
	doUpdateContentTree(ctx, status)
	if status.State != types.LOADING {
		t.Errorf("tree state = %s, want LOADING", status.State)
	}
	if blob := ctx.LookupBlobStatus("sha-refused"); blob.State != types.LOADING {
		t.Errorf("blob state = %s, want LOADING", blob.State)
	}
	if status.HasError() {
		t.Errorf("deferral warning must be cleared on submit, got %q", status.Error)
	}
	if !ctx.pendingIngest[status.Key()] {
		t.Error("accepted job must be recorded as in flight")
	}
}

// TestLoadingWithoutIngestResets pins the self-healing of a content tree
// found in LOADING with no ingest job in flight (a refused submit from before
// this fix, or a volumemgr restart mid-ingest): it must fall back to VERIFIED
// and resubmit the load, instead of waiting forever for a work result that
// cannot arrive. A tree whose ingest actually failed keeps its error and
// stays parked, as before.
func TestLoadingWithoutIngestResets(t *testing.T) {
	ctx, wk := newIngestTestCtx(t)
	status := verifiedTree(ctx, "orphaned", "sha-orphaned", types.LOADING)
	status.State = types.LOADING
	publishContentTreeStatus(ctx, status)

	changed, _ := doUpdateContentTree(ctx, status)
	if !changed || status.State != types.LOADING {
		t.Errorf("got (changed=%v,state=%s), want (true,LOADING) with a fresh job",
			changed, status.State)
	}
	if len(wk.submitted) != 1 {
		t.Fatalf("expected the load to be resubmitted once, got %d", len(wk.submitted))
	}
	if !ctx.pendingIngest[status.Key()] {
		t.Error("resubmitted job must be recorded as in flight")
	}

	// With the job recorded as in flight it must keep waiting in LOADING.
	doUpdateContentTree(ctx, status)
	if status.State != types.LOADING || len(wk.submitted) != 1 {
		t.Errorf("state = %s, submissions = %d; want waiting in LOADING with no resubmit",
			status.State, len(wk.submitted))
	}

	// A tree with an error is the controller's to retry; no auto-resubmit.
	delete(ctx.pendingIngest, status.Key())
	status.SetErrorWithSource("ingest failed", types.ContentTreeStatus{}, status.CreateTime)
	doUpdateContentTree(ctx, status)
	if status.State != types.LOADING || len(wk.submitted) != 1 {
		t.Errorf("state = %s, submissions = %d; want parked in LOADING with the error",
			status.State, len(wk.submitted))
	}
}

// TestOrphanedRootBlobTakeover pins the shared-blob half of the stall: a
// content tree must defer on a root blob in LOADING only while some in-flight
// ingest actually covers that blob. An orphaned LOADING root (its tree's
// submit was refused) is taken over instead of deferred to forever.
func TestOrphanedRootBlobTakeover(t *testing.T) {
	ctx, wk := newIngestTestCtx(t)
	status := verifiedTree(ctx, "sharer", "sha-shared", types.LOADING)

	// No ingest in flight covers the root: take the load over.
	doUpdateContentTree(ctx, status)
	if status.State != types.LOADING {
		t.Errorf("state = %s, want LOADING (took over orphaned root)", status.State)
	}
	if len(wk.submitted) != 1 {
		t.Fatalf("expected one submitted job, got %d", len(wk.submitted))
	}

	// The takeover is now the in-flight ingest covering the shared blob, so a
	// second tree sharing it defers (and submits nothing).
	waiting := verifiedTree(ctx, "waiter", "sha-shared", types.LOADING)
	doUpdateContentTree(ctx, waiting)
	if waiting.State != types.VERIFIED {
		t.Errorf("state = %s, want VERIFIED (deferring to in-flight load)", waiting.State)
	}
	if len(wk.submitted) != 1 {
		t.Errorf("expected no new submission while deferring, got %d", len(wk.submitted))
	}
}

// TestSharedBlobIngestedOnce pins the claim protocol that stops concurrent
// workers from ingesting the same blob: the job submitted for a content tree
// claims the LOADING blobs no other in-flight job owns, a second tree sharing
// the blob defers instead of submitting a duplicate load, and when the owning
// job ends without loading the blob (here: it failed), the release of its
// claims lets the waiting tree take the load over. Before this, every tree
// sharing a layer re-ingested it, and the loser of that race could find the
// verified file already deleted by the winner's completion.
func TestSharedBlobIngestedOnce(t *testing.T) {
	ctx, wk := newIngestTestCtx(t)
	first := verifiedTree(ctx, "first", "sha-once", types.VERIFIED)

	doUpdateContentTree(ctx, first)
	if owner := ctx.inflightBlobIngests["sha-once"]; owner != first.Key() {
		t.Fatalf("blob owner = %q, want %q", owner, first.Key())
	}
	d := wk.submitted[0].Description.(casIngestWorkDescription)
	if len(d.claimedBlobs) != 1 || d.claimedBlobs[0] != "sha-once" {
		t.Fatalf("claimedBlobs = %v, want [sha-once]", d.claimedBlobs)
	}

	// A second tree sharing the blob defers on the claimed root instead of
	// submitting a duplicate ingest of the same content.
	second := verifiedTree(ctx, "second", "sha-once", types.LOADING)
	doUpdateContentTree(ctx, second)
	if second.State != types.VERIFIED || len(wk.submitted) != 1 {
		t.Fatalf("state = %s, submissions = %d; want deferred with no duplicate job",
			second.State, len(wk.submitted))
	}

	// The owning job fails without having loaded the blob. Its result must
	// release the claim, and the waiting tree must take the load over with a
	// job of its own, rather than deferring forever to a load nobody owns.
	res := worker.WorkResult{
		Key:         first.Key(),
		Error:       &worker.PoolFullError{}, // any error will do
		Description: d,
	}
	wk.results[first.Key()] = &res
	if err := processCasIngestWorkResult(ctx, res); err != nil {
		t.Fatal(err)
	}
	// The released claim is not observable as an empty map out here: releasing
	// it inside the handler is exactly what lets the re-drive in the same call
	// hand the blob to the waiting tree, which claims it again. What must hold
	// is that the failed job no longer owns it.
	if owner := ctx.inflightBlobIngests["sha-once"]; owner == first.Key() {
		t.Errorf("failed job still owns the blob claim")
	}
	failed := ctx.LookupContentTreeStatus(first.Key())
	if !failed.HasError() || failed.State != types.LOADING {
		t.Errorf("failed tree: state=%s error=%q; want parked in LOADING with the error",
			failed.State, failed.Error)
	}
	if len(wk.submitted) != 2 {
		t.Fatalf("submissions = %d; want the waiting tree to take the load over",
			len(wk.submitted))
	}
	takeover := wk.submitted[1].Description.(casIngestWorkDescription)
	if len(takeover.claimedBlobs) != 1 || takeover.claimedBlobs[0] != "sha-once" {
		t.Errorf("takeover claims = %v, want [sha-once]", takeover.claimedBlobs)
	}
	if owner := ctx.inflightBlobIngests["sha-once"]; owner != second.Key() {
		t.Errorf("blob owner after takeover = %q, want %q", owner, second.Key())
	}
}

// TestSelectClaimedBlobs pins what the ingest worker will load: fresh copies
// of exactly the claimed blobs, skipping one that disappeared (its tree was
// deleted while the job waited) or that is already loaded.
func TestSelectClaimedBlobs(t *testing.T) {
	ctx, _ := newIngestTestCtx(t)
	publishBlobStatus(ctx,
		&types.BlobStatus{Sha256: "sha-load", State: types.LOADING, Path: "/fresh/path"},
		&types.BlobStatus{Sha256: "sha-done", State: types.LOADED})

	got := selectClaimedBlobs(ctx, "key", []string{"sha-load", "sha-done", "sha-gone"})
	if len(got) != 1 || got[0].Sha256 != "sha-load" || got[0].Path != "/fresh/path" {
		t.Errorf("selectClaimedBlobs = %+v, want just sha-load with its current path", got)
	}
}

// TestLoadingWaitsOnForeignClaim pins the guard on the LOADING self-heal: a
// content tree with no job of its own must NOT reset and resubmit while a
// concurrent job's claim covers its missing blob -- that job's result is what
// re-drives this tree. Without the guard the reset loops: the fresh job can
// claim nothing (the blob is owned), completes as a no-op that still updates
// the image reference in containerd, and its result handler re-drives the
// tree straight back into the reset, for as long as the owning job keeps
// loading the shared layer.
func TestLoadingWaitsOnForeignClaim(t *testing.T) {
	ctx, wk := newIngestTestCtx(t)
	publishBlobStatus(ctx,
		&types.BlobStatus{Sha256: "sha-root-l", State: types.LOADED},
		&types.BlobStatus{Sha256: "sha-layer", State: types.LOADING, Path: "/some/path"})
	contentID, _ := uuid.NewV4()
	status := &types.ContentTreeStatus{
		ContentID:   contentID,
		DisplayName: "waiter",
		State:       types.LOADING,
		Blobs:       []string{"sha-root-l", "sha-layer"},
	}
	publishContentTreeStatus(ctx, status)
	ctx.inflightBlobIngests["sha-layer"] = "other-tree-key"

	changed, _ := doUpdateContentTree(ctx, status)
	if changed || status.State != types.LOADING || len(wk.submitted) != 0 {
		t.Errorf("got (changed=%v,state=%s,submissions=%d); want to keep waiting in LOADING",
			changed, status.State, len(wk.submitted))
	}

	// Once the claim is released (the owning job finished without loading the
	// blob), the reset fires and the resubmitted job claims the blob itself.
	delete(ctx.inflightBlobIngests, "sha-layer")
	doUpdateContentTree(ctx, status)
	if status.State != types.LOADING || len(wk.submitted) != 1 {
		t.Errorf("state=%s submissions=%d; want reset and one resubmitted job",
			status.State, len(wk.submitted))
	}
	if owner := ctx.inflightBlobIngests["sha-layer"]; owner != status.Key() {
		t.Errorf("blob owner = %q, want %q", owner, status.Key())
	}
}
