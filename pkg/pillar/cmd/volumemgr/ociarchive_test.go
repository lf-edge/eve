// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/worker"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// fakeCAS answers the few image queries the content tree state machine makes
// and records what it is asked to load or remove. Any other method panics on
// the nil embedded interface.
type fakeCAS struct {
	cas.CAS
	images  map[string]string            // reference -> manifest hash
	labels  map[string]map[string]string // reference -> image labels
	blobs   map[string][]string          // blob hash -> children
	content map[string]string            // blob hash -> content
	removed []string
	// arguments of the last IngestOCILayoutAndCreateImage, and its error
	ingestArchive    string
	ingestArchiveSha string
	ingestBlobs      []string
	ingestErr        error
}

func newFakeCAS() *fakeCAS {
	return &fakeCAS{
		images:  map[string]string{},
		labels:  map[string]map[string]string{},
		blobs:   map[string][]string{},
		content: map[string]string{},
	}
}

func (c *fakeCAS) GetImageHash(reference string) (string, error) {
	hash, ok := c.images[reference]
	if !ok {
		return "", cas.ErrImageNotFound
	}
	return hash, nil
}

func (c *fakeCAS) GetImageLabels(reference string) (map[string]string, error) {
	if _, ok := c.images[reference]; !ok {
		return nil, cas.ErrImageNotFound
	}
	return c.labels[reference], nil
}

func (c *fakeCAS) Children(blobHash string) ([]string, error) {
	return c.blobs[blobHash], nil
}

func (c *fakeCAS) ReadBlob(_ context.Context, blobHash string) (io.Reader, error) {
	content, ok := c.content[blobHash]
	if !ok {
		return nil, fmt.Errorf("blob %s not found", blobHash)
	}
	return strings.NewReader(content), nil
}

func (c *fakeCAS) CtrNewUserServicesCtx() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

func (c *fakeCAS) RemoveBlob(blobHash string) error {
	c.removed = append(c.removed, blobHash)
	return nil
}

func (c *fakeCAS) IngestOCILayoutAndCreateImage(reference, archivePath, archiveSha256 string, blobs []string) ([]string, error) {
	c.ingestArchive = archivePath
	c.ingestArchiveSha = archiveSha256
	c.ingestBlobs = blobs
	if c.ingestErr != nil {
		return nil, c.ingestErr
	}
	c.images[reference] = "sha256:image"
	return blobs, nil
}

const (
	archiveSha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	configSha  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	manifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	layerMediaType    = "application/vnd.oci.image.layer.v1.tar"
)

// testImage is the image inside the archive written by writeImageArchive.
type testImage struct {
	archive                 string // path of the archive
	manifest, config, layer string // sha256 of the blobs
	manifestJSON            string
}

func (img testImage) blobs() []string {
	return []string{img.manifest, img.config, img.layer}
}

// writeImageArchive writes an OCI image-layout archive holding one image with
// one layer for the architecture the test runs on.
func writeImageArchive(t *testing.T) testImage {
	t.Helper()
	sum := func(data string) string {
		return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
	}
	layer := "layer content"
	config := fmt.Sprintf(`{"architecture":%q,"os":"linux"}`, runtime.GOARCH)
	manifest := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,`+
		`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%s","size":%d},`+
		`"layers":[{"mediaType":%q,"digest":"sha256:%s","size":%d}]}`,
		manifestMediaType, sum(config), len(config), layerMediaType, sum(layer), len(layer))
	index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"mediaType":%q,"digest":"sha256:%s","size":%d}]}`,
		manifestMediaType, sum(manifest), len(manifest))

	img := testImage{
		archive:      filepath.Join(t.TempDir(), "image.tar"),
		manifest:     sum(manifest),
		config:       sum(config),
		layer:        sum(layer),
		manifestJSON: manifest,
	}
	f, err := os.Create(img.archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for _, entry := range [][2]string{
		{"oci-layout", `{"imageLayoutVersion":"1.0.0"}`},
		{"index.json", index},
		{"blobs/sha256/" + img.manifest, manifest},
		{"blobs/sha256/" + img.config, config},
		{"blobs/sha256/" + img.layer, layer},
	} {
		hdr := &tar.Header{Name: entry[0], Typeflag: tar.TypeReg, Size: int64(len(entry[1])), Mode: 0644}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(entry[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return img
}

// singleBlobTree publishes a content tree whose one blob, the file at path,
// is verified.
func singleBlobTree(ctx *volumemgrContext, path string) *types.ContentTreeStatus {
	blob := &types.BlobStatus{Sha256: archiveSha, State: types.VERIFIED, Path: path, RefCount: 1}
	publishBlobStatus(ctx, blob)
	contentID, _ := uuid.NewV4()
	status := &types.ContentTreeStatus{
		ContentID:             contentID,
		DisplayName:           "base-os",
		RelativeURL:           "eve.tar",
		ContentSha256:         archiveSha,
		State:                 types.DOWNLOADING,
		Blobs:                 []string{archiveSha},
		AllDatastoresResolved: true,
	}
	publishContentTreeStatus(ctx, status)
	return status
}

// loadingArchiveTree returns the content tree of a verified archive after its
// ingest job was submitted, and that job.
func loadingArchiveTree(t *testing.T, ctx *volumemgrContext, wk *fakeWorker, img testImage) (*types.ContentTreeStatus, worker.Work) {
	t.Helper()
	status := singleBlobTree(ctx, img.archive)
	doUpdateContentTree(ctx, status)
	if status.State != types.LOADING || len(wk.submitted) != 1 {
		t.Fatalf("state = %s (error %q), submissions = %d; want LOADING with one ingest job",
			status.State, status.Error, len(wk.submitted))
	}
	publishContentTreeStatus(ctx, status)
	return status, wk.submitted[0]
}

// finishIngest runs the ingest job and hands its result to the main loop.
func finishIngest(t *testing.T, ctx *volumemgrContext, wk *fakeWorker, job worker.Work) {
	t.Helper()
	res := casIngestWorker(ctx, job)
	wk.results[job.Key] = &res
	if err := processCasIngestWorkResult(ctx, res); err != nil {
		t.Fatal(err)
	}
}

func wantBlobs(t *testing.T, status *types.ContentTreeStatus, want ...string) {
	t.Helper()
	if strings.Join(status.Blobs, ",") != strings.Join(want, ",") {
		t.Fatalf("blobs = %v, want %v", status.Blobs, want)
	}
}

// A verified archive must make the content tree hold the blobs of its image
// before anything is loaded, and the ingest job must be told to load them
// from the archive. Any other file still gets wrapped in a manifest of its
// own.
func TestArchiveImageBlobsAdded(t *testing.T) {
	t.Run("archive", func(t *testing.T) {
		ctx, wk, fake := newCreateTestCtx(t)
		img := writeImageArchive(t)
		status, job := loadingArchiveTree(t, ctx, wk, img)

		wantBlobs(t, status, img.blobs()...)
		if status.OCIArchiveBlob != archiveSha {
			t.Errorf("OCIArchiveBlob = %q, want the archive", status.OCIArchiveBlob)
		}
		for _, sha := range append(img.blobs(), archiveSha) {
			if blob := ctx.LookupBlobStatus(sha); blob == nil || blob.RefCount != 1 {
				t.Errorf("blob %s = %+v, want one reference", sha[:4], blob)
			}
		}
		if root := ctx.LookupBlobStatus(status.Blobs[0]); !root.IsManifest() {
			t.Errorf("root blob has media type %q, want a manifest", root.MediaType)
		}
		if blob := ctx.LookupBlobStatus(archiveSha); blob.State != types.VERIFIED {
			t.Errorf("archive blob is %s, want it left VERIFIED", blob.State)
		}

		res := casIngestWorker(ctx, job)
		if res.Error != nil {
			t.Fatal(res.Error)
		}
		if fake.ingestArchive != img.archive || fake.ingestArchiveSha != archiveSha ||
			strings.Join(fake.ingestBlobs, ",") != strings.Join(img.blobs(), ",") {
			t.Errorf("worker loaded %v from %q (sha %q), want the image blobs from the archive",
				fake.ingestBlobs, fake.ingestArchive, fake.ingestArchiveSha)
		}
	})
	t.Run("plain file", func(t *testing.T) {
		ctx, wk, _ := newCreateTestCtx(t)
		plain := filepath.Join(t.TempDir(), "rootfs.img")
		if err := os.WriteFile(plain, []byte("hsqs-not-a-tar"), 0644); err != nil {
			t.Fatal(err)
		}
		status := singleBlobTree(ctx, plain)
		doUpdateContentTree(ctx, status)

		if status.State != types.LOADING || len(wk.submitted) != 1 {
			t.Fatalf("state = %s, submissions = %d; want LOADING with one ingest job",
				status.State, len(wk.submitted))
		}
		if len(status.Blobs) != 3 || status.Blobs[2] != archiveSha || status.OCIArchiveBlob != "" {
			t.Fatalf("blobs = %v, OCIArchiveBlob = %q; want the file behind a manifest and a config",
				status.Blobs, status.OCIArchiveBlob)
		}
	})
}

// An archive that cannot be read must fail the content tree, not be wrapped
// as if it were the artifact.
func TestArchiveUnreadable(t *testing.T) {
	noImage := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(noImage)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	for _, entry := range [][2]string{
		{"oci-layout", `{"imageLayoutVersion":"1.0.0"}`},
		{"index.json", `{"schemaVersion":2,"manifests":[]}`},
	} {
		_ = tw.WriteHeader(&tar.Header{Name: entry[0], Typeflag: tar.TypeReg, Size: int64(len(entry[1])), Mode: 0644})
		_, _ = tw.Write([]byte(entry[1]))
	}
	if err := errors.Join(tw.Close(), f.Close()); err != nil {
		t.Fatal(err)
	}
	whole, err := os.ReadFile(writeImageArchive(t).archive)
	if err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(truncated, whole[:len(whole)/2], 0644); err != nil {
		t.Fatal(err)
	}

	for name, file := range map[string]string{
		"no image":  noImage,
		"truncated": truncated,
		"missing":   filepath.Join(t.TempDir(), "absent"),
	} {
		t.Run(name, func(t *testing.T) {
			ctx, wk, _ := newCreateTestCtx(t)
			status := singleBlobTree(ctx, file)

			doUpdateContentTree(ctx, status)

			if !status.HasError() || len(wk.submitted) != 0 {
				t.Errorf("error = %q, submissions = %d; want an error and no ingest job",
					status.Error, len(wk.submitted))
			}
			wantBlobs(t, status, archiveSha)
		})
	}
}

// Once the image is loaded, the content tree must hold just its blobs and
// must have let go of the archive.
func TestArchiveIngestCompletes(t *testing.T) {
	ctx, wk, _ := newCreateTestCtx(t)
	img := writeImageArchive(t)
	status, job := loadingArchiveTree(t, ctx, wk, img)

	finishIngest(t, ctx, wk, job)

	got := ctx.LookupContentTreeStatus(status.Key())
	if got.State != types.LOADED || got.OCIArchiveBlob != "" {
		t.Errorf("state = %s (error %q), OCIArchiveBlob = %q; want LOADED without the archive",
			got.State, got.Error, got.OCIArchiveBlob)
	}
	wantBlobs(t, got, img.blobs()...)
	for _, sha := range img.blobs() {
		if blob := ctx.LookupBlobStatus(sha); blob == nil || blob.State != types.LOADED || blob.RefCount != 1 {
			t.Errorf("blob %s = %+v, want LOADED with one reference", sha[:4], blob)
		}
	}
	if ctx.LookupBlobStatus(archiveSha) != nil {
		t.Error("the archive blob is still published")
	}
}

// A loaded blob the image shares with another content tree must survive that
// tree being deleted while the archive is loaded, and must not be loaded a
// second time.
func TestArchiveKeepsSharedBlob(t *testing.T) {
	ctx, wk, fake := newCreateTestCtx(t)
	img := writeImageArchive(t)
	shared := &types.BlobStatus{Sha256: img.layer, State: types.LOADED, RefCount: 1}
	publishBlobStatus(ctx, shared)

	status, job := loadingArchiveTree(t, ctx, wk, img)
	d := job.Description.(casIngestWorkDescription)
	if strings.Join(d.claimedBlobs, ",") != img.manifest+","+img.config {
		t.Errorf("job claims %v, want the manifest and the config only", d.claimedBlobs)
	}

	RemoveRefFromBlobStatus(ctx, ctx.LookupBlobStatus(img.layer))
	if blob := ctx.LookupBlobStatus(img.layer); blob == nil || blob.RefCount != 1 || len(fake.removed) != 0 {
		t.Fatalf("shared layer = %+v, removed from CAS: %v; want it kept for the archive's tree",
			blob, fake.removed)
	}

	finishIngest(t, ctx, wk, job)
	if got := ctx.LookupContentTreeStatus(status.Key()); got.State != types.LOADED {
		t.Errorf("state = %s (error %q), want LOADED", got.State, got.Error)
	}
}

// A blob that another content tree's job is loading is left to that job. The
// archive's tree must wait for it without resubmitting its own job, which
// would have nothing to do.
func TestArchiveWaitsOnForeignClaim(t *testing.T) {
	ctx, wk, _ := newCreateTestCtx(t)
	img := writeImageArchive(t)
	publishBlobStatus(ctx, &types.BlobStatus{Sha256: img.layer, State: types.LOADING, RefCount: 1})
	ctx.inflightBlobIngests[img.layer] = "another-tree"

	status, job := loadingArchiveTree(t, ctx, wk, img)
	finishIngest(t, ctx, wk, job)

	got := ctx.LookupContentTreeStatus(status.Key())
	if got.State != types.LOADING || got.HasError() || len(wk.submitted) != 1 {
		t.Fatalf("state = %s, error = %q, %d job(s) submitted; want LOADING on the one job",
			got.State, got.Error, len(wk.submitted))
	}
	if got.OCIArchiveBlob != archiveSha {
		t.Errorf("OCIArchiveBlob = %q, want the archive kept", got.OCIArchiveBlob)
	}

	delete(ctx.inflightBlobIngests, img.layer)
	layer := ctx.LookupBlobStatus(img.layer)
	layer.State = types.LOADED
	publishBlobStatus(ctx, layer)
	updateStatusByBlob(ctx, img.layer)

	if got := ctx.LookupContentTreeStatus(status.Key()); got.State != types.LOADED {
		t.Errorf("state = %s (error %q), want LOADED", got.State, got.Error)
	}
}

// The archive has the content of a blob that another content tree is still
// downloading, so the job loads it, and a download error on it must not
// outlive the load.
func TestArchiveLoadsBlobBeingDownloaded(t *testing.T) {
	ctx, wk, _ := newCreateTestCtx(t)
	img := writeImageArchive(t)
	downloading := &types.BlobStatus{Sha256: img.layer, State: types.DOWNLOADING, RefCount: 1}
	downloading.SetErrorWithSource("connection reset", types.DownloaderStatus{}, time.Now())
	publishBlobStatus(ctx, downloading)

	_, job := loadingArchiveTree(t, ctx, wk, img)
	if blob := ctx.LookupBlobStatus(img.layer); blob.State != types.DOWNLOADING {
		t.Fatalf("layer is %s, want its state left to the tree that downloads it", blob.State)
	}
	finishIngest(t, ctx, wk, job)

	if blob := ctx.LookupBlobStatus(img.layer); blob.State != types.LOADED || blob.HasError() {
		t.Errorf("layer is %s with error %q, want LOADED without error", blob.State, blob.Error)
	}
}

// A failed ingest must leave the content tree with its references and the
// archive, with the error reported, and must not be retried on its own.
// Deleting the tree then leaves nothing behind.
func TestArchiveIngestError(t *testing.T) {
	ctx, wk, fake := newCreateTestCtx(t)
	img := writeImageArchive(t)
	status, job := loadingArchiveTree(t, ctx, wk, img)

	fake.ingestErr = errors.New("no space left on device")
	finishIngest(t, ctx, wk, job)

	got := ctx.LookupContentTreeStatus(status.Key())
	if !got.HasError() || got.State != types.LOADING {
		t.Errorf("state = %s, error = %q; want LOADING with the ingest error", got.State, got.Error)
	}
	wantBlobs(t, got, img.blobs()...)
	if blob := ctx.LookupBlobStatus(archiveSha); blob == nil || blob.RefCount != 1 {
		t.Errorf("archive blob = %+v, want it kept with one reference", blob)
	}
	if len(ctx.inflightBlobIngests) != 0 {
		t.Errorf("claims left behind: %v", ctx.inflightBlobIngests)
	}
	doUpdateContentTree(ctx, got)
	if len(wk.submitted) != 1 {
		t.Errorf("%d jobs submitted, want the failed load not to be retried", len(wk.submitted))
	}

	RemoveAllBlobsFromContentTreeStatus(ctx, got, got.Blobs...)
	for _, sha := range append(img.blobs(), archiveSha) {
		if ctx.LookupBlobStatus(sha) != nil {
			t.Errorf("blob %s is left behind by the deleted content tree", sha[:4])
		}
	}
}

// Deleting the content tree while the ingest runs must drop every blob it
// brought in, and the result of the finished ingest must not bring any back.
func TestArchiveIngestForDeletedTree(t *testing.T) {
	ctx, wk, _ := newCreateTestCtx(t)
	img := writeImageArchive(t)
	status, job := loadingArchiveTree(t, ctx, wk, img)

	res := casIngestWorker(ctx, job)
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	RemoveAllBlobsFromContentTreeStatus(ctx, status, status.Blobs...)
	unpublishContentTreeStatus(ctx, status)
	if err := processCasIngestWorkResult(ctx, res); err != nil {
		t.Fatal(err)
	}

	for _, sha := range append(img.blobs(), archiveSha) {
		if ctx.LookupBlobStatus(sha) != nil {
			t.Errorf("blob %s is published for a deleted content tree", sha[:4])
		}
	}
}

// secondArchiveTree returns another content tree for the archive that
// singleBlobTree published, after its turn in the state machine.
func secondArchiveTree(ctx *volumemgrContext) *types.ContentTreeStatus {
	AddRefToBlobStatus(ctx, ctx.LookupBlobStatus(archiveSha))
	contentID, _ := uuid.NewV4()
	status := &types.ContentTreeStatus{
		ContentID:             contentID,
		DisplayName:           "second",
		RelativeURL:           "eve.tar",
		ContentSha256:         archiveSha,
		State:                 types.DOWNLOADING,
		Blobs:                 []string{archiveSha},
		AllDatastoresResolved: true,
	}
	doUpdateContentTree(ctx, status)
	publishContentTreeStatus(ctx, status)
	return status
}

// Two content trees for the same archive must load its image once, and the
// archive must stay until both are done with it.
func TestArchiveSharedByTwoTrees(t *testing.T) {
	ctx, wk, _ := newCreateTestCtx(t)
	img := writeImageArchive(t)
	first, firstJob := loadingArchiveTree(t, ctx, wk, img)
	second := secondArchiveTree(ctx)

	if len(wk.submitted) != 2 {
		t.Fatalf("%d jobs submitted, want one per content tree", len(wk.submitted))
	}
	secondJob := wk.submitted[1]
	if claimed := secondJob.Description.(casIngestWorkDescription).claimedBlobs; len(claimed) != 0 {
		t.Errorf("second job claims %v, want everything left to the first", claimed)
	}
	for _, sha := range append(img.blobs(), archiveSha) {
		if blob := ctx.LookupBlobStatus(sha); blob.RefCount != 2 {
			t.Errorf("blob %s has %d references, want 2", sha[:4], blob.RefCount)
		}
	}

	finishIngest(t, ctx, wk, secondJob)
	if got := ctx.LookupContentTreeStatus(second.Key()); got.State != types.LOADING || len(wk.submitted) != 2 {
		t.Fatalf("second tree is %s after %d jobs, want it to wait for the first job",
			got.State, len(wk.submitted))
	}
	finishIngest(t, ctx, wk, firstJob)

	for _, key := range []string{first.Key(), second.Key()} {
		got := ctx.LookupContentTreeStatus(key)
		if got.State != types.LOADED || got.OCIArchiveBlob != "" {
			t.Errorf("tree is %s (error %q) with archive %q, want LOADED without it",
				got.State, got.Error, got.OCIArchiveBlob)
		}
	}
	if ctx.LookupBlobStatus(archiveSha) != nil {
		t.Error("the archive blob is still published")
	}
}

// When the job that claimed the blobs fails, a second content tree for the
// same archive must load them itself.
func TestArchiveSecondTreeTakesOver(t *testing.T) {
	ctx, wk, fake := newCreateTestCtx(t)
	img := writeImageArchive(t)
	first, firstJob := loadingArchiveTree(t, ctx, wk, img)
	second := secondArchiveTree(ctx)
	finishIngest(t, ctx, wk, wk.submitted[1])

	fake.ingestErr = errors.New("no space left on device")
	finishIngest(t, ctx, wk, firstJob)
	fake.ingestErr = nil

	if len(wk.submitted) != 3 || wk.submitted[2].Key != second.Key() {
		t.Fatalf("%d jobs submitted, want a third one for the second tree", len(wk.submitted))
	}
	if claimed := wk.submitted[2].Description.(casIngestWorkDescription).claimedBlobs; len(claimed) != 3 {
		t.Errorf("takeover job claims %v, want all three blobs", claimed)
	}
	finishIngest(t, ctx, wk, wk.submitted[2])

	if got := ctx.LookupContentTreeStatus(second.Key()); got.State != types.LOADED {
		t.Errorf("second tree is %s (error %q), want LOADED", got.State, got.Error)
	}
	got := ctx.LookupContentTreeStatus(first.Key())
	if !got.HasError() || got.OCIArchiveBlob != archiveSha {
		t.Errorf("first tree has error %q and archive %q, want its error and the archive kept",
			got.Error, got.OCIArchiveBlob)
	}
	if blob := ctx.LookupBlobStatus(archiveSha); blob == nil || blob.RefCount != 1 {
		t.Errorf("archive blob = %+v, want the first tree's reference left", blob)
	}
}

// A refused submission must leave the content tree ready to try again with
// its references in place, and so must a job that got lost.
func TestArchiveSubmitRetried(t *testing.T) {
	ctx, wk, _ := newCreateTestCtx(t)
	img := writeImageArchive(t)
	status := singleBlobTree(ctx, img.archive)

	wk.submitErr = &worker.PoolFullError{}
	doUpdateContentTree(ctx, status)
	if status.State != types.VERIFIED || status.OCIArchiveBlob != archiveSha ||
		len(ctx.pendingIngest) != 0 || len(ctx.inflightBlobIngests) != 0 {
		t.Fatalf("state = %s, archive = %q, pending = %v, claims = %v; want VERIFIED with nothing in flight",
			status.State, status.OCIArchiveBlob, ctx.pendingIngest, ctx.inflightBlobIngests)
	}
	wantBlobs(t, status, img.blobs()...)
	for _, sha := range append(img.blobs(), archiveSha) {
		if blob := ctx.LookupBlobStatus(sha); blob == nil || blob.RefCount != 1 {
			t.Errorf("blob %s = %+v, want one reference", sha[:4], blob)
		}
	}

	wk.submitErr = nil
	doUpdateContentTree(ctx, status)
	publishContentTreeStatus(ctx, status)
	if status.State != types.LOADING || len(wk.submitted) != 2 {
		t.Fatalf("state = %s after %d submissions, want LOADING on the second", status.State, len(wk.submitted))
	}

	// the job is lost
	delete(ctx.pendingIngest, status.Key())
	for sha := range ctx.inflightBlobIngests {
		delete(ctx.inflightBlobIngests, sha)
	}
	doUpdateContentTree(ctx, status)
	publishContentTreeStatus(ctx, status)
	if len(wk.submitted) != 3 {
		t.Fatalf("%d submissions, want the lost job submitted again", len(wk.submitted))
	}
	if claimed := wk.submitted[2].Description.(casIngestWorkDescription).claimedBlobs; len(claimed) != 3 {
		t.Errorf("resubmitted job claims %v, want all three blobs", claimed)
	}
	finishIngest(t, ctx, wk, wk.submitted[2])
	if got := ctx.LookupContentTreeStatus(status.Key()); got.State != types.LOADED {
		t.Errorf("state = %s (error %q), want LOADED", got.State, got.Error)
	}
}

// Only a blob that nothing can download gets a source from the content tree
// that finds it.
func TestHasNoSource(t *testing.T) {
	datastore, _ := uuid.NewV4()
	tests := map[string]struct {
		blob types.BlobStatus
		want bool
	}{
		"from an archive":   {types.BlobStatus{State: types.INITIAL}, true},
		"has a datastore":   {types.BlobStatus{State: types.INITIAL, DatastoreIDList: []uuid.UUID{datastore}}, false},
		"loaded at boot":    {types.BlobStatus{State: types.LOADED}, false},
		"being loaded":      {types.BlobStatus{State: types.LOADING}, false},
		"download underway": {types.BlobStatus{State: types.DOWNLOADING}, false},
	}
	for name, tt := range tests {
		if got := hasNoSource(&tt.blob); got != tt.want {
			t.Errorf("%s: hasNoSource = %v, want %v", name, got, tt.want)
		}
	}
}

// A content tree that finds a blob of the archive's image in a registry must
// be able to download it there, so that it does not depend on the archive.
func TestRegistryTreeDownloadsArchiveBlob(t *testing.T) {
	ctx, wk, _ := newCreateTestCtx(t)
	img := writeImageArchive(t)
	loadingArchiveTree(t, ctx, wk, img)

	manifestFile := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(manifestFile, []byte(img.manifestJSON), 0644); err != nil {
		t.Fatal(err)
	}
	datastore, _ := uuid.NewV4()
	parent := &types.BlobStatus{
		Sha256:          configSha,
		State:           types.VERIFIED,
		Path:            manifestFile,
		MediaType:       manifestMediaType,
		DatastoreIDList: []uuid.UUID{datastore},
		RelativeURL:     "repo/image@sha256:" + configSha,
	}

	children := getBlobChildren(ctx, parent)

	if len(children) != 2 {
		t.Fatalf("got %d children, want config and layer", len(children))
	}
	layer := ctx.LookupBlobStatus(img.layer)
	if len(layer.DatastoreIDList) != 1 || layer.DatastoreIDList[0] != datastore ||
		layer.RelativeURL != "repo/image@sha256:"+img.layer {
		t.Errorf("layer downloads from %v %q, want the registry of the tree that found it",
			layer.DatastoreIDList, layer.RelativeURL)
	}
}

// The same holds for a content tree whose root is such a blob.
func TestRegistryTreeDownloadsArchiveRoot(t *testing.T) {
	ctx, wk, _ := newCreateTestCtx(t)
	img := writeImageArchive(t)
	loadingArchiveTree(t, ctx, wk, img)

	config := archiveConfig()
	config.ContentSha256 = img.manifest
	config.RelativeURL = "repo/image@sha256:" + img.manifest
	datastore, _ := uuid.NewV4()
	config.DatastoreIDList = []uuid.UUID{datastore}
	createContentTreeStatus(ctx, config)

	root := ctx.LookupBlobStatus(img.manifest)
	if root.RefCount != 2 || len(root.DatastoreIDList) != 1 || root.RelativeURL != config.RelativeURL {
		t.Errorf("root = %+v, want two references and the registry as its source", root)
	}
}

// newCreateTestCtx adds what createContentTreeStatus needs on top of the
// ingest test context.
func newCreateTestCtx(t *testing.T) (*volumemgrContext, *fakeWorker, *fakeCAS) {
	t.Helper()
	ctx, wk := newIngestTestCtx(t)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logrus.StandardLogger(), log)
	var err error
	ctx.pubDeferredDelete, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DeferredContentDeleteStatus{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx.subVerifyImageStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "verifier",
		TopicImpl: types.VerifyImageStatus{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx.subDatastoreConfig, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName: "zedagent",
		TopicImpl: types.DatastoreConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeCAS()
	ctx.casClient = fake
	return ctx, wk, fake
}

func archiveConfig() types.ContentTreeConfig {
	contentID, _ := uuid.NewV4()
	return types.ContentTreeConfig{
		ContentID:     contentID,
		RelativeURL:   "eve.tar",
		ContentSha256: strings.ToUpper(archiveSha),
		IsLocal:       true,
	}
}
