// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/worker"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// fakeCAS answers the few image queries the content tree state machine makes.
// Any other method panics on the nil embedded interface.
type fakeCAS struct {
	cas.CAS
	images  map[string]string            // reference -> manifest hash
	labels  map[string]map[string]string // reference -> image labels
	blobs   map[string][]string          // blob hash -> children
	content map[string]string            // blob hash -> content
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

func (c *fakeCAS) CheckBlobExists(blobHash string) bool {
	_, ok := c.blobs[blobHash]
	return ok
}

const (
	archiveSha  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	manifestSha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	configSha   = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	layerSha    = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	manifestMediaType = "application/vnd.oci.image.manifest.v1+json"
)

// writeLayoutTar writes a tar that passes for an OCI image layout.
func writeLayoutTar(t *testing.T) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for name, content := range map[string]string{
		"index.json": "{}",
		"oci-layout": `{"imageLayoutVersion":"1.0.0"}`,
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return file
}

// singleBlobTree publishes a content tree holding one blob in the given state.
func singleBlobTree(ctx *volumemgrContext, state types.SwState, path string) *types.ContentTreeStatus {
	blob := &types.BlobStatus{Sha256: archiveSha, State: state, Path: path, RefCount: 1}
	publishBlobStatus(ctx, blob)
	contentID, _ := uuid.NewV4()
	status := &types.ContentTreeStatus{
		ContentID:             contentID,
		DisplayName:           "base-os",
		RelativeURL:           "eve.tar",
		ContentSha256:         archiveSha,
		State:                 state,
		Blobs:                 []string{archiveSha},
		AllDatastoresResolved: true,
	}
	publishContentTreeStatus(ctx, status)
	return status
}

func archiveBlobs() []types.BlobStatus {
	return []types.BlobStatus{
		{Sha256: manifestSha, State: types.LOADED, MediaType: manifestMediaType},
		{Sha256: configSha, State: types.LOADED},
		{Sha256: layerSha, State: types.LOADED},
	}
}

// An OCI archive must reach the ingest worker as the single blob it is, while
// any other file still gets wrapped in a manifest of its own.
func TestArchiveIsNotWrapped(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "rootfs.img")
	if err := os.WriteFile(plain, []byte("hsqs-not-a-tar"), 0644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		path      string
		wantBlobs int
	}{
		{"archive", writeLayoutTar(t), 1},
		{"plain file", plain, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, wk := newIngestTestCtx(t)
			ctx.casClient = newFakeCAS()
			status := singleBlobTree(ctx, types.VERIFIED, tt.path)
			status.State = types.DOWNLOADING

			doUpdateContentTree(ctx, status)

			if status.State != types.LOADING || len(wk.submitted) != 1 {
				t.Fatalf("state = %s, submissions = %d; want LOADING with one ingest job",
					status.State, len(wk.submitted))
			}
			if len(status.Blobs) != tt.wantBlobs {
				t.Fatalf("content tree has %d blobs, want %d: %v",
					len(status.Blobs), tt.wantBlobs, status.Blobs)
			}
			root := ctx.LookupBlobStatus(status.Blobs[0])
			if got := isArchiveTree(status, root); got != (tt.wantBlobs == 1) {
				t.Errorf("isArchiveTree = %v", got)
			}
		})
	}
}

// Once the archive is loaded, the content tree must hold the blobs of the
// image, with a reference on each, and must have let go of the archive.
func TestArchiveIngestSwapsBlobs(t *testing.T) {
	ctx, wk := newIngestTestCtx(t)
	fake := newFakeCAS()
	ctx.casClient = fake
	status := singleBlobTree(ctx, types.LOADING, "/verified/archive")
	ctx.pendingIngest[status.Key()] = true
	ctx.inflightBlobIngests[archiveSha] = status.Key()
	// A layer another content tree already holds.
	publishBlobStatus(ctx, &types.BlobStatus{Sha256: layerSha, State: types.LOADED, RefCount: 1})

	fake.images[status.ReferenceID()] = "sha256:" + manifestSha
	for _, sha := range []string{manifestSha, configSha, layerSha} {
		fake.blobs["sha256:"+sha] = nil
	}
	res := worker.WorkResult{
		Key:         status.Key(),
		Description: casIngestWorkDescription{status: *status, archiveBlobs: archiveBlobs()},
	}
	wk.results[status.Key()] = &res
	if err := processCasIngestWorkResult(ctx, res); err != nil {
		t.Fatal(err)
	}

	got := ctx.LookupContentTreeStatus(status.Key())
	if got.State != types.LOADED {
		t.Errorf("state = %s, want LOADED (error %q)", got.State, got.Error)
	}
	if strings.Join(got.Blobs, ",") != strings.Join([]string{manifestSha, configSha, layerSha}, ",") {
		t.Errorf("blobs = %v, want manifest, config, layer", got.Blobs)
	}
	for sha, wantRefs := range map[string]uint{manifestSha: 1, configSha: 1, layerSha: 2} {
		blob := ctx.LookupBlobStatus(sha)
		if blob == nil || blob.State != types.LOADED || blob.RefCount != wantRefs {
			t.Errorf("blob %s = %+v, want LOADED with %d reference(s)", sha[:4], blob, wantRefs)
		}
	}
	if ctx.LookupBlobStatus(archiveSha) != nil {
		t.Error("the archive blob is still published")
	}
}

// A blob the image shares with another content tree is deleted from the CAS
// when that tree goes away while the ingest runs. The image must not be
// adopted without it; the archive is loaded again.
func TestArchiveIngestLostSharedBlob(t *testing.T) {
	ctx, wk := newIngestTestCtx(t)
	fake := newFakeCAS()
	ctx.casClient = fake
	status := singleBlobTree(ctx, types.LOADING, "/verified/archive")
	ctx.pendingIngest[status.Key()] = true
	ctx.inflightBlobIngests[archiveSha] = status.Key()
	ctx.LookupBlobStatus(archiveSha).State = types.LOADING

	for _, sha := range []string{manifestSha, configSha} {
		fake.blobs["sha256:"+sha] = nil
	}
	res := worker.WorkResult{
		Key:         status.Key(),
		Description: casIngestWorkDescription{status: *status, archiveBlobs: archiveBlobs()},
	}
	wk.results[status.Key()] = &res
	if err := processCasIngestWorkResult(ctx, res); err != nil {
		t.Fatal(err)
	}

	got := ctx.LookupContentTreeStatus(status.Key())
	if len(got.Blobs) != 1 || got.Blobs[0] != archiveSha {
		t.Fatalf("blobs = %v, want the archive only", got.Blobs)
	}
	if blob := ctx.LookupBlobStatus(archiveSha); blob == nil || blob.RefCount != 1 {
		t.Errorf("archive blob = %+v, want it kept with one reference", blob)
	}
	if got.State != types.LOADING || got.HasError() || len(wk.submitted) != 1 {
		t.Errorf("state = %s, error = %q, %d job(s) submitted; want LOADING with the ingest resubmitted",
			got.State, got.Error, len(wk.submitted))
	}
}

// A failed archive ingest must leave the content tree as it was, holding the
// archive, with the error reported.
func TestArchiveIngestError(t *testing.T) {
	ctx, wk := newIngestTestCtx(t)
	ctx.casClient = newFakeCAS()
	status := singleBlobTree(ctx, types.LOADING, "/verified/archive")
	ctx.pendingIngest[status.Key()] = true

	res := worker.WorkResult{
		Key:         status.Key(),
		Error:       errors.New("archive must hold exactly one image"),
		Description: casIngestWorkDescription{status: *status},
	}
	wk.results[status.Key()] = &res
	if err := processCasIngestWorkResult(ctx, res); err != nil {
		t.Fatal(err)
	}

	got := ctx.LookupContentTreeStatus(status.Key())
	if !got.HasError() || got.State != types.LOADING {
		t.Errorf("state = %s, error = %q; want LOADING with the ingest error", got.State, got.Error)
	}
	if len(got.Blobs) != 1 || got.Blobs[0] != archiveSha {
		t.Errorf("blobs = %v, want the archive only", got.Blobs)
	}
	if blob := ctx.LookupBlobStatus(archiveSha); blob == nil || blob.RefCount != 1 {
		t.Errorf("archive blob = %+v, want it kept with one reference", blob)
	}
}

// A result for a content tree that was deleted while the ingest ran must not
// publish anything.
func TestArchiveIngestForDeletedTree(t *testing.T) {
	ctx, _ := newIngestTestCtx(t)
	ctx.casClient = newFakeCAS()
	status := singleBlobTree(ctx, types.LOADING, "/verified/archive")
	unpublishContentTreeStatus(ctx, status)

	res := worker.WorkResult{
		Key:         status.Key(),
		Description: casIngestWorkDescription{status: *status, archiveBlobs: archiveBlobs()},
	}
	if err := processCasIngestWorkResult(ctx, res); err != nil {
		t.Fatal(err)
	}
	for _, sha := range []string{manifestSha, configSha, layerSha} {
		if ctx.LookupBlobStatus(sha) != nil {
			t.Errorf("blob %s was published for a deleted content tree", sha[:4])
		}
	}
}

// loadedImage sets up what a boot finds after an archive was loaded earlier:
// the labelled image in the CAS and a LOADED BlobStatus for each of its blobs.
func loadedImage(ctx *volumemgrContext, fake *fakeCAS, reference string) {
	fake.images[reference] = "sha256:" + manifestSha
	fake.labels[reference] = map[string]string{
		types.EVEOCIArchiveLabel:         archiveSha,
		types.EVEOCIArchiveManifestLabel: "sha256:" + manifestSha,
	}
	fake.blobs["sha256:"+manifestSha] = []string{"sha256:" + configSha, "sha256:" + layerSha}
	fake.content["sha256:"+manifestSha] = fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":"application/vnd.oci.image.config.v1+json",`+
			`"digest":"sha256:%s","size":2},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar",`+
			`"digest":"sha256:%s","size":4}]}`, manifestMediaType, configSha, layerSha)
	for i := range archiveBlobs() {
		blob := archiveBlobs()[i]
		publishBlobStatus(ctx, &blob)
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

func configReference(config types.ContentTreeConfig) string {
	status := types.ContentTreeStatus{ContentID: config.ContentID, RelativeURL: config.RelativeURL}
	return status.ReferenceID()
}

// A content tree for an archive that is already loaded must start from the
// image manifest, so that the archive is not downloaded a second time.
func TestLoadedArchiveIsAdopted(t *testing.T) {
	ctx, wk, fake := newCreateTestCtx(t)
	config := archiveConfig()
	loadedImage(ctx, fake, configReference(config))

	status := createContentTreeStatus(ctx, config)

	if len(status.Blobs) != 1 || status.Blobs[0] != manifestSha {
		t.Fatalf("blobs = %v, want the image manifest", status.Blobs)
	}
	if ctx.LookupBlobStatus(archiveSha) != nil {
		t.Error("a blob was created for the archive, which would download it again")
	}
	if blob := ctx.LookupBlobStatus(manifestSha); blob.RefCount != 1 {
		t.Errorf("manifest has %d references, want 1", blob.RefCount)
	}

	// From the manifest the tree must find the rest of the image in the CAS
	// and reach LOADED without asking for any download.
	status.AllDatastoresResolved = true
	doUpdateContentTree(ctx, status)
	if strings.Join(status.Blobs, ",") != strings.Join([]string{manifestSha, configSha, layerSha}, ",") {
		t.Fatalf("blobs = %v, want manifest, config, layer", status.Blobs)
	}
	if status.State != types.LOADING || len(wk.submitted) != 1 {
		t.Fatalf("state = %s, submissions = %d; want LOADING with one ingest job",
			status.State, len(wk.submitted))
	}
	d := wk.submitted[0].Description.(casIngestWorkDescription)
	if len(d.claimedBlobs) != 0 {
		t.Errorf("ingest job claims %v, want nothing left to load", d.claimedBlobs)
	}
	res := worker.WorkResult{Key: status.Key(), Description: d}
	wk.results[status.Key()] = &res
	if err := processCasIngestWorkResult(ctx, res); err != nil {
		t.Fatal(err)
	}
	if got := ctx.LookupContentTreeStatus(status.Key()); got.State != types.LOADED {
		t.Errorf("state = %s, want LOADED (error %q)", got.State, got.Error)
	}
	for _, sha := range status.Blobs {
		if blob := ctx.LookupBlobStatus(sha); blob.HasDownloaderRef || blob.HasVerifierRef {
			t.Errorf("blob %s was sent to the downloader or verifier", sha[:4])
		}
	}
}

// Anything short of a complete image loaded from this very archive must fall
// back to downloading the archive.
func TestLoadedArchiveNotAdopted(t *testing.T) {
	tests := map[string]func(ctx *volumemgrContext, fake *fakeCAS, reference string){
		"no image": func(ctx *volumemgrContext, fake *fakeCAS, reference string) {
			delete(fake.images, reference)
		},
		"image from another archive": func(ctx *volumemgrContext, fake *fakeCAS, reference string) {
			fake.labels[reference][types.EVEOCIArchiveLabel] = layerSha
		},
		"target replaced by other content": func(ctx *volumemgrContext, fake *fakeCAS, reference string) {
			fake.labels[reference][types.EVEOCIArchiveManifestLabel] = "sha256:" + configSha
		},
		"image without the label": func(ctx *volumemgrContext, fake *fakeCAS, reference string) {
			fake.labels[reference] = nil
		},
		"manifest blob unknown": func(ctx *volumemgrContext, fake *fakeCAS, reference string) {
			ctx.pubBlobStatus.Unpublish(manifestSha)
		},
		"layer missing": func(ctx *volumemgrContext, fake *fakeCAS, reference string) {
			ctx.pubBlobStatus.Unpublish(layerSha)
		},
	}
	for name, breakIt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, _, fake := newCreateTestCtx(t)
			config := archiveConfig()
			loadedImage(ctx, fake, configReference(config))
			breakIt(ctx, fake, configReference(config))

			status := createContentTreeStatus(ctx, config)

			if len(status.Blobs) != 1 || status.Blobs[0] != archiveSha {
				t.Fatalf("blobs = %v, want the archive", status.Blobs)
			}
			if blob := ctx.LookupBlobStatus(archiveSha); blob == nil || blob.State != types.INITIAL {
				t.Errorf("archive blob = %+v, want it created for download", blob)
			}
		})
	}
}
