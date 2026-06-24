// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cas

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// newTestContainerdCAS connects to the host containerd. These tests exercise
// the real content store, so they only run on systems that have a functional
// containerd and are skipped otherwise (same convention as containerd/oci_test.go).
func newTestContainerdCAS(t *testing.T) *containerdCAS {
	t.Helper()
	client, err := containerd.NewContainerdClient(false)
	if err != nil {
		t.Skipf("test must be run on a system with a functional containerd: %v", err)
	}
	return &containerdCAS{ctrdClient: client}
}

func leafBlob(sha string, data []byte, path string) types.BlobStatus {
	return types.BlobStatus{
		Sha256: sha,
		Size:   uint64(len(data)),
		Path:   path,
		// State must be < LOADED, otherwise IngestBlob short-circuits before
		// ever opening the file, which is the path under test here.
		State:     types.VERIFIED,
		MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
	}
}

// TestIngestBlobMissingFileAlreadyInCAS verifies that IngestBlob is idempotent
// when the verified blob file is gone but the blob is already in the content
// store. A layer blob shared by multiple content trees is backed by a single
// verified file that is removed once the blob has been committed to the content
// store; a content tree that ingests the same blob afterwards finds the file
// missing. Since the content is already present, IngestBlob must report the
// blob as loaded rather than fail.
func TestIngestBlobMissingFileAlreadyInCAS(t *testing.T) {
	c := newTestContainerdCAS(t)
	// Registered first so it runs last (t.Cleanup is LIFO): the blob removal
	// below must run while the client is still open.
	t.Cleanup(func() { _ = c.CloseClient() })

	data := []byte("shared layer blob contents")
	sum := sha256.Sum256(data)
	blobSha := hex.EncodeToString(sum[:])
	blobHash := fmt.Sprintf("sha256:%s", blobSha)

	blobPath := filepath.Join(t.TempDir(), "verified-blob")
	if err := os.WriteFile(blobPath, data, 0644); err != nil {
		t.Fatalf("failed to write blob file: %v", err)
	}
	t.Cleanup(func() { _ = c.RemoveBlob(blobHash) })

	// A single lease keeps the blob referenced (and out of containerd GC) across
	// both ingests, mirroring the image reference that holds it in production.
	ctx, deleteLease, err := c.ctrdClient.CtrNewUserServicesCtxWithLease()
	if err != nil {
		t.Fatalf("failed to create lease context: %v", err)
	}
	defer deleteLease()

	// First load: ingests the blob into CAS from the verified file.
	loaded, err := c.IngestBlob(ctx, leafBlob(blobSha, data, blobPath))
	if err != nil {
		t.Fatalf("first IngestBlob failed: %v", err)
	}
	if len(loaded) != 1 || loaded[0].State != types.LOADED {
		t.Fatalf("expected blob LOADED after first ingest, got %+v", loaded)
	}
	if !c.CheckBlobExists(blobHash) {
		t.Fatalf("blob %s not present in CAS after first ingest", blobHash)
	}

	// Simulate the verifier deleting the shared verified file once the first
	// tree finished loading it.
	if err := os.Remove(blobPath); err != nil {
		t.Fatalf("failed to remove blob file: %v", err)
	}

	// Second load from a fresh BlobStatus whose file is now gone. The blob is
	// already in CAS, so this must succeed.
	loaded2, err := c.IngestBlob(ctx, leafBlob(blobSha, data, blobPath))
	if err != nil {
		t.Fatalf("second IngestBlob failed although the blob is already present in CAS: %v", err)
	}
	if len(loaded2) != 1 || loaded2[0].State != types.LOADED {
		t.Fatalf("expected blob LOADED on second ingest, got %+v", loaded2)
	}
}

// TestIngestBlobMissingFileNotInCAS verifies the fallback does not swallow
// genuine errors: a missing file for a blob that is NOT in CAS must still fail.
func TestIngestBlobMissingFileNotInCAS(t *testing.T) {
	c := newTestContainerdCAS(t)
	defer c.CloseClient()

	// A sha that is not present in CAS, paired with a non-existent file.
	data := []byte("blob that was never ingested")
	sum := sha256.Sum256(data)
	blobSha := hex.EncodeToString(sum[:])
	if c.CheckBlobExists(fmt.Sprintf("sha256:%s", blobSha)) {
		t.Skipf("unexpected: blob %s already present in CAS", blobSha)
	}

	ctx, deleteLease, err := c.ctrdClient.CtrNewUserServicesCtxWithLease()
	if err != nil {
		t.Fatalf("failed to create lease context: %v", err)
	}
	defer deleteLease()

	missingPath := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := c.IngestBlob(ctx, leafBlob(blobSha, data, missingPath)); err == nil {
		t.Fatalf("expected IngestBlob to fail for a missing file not in CAS, got nil")
	}
}
