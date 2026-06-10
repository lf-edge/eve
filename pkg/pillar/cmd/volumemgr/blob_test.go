// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// TestLookupBlobStatus checks the case when a sha is repeated
// This test only works if /persist and /run are writable
func TestLookupBlobStatus(t *testing.T) {
	if !utils.Writable(types.PersistDir) || !utils.Writable("/run") {
		t.Logf("Required directories not writeable; SKIP")
		return
	}
	pubLogger, pubLog := agentlog.Init(agentName)
	pubLogger.SetLevel(logrus.InfoLevel)
	pubPs := pubsub.New(
		&socketdriver.SocketDriver{
			Logger: pubLogger,
			Log:    pubLog,
		},
		pubLogger, pubLog)
	pub, err := pubPs.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		TopicType:  types.BlobStatus{},
		Persistent: false,
	})
	if err != nil {
		t.Fatalf("unable to publish: %v", err)
	}
	ctx := volumemgrContext{
		pubBlobStatus: pub,
	}
	blob1 := types.BlobStatus{
		Sha256:         "sha1",
		HasVerifierRef: true,
	}
	blob2 := types.BlobStatus{
		Sha256:         "sha2",
		HasVerifierRef: true,
	}
	pub.Publish(blob1.Key(), blob1)
	pub.Publish(blob2.Key(), blob2)

	shas := []string{"sha0", "sha1", "sha2", "sha1", "sha3"}
	blobPtrs := lookupBlobStatuses(&ctx, shas...)
	assert.NotNil(t, blobPtrs)
	for _, blobPtr := range blobPtrs {
		assert.True(t, blobPtr.HasVerifierRef)
	}
	assert.Equal(t, 3, len(blobPtrs))
	// Check that changing [0] affects [2]
	blobPtrs[0].HasVerifierRef = false
	assert.False(t, blobPtrs[0].HasVerifierRef)
	assert.True(t, blobPtrs[1].HasVerifierRef)
	assert.False(t, blobPtrs[2].HasVerifierRef)
}

// blobInfo is a tiny constructor that mirrors the fields of cas.BlobInfo we
// care about — keeps the test cases readable without dragging cas details in.
func blobInfo(digest string, labels map[string]string) *cas.BlobInfo {
	return &cas.BlobInfo{Digest: digest, Labels: labels}
}

func TestTransitivelyEVEDownloaded_NoSeeds(t *testing.T) {
	got := transitivelyEVEDownloaded([]*cas.BlobInfo{
		blobInfo("sha256:a", nil),
		blobInfo("sha256:b", nil),
	})
	assert.Empty(t, got, "no eve-downloaded labels → no eve-owned blobs")
}

func TestTransitivelyEVEDownloaded_DirectLabelOnly(t *testing.T) {
	got := transitivelyEVEDownloaded([]*cas.BlobInfo{
		blobInfo("sha256:a", map[string]string{types.EVEDownloadedLabel: "true"}),
		blobInfo("sha256:b", nil),
	})
	assert.True(t, got["sha256:a"], "directly-labeled blob is eve-owned")
	assert.False(t, got["sha256:b"], "unrelated blob is not eve-owned")
	assert.Len(t, got, 1)
}

// TestTransitivelyEVEDownloaded_ManifestPlusLayers is the load-bearing case:
// a manifest blob carries the eve-downloaded label AND containerd.io/
// gc.ref.content.* labels pointing at each layer. The layers themselves
// carry no labels — same shape pillar's CAS writes on EVE-k after pulling
// an OCI image (verified empirically against /persist/vault/containerd's
// metadata DB, 2026-06-09).
func TestTransitivelyEVEDownloaded_ManifestPlusLayers(t *testing.T) {
	manifestLabels := map[string]string{
		types.EVEDownloadedLabel:              "true",
		"containerd.io/gc.ref.content.0":      "sha256:layer1",
		"containerd.io/gc.ref.content.1":      "sha256:layer2",
		"containerd.io/gc.ref.content.config": "sha256:cfg",
	}
	got := transitivelyEVEDownloaded([]*cas.BlobInfo{
		blobInfo("sha256:manifest", manifestLabels),
		blobInfo("sha256:layer1", nil),
		blobInfo("sha256:layer2", nil),
		blobInfo("sha256:cfg", nil),
		blobInfo("sha256:unrelated", nil),
	})
	assert.True(t, got["sha256:manifest"])
	assert.True(t, got["sha256:layer1"], "layer1 reached via gc.ref.content.0")
	assert.True(t, got["sha256:layer2"], "layer2 reached via gc.ref.content.1")
	assert.True(t, got["sha256:cfg"], "config reached via gc.ref.content.config")
	assert.False(t, got["sha256:unrelated"])
}

// TestTransitivelyEVEDownloaded_OCIImageIndex covers multi-arch /
// imageIndex shapes where an index points at manifests which in turn
// point at layers. The eve-downloaded label is typically on the index;
// the walk should traverse through manifest entries to the layers.
func TestTransitivelyEVEDownloaded_OCIImageIndex(t *testing.T) {
	got := transitivelyEVEDownloaded([]*cas.BlobInfo{
		blobInfo("sha256:index", map[string]string{
			types.EVEDownloadedLabel:         "true",
			"containerd.io/gc.ref.content.0": "sha256:manifestAmd64",
			"containerd.io/gc.ref.content.1": "sha256:manifestArm64",
		}),
		blobInfo("sha256:manifestAmd64", map[string]string{
			"containerd.io/gc.ref.content.l.0": "sha256:layerAmd64a",
			"containerd.io/gc.ref.content.l.1": "sha256:layerAmd64b",
		}),
		blobInfo("sha256:manifestArm64", map[string]string{
			"containerd.io/gc.ref.content.l.0": "sha256:layerArm64a",
		}),
		blobInfo("sha256:layerAmd64a", nil),
		blobInfo("sha256:layerAmd64b", nil),
		blobInfo("sha256:layerArm64a", nil),
	})
	for _, d := range []string{
		"sha256:index", "sha256:manifestAmd64", "sha256:manifestArm64",
		"sha256:layerAmd64a", "sha256:layerAmd64b", "sha256:layerArm64a",
	} {
		assert.True(t, got[d], "expected %s to be eve-owned via transitive walk", d)
	}
	assert.Len(t, got, 6)
}

// TestTransitivelyEVEDownloaded_DanglingRef guards against a manifest
// whose gc.ref.content.* label points at a digest that isn't itself in the
// blobInfoList (e.g. a long-pruned layer). The walk should not panic and
// should not include the dangling digest in the owned set.
func TestTransitivelyEVEDownloaded_DanglingRef(t *testing.T) {
	got := transitivelyEVEDownloaded([]*cas.BlobInfo{
		blobInfo("sha256:manifest", map[string]string{
			types.EVEDownloadedLabel:         "true",
			"containerd.io/gc.ref.content.0": "sha256:missing",
		}),
	})
	assert.True(t, got["sha256:manifest"])
	assert.False(t, got["sha256:missing"], "dangling ref not in blob list → not owned")
	assert.Len(t, got, 1)
}

// TestTransitivelyEVEDownloaded_NoFalsePositiveFromForeignManifest
// guards against the bug where a k3s-pulled image's manifest holds
// gc.ref.content.* labels pointing at the same digests as a pillar
// blob (in some hypothetical collision). Since the k3s manifest does
// NOT carry the eve-downloaded label, the walk doesn't seed from it and
// the pillar blob remains the only seed.
func TestTransitivelyEVEDownloaded_NoFalsePositiveFromForeignManifest(t *testing.T) {
	got := transitivelyEVEDownloaded([]*cas.BlobInfo{
		blobInfo("sha256:k3sManifest", map[string]string{
			"containerd.io/gc.ref.content.0": "sha256:shared",
		}),
		blobInfo("sha256:shared", nil),
	})
	assert.Empty(t, got, "neither blob carries eve-downloaded → none owned")
}
