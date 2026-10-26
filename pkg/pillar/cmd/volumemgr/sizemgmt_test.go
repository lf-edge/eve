// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// TestReservedContentTreeDiskUsageCountsSharedBlobsOnce reproduces two app
// instances using the same image: the controller sends one content tree per
// volume instance, so two content trees reference the same blob sha256, which
// is stored only once in the CAS and must be reserved only once.
func TestReservedContentTreeDiskUsageCountsSharedBlobsOnce(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-volumemgr", 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logrus.StandardLogger(), log)

	pubContentTreeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ContentTreeStatus{},
	})
	if err != nil {
		t.Fatalf("NewPublication(ContentTreeStatus): %v", err)
	}
	pubBlobStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.BlobStatus{},
	})
	if err != nil {
		t.Fatalf("NewPublication(BlobStatus): %v", err)
	}
	ctx := &volumemgrContext{
		pubContentTreeStatus: pubContentTreeStatus,
		pubBlobStatus:        pubBlobStatus,
	}

	const (
		imageSha     = "89588426c668aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		baseSha      = "4a710647bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		pendingSha   = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		imageSize    = int64(125458513920)
		baseSize     = int64(291123200)
		pendingSize  = int64(1 << 30)
		expectedSize = uint64(imageSize + baseSize)
	)
	for _, blob := range []types.BlobStatus{
		{Sha256: imageSha, CurrentSize: imageSize, State: types.LOADED, RefCount: 2},
		{Sha256: baseSha, CurrentSize: baseSize, State: types.LOADED, RefCount: 1},
		{Sha256: pendingSha, CurrentSize: pendingSize, State: types.DOWNLOADING, RefCount: 1},
	} {
		if err := pubBlobStatus.Publish(blob.Key(), blob); err != nil {
			t.Fatalf("Publish(BlobStatus): %v", err)
		}
	}
	for _, ct := range []types.ContentTreeStatus{
		{ContentID: uuid.FromStringOrNil("00000000-0000-0000-0000-000000000001"), Blobs: []string{imageSha}, CurrentSize: imageSize, State: types.LOADED},
		{ContentID: uuid.FromStringOrNil("00000000-0000-0000-0000-000000000002"), Blobs: []string{imageSha}, CurrentSize: imageSize, State: types.LOADED},
		{ContentID: uuid.FromStringOrNil("00000000-0000-0000-0000-000000000003"), Blobs: []string{baseSha}, CurrentSize: baseSize, State: types.LOADED},
		// not LOADED yet: not reserved
		{ContentID: uuid.FromStringOrNil("00000000-0000-0000-0000-000000000004"), Blobs: []string{pendingSha}, CurrentSize: pendingSize, State: types.DOWNLOADING},
	} {
		if err := pubContentTreeStatus.Publish(ct.Key(), ct); err != nil {
			t.Fatalf("Publish(ContentTreeStatus): %v", err)
		}
	}

	if got := reservedContentTreeDiskUsage(ctx); got != expectedSize {
		t.Errorf("reservedContentTreeDiskUsage() = %d, want %d", got, expectedSize)
	}
}
