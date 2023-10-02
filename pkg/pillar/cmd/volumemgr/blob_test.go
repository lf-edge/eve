// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
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
