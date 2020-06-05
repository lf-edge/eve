// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

// Interface to worker to run the create and destroy in separate goroutines

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
)

func TestHandleWorkCreate(t *testing.T) {
	status := types.VolumeStatus{
		VolumeID:     uuid.NewV4(), // XXX future
		AppInstID:    uuid.NewV4(),
		PurgeCounter: 0,
		Origin:       types.OriginTypeDownload,
		Format:       zconfig.Format_QCOW2,
		ObjType:      types.AppImgObj,
	}
	testMatrix := map[string]struct {
		ReadOnly         bool
		SrcLocation      string
		BlobSha256       string
		ExpectFail       bool
		ExpectedLocation string
		ExpectCreated    bool
	}{
		"read-only": {
			ReadOnly:         true,
			SrcLocation:      "/dev/null",
			BlobSha256:       "somesha",
			ExpectFail:       false,
			ExpectedLocation: "/dev/null",
			ExpectCreated:    true,
		},
		"read-write fail": {
			ReadOnly:    false,
			SrcLocation: "/dev/null",
			BlobSha256:  "somesha",
			ExpectFail:  true,
			ExpectedLocation: appRwVolumeName("somesha", status.AppInstID.String(),
				status.PurgeCounter, status.Format, status.Origin, false),

			ExpectCreated: true,
		},
	}
	ctx := initCtx(t)
	ctx.worker = InitHandleWork(&ctx)
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		t.Run(testname, func(t *testing.T) {

			status.ReadOnly = test.ReadOnly
			status.FileLocation = test.SrcLocation
			status.BlobSha256 = test.BlobSha256

			MaybeAddWorkCreate(&ctx, &status)
			assert.Equal(t, ctx.worker.NumPending(), 1)
			MaybeAddWorkCreate(&ctx, &status)
			assert.Equal(t, ctx.worker.NumPending(), 1)

			vr := lookupVolumeWorkResult(&ctx, status.Key())
			assert.Nil(t, vr)

			res := <-ctx.worker.MsgChan()
			HandleWorkResult(&ctx, ctx.worker.Process(res))
			assert.Equal(t, ctx.worker.NumPending(), 0)
			vr = lookupVolumeWorkResult(&ctx, status.Key())
			assert.NotNil(t, vr)
			deleteVolumeWorkResult(&ctx, status.Key())
			DeleteWorkCreate(&ctx, &status)

			if test.ExpectFail {
				assert.NotNil(t, vr.Error, "Error")
				assert.NotEqual(t, vr.ErrorTime, time.Time{},
					"ErrorTime")
			} else {
				assert.Nil(t, vr.Error, "Error")
				assert.Equal(t, vr.ErrorTime, time.Time{},
					"ErrorTime")
			}
			assert.Equal(t, vr.VolumeCreated, test.ExpectCreated,
				"VolumeCreated")
			assert.Equal(t, vr.FileLocation, test.ExpectedLocation,
				"FileLocation")
		})
	}
}

func TestHandleWorkDestroy(t *testing.T) {
	testMatrix := map[string]struct {
		ReadOnly         bool
		SrcLocation      string
		BlobSha256       string
		VolumeCreated    bool
		ExpectFail       bool
		ExpectedLocation string
		ExpectCreated    bool
	}{
		"read-only created": {
			ReadOnly:         true,
			SrcLocation:      "/tmp/xyzzy",
			BlobSha256:       "somesha",
			VolumeCreated:    true,
			ExpectFail:       false,
			ExpectedLocation: "",
			ExpectCreated:    false,
		},
		"read-write created": {
			ReadOnly:         false,
			SrcLocation:      "/tmp/xyzzy",
			BlobSha256:       "somesha",
			VolumeCreated:    true,
			ExpectFail:       true,
			ExpectedLocation: "",
			ExpectCreated:    true,
		},
		"read-write not created": {
			ReadOnly:         false,
			SrcLocation:      "/dev/null",
			BlobSha256:       "somesha",
			VolumeCreated:    false,
			ExpectFail:       false,
			ExpectedLocation: "/dev/null",
			ExpectCreated:    false,
		},
	}
	ctx := initCtx(t)
	ctx.worker = InitHandleWork(&ctx)
	status := types.VolumeStatus{
		VolumeID:     uuid.NewV4(), // XXX future
		AppInstID:    uuid.NewV4(),
		PurgeCounter: 0,
		Origin:       types.OriginTypeDownload,
		Format:       zconfig.Format_QCOW2,
		ObjType:      types.AppImgObj,
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		t.Run(testname, func(t *testing.T) {

			status.ReadOnly = test.ReadOnly
			status.FileLocation = test.SrcLocation
			status.BlobSha256 = test.BlobSha256
			status.VolumeCreated = test.VolumeCreated
			MaybeAddWorkDestroy(&ctx, &status)
			assert.Equal(t, ctx.worker.NumPending(), 1)
			MaybeAddWorkDestroy(&ctx, &status)
			assert.Equal(t, ctx.worker.NumPending(), 1)

			vr := lookupVolumeWorkResult(&ctx, status.Key())
			assert.Nil(t, vr)

			res := <-ctx.worker.MsgChan()
			HandleWorkResult(&ctx, ctx.worker.Process(res))
			assert.Equal(t, ctx.worker.NumPending(), 0)
			vr = lookupVolumeWorkResult(&ctx, status.Key())
			assert.NotNil(t, vr)
			deleteVolumeWorkResult(&ctx, status.Key())
			DeleteWorkDestroy(&ctx, &status)

			if test.ExpectFail {
				assert.NotNil(t, vr.Error, "Error")
				assert.NotEqual(t, vr.ErrorTime, time.Time{},
					"ErrorTime")
			} else {
				assert.Nil(t, vr.Error, "Error")
				assert.Equal(t, vr.ErrorTime, time.Time{},
					"ErrorTime")
			}
			assert.Equal(t, vr.VolumeCreated, test.ExpectCreated,
				"VolumeCreated")
			assert.Equal(t, vr.FileLocation, test.ExpectedLocation,
				"FileLocation")
		})
	}
}

func initCtx(t *testing.T) volumemgrContext {
	ctx := volumemgrContext{}
	ps := pubsub.New(&pubsub.EmptyDriver{})

	pubAppVolumeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		AgentScope: types.AppImgObj,
		TopicType:  types.VolumeStatus{},
	})
	assert.Nil(t, err)
	ctx.pubAppVolumeStatus = pubAppVolumeStatus

	pubContentTreeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		AgentScope: types.AppImgObj,
		TopicType:  types.ContentTreeStatus{},
	})
	assert.Nil(t, err)
	ctx.pubContentTreeStatus = pubContentTreeStatus
	return ctx
}
