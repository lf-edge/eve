// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

func TestIsErrorSourceOnPubSub(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "volumemgr", 0)
	status := &types.VolumeStatus{}
	errStr := "test1"
	status.SetErrorWithSource(errStr, types.ContentTreeStatus{}, time.Now())
	log.Functionf("set error %s", status.Error)
	ctx := initStatusCtx(t)
	publishVolumeStatus(ctx, status)
	status = ctx.LookupVolumeStatus(status.Key())
	assert.True(t, status.HasError())
	assert.True(t, status.IsErrorSource(types.ContentTreeStatus{}),
		"Pubsub error source type: %T", status.ErrorSourceType)
	assert.False(t, status.IsErrorSource(types.VolumeStatus{}),
		"Pubsub error source type: %T", status.ErrorSourceType)
	assert.Equal(t, errStr, status.Error)
	status.ClearErrorWithSource()
	log.Functionf("cleared error %s", status.Error)
	assert.False(t, status.IsErrorSource(types.ContentTreeStatus{}),
		"Pubsub error source type: %T", status.ErrorSourceType)
	assert.Equal(t, "", status.Error)
}

func initStatusCtx(t *testing.T) *volumemgrContext {
	ctx := &volumemgrContext{}
	logger := logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, "test", 1234)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	pubVolumeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumeStatus{},
	})
	assert.Nil(t, err)
	ctx.pubVolumeStatus = pubVolumeStatus
	return ctx
}

// initVolumeModifyCtx builds on initStatusCtx with the additional
// subscriptions/config handleVolumeModify's call chain (updateVolumeStatusRefCount,
// doUpdateVol, updateVolumeRefStatus) touches, so handleVolumeModify can be
// exercised directly instead of only its pubsub-facing helpers.
func initVolumeModifyCtx(t *testing.T) *volumemgrContext {
	ctx := initStatusCtx(t)
	ctx.globalConfig = types.DefaultConfigItemValueMap()
	ctx.volumeConfigCreateDeferredMap = make(map[string]*types.VolumeConfig)

	ps := pubsub.New(&pubsub.EmptyDriver{}, logrus.StandardLogger(), log)

	subVolumeConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.VolumeConfig{},
		Ctx:         ctx,
	})
	assert.Nil(t, err)
	ctx.subVolumeConfig = subVolumeConfig
	subVolumeConfig.Activate()

	subVolumeRefConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedmanager",
		MyAgentName: agentName,
		TopicImpl:   types.VolumeRefConfig{},
		Ctx:         ctx,
	})
	assert.Nil(t, err)
	ctx.subVolumeRefConfig = subVolumeRefConfig
	subVolumeRefConfig.Activate()

	pubContentTreeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ContentTreeStatus{},
	})
	assert.Nil(t, err)
	ctx.pubContentTreeStatus = pubContentTreeStatus

	return ctx
}

// TestHandleVolumeModifyResyncsIsReplicated is a regression test for a cluster
// (ENC) bug: when a "replace node" operation reassigns a volume's Designated
// Node ID to this node, zedagent republishes VolumeConfig with IsReplicated
// flipped to false, but handleVolumeModify never copied the new value onto
// the already-existing VolumeStatus -- it stayed frozen at whatever value was
// set when the status was first created. Since DestroyVolume() gates PVC
// deletion on VolumeStatus.IsReplicated, a stale "true" meant the
// newly-designated node silently skipped deleting the PVC on Delete.
func TestHandleVolumeModifyResyncsIsReplicated(t *testing.T) {
	ctx := initVolumeModifyCtx(t)

	volumeID := uuid.Must(uuid.NewV4())
	contentID := uuid.Must(uuid.NewV4())

	// Simulate this node's pre-fix state: it was a replica (the volume's PVC
	// lives on a different, designated node), already fully reconciled.
	status := &types.VolumeStatus{
		VolumeID:     volumeID,
		ContentID:    contentID,
		MaxVolSize:   1024,
		State:        types.CREATED_VOLUME,
		SubState:     types.VolumeSubStateCreated,
		IsReplicated: true,
	}
	publishVolumeStatus(ctx, status)

	// Controller reassigns DNID to this node: same volume, same content,
	// only IsReplicated flips to false.
	config := types.VolumeConfig{
		VolumeID:     volumeID,
		ContentID:    contentID,
		MaxVolSize:   1024,
		IsReplicated: false,
	}

	handleVolumeModify(ctx, config.Key(), config, types.VolumeConfig{})

	got := ctx.LookupVolumeStatus(config.Key())
	assert.NotNil(t, got)
	assert.False(t, got.IsReplicated,
		"VolumeStatus.IsReplicated must be resynced from VolumeConfig on modify, not frozen at creation time")
}

// A native container deployed by tag, whose digest was latched at an
// earlier boot.
const (
	testImageTagURL = "lfedge/evetest-logger-ctr:1.0"
	testImageDigest = "9e27c1d1bdf65a0d6a4aa0f4c7cd7d0b5b8e2e5c2a6b0f86a3c1f8e9d7b6a5c4"
)

// initReferenceNameCtx extends initVolumeModifyCtx with what naming the
// image of a volume touches: latched digests and VolumeRefStatus, and a
// VolumeRefConfig subscription over the memory driver, so that
// updateVolumeRefStatus finds the app's reference. Returns the
// VolumeRefConfig publication to publish with.
func initReferenceNameCtx(t *testing.T) (*volumemgrContext, pubsub.Publication) {
	t.Helper()
	ctx := initVolumeModifyCtx(t)
	logger := logrus.StandardLogger()

	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)
	for _, p := range []struct {
		pub   *pubsub.Publication
		topic interface{}
	}{
		{&ctx.pubContentTreeToHash, types.AppAndImageToHash{}},
		{&ctx.pubVolumeRefStatus, types.VolumeRefStatus{}},
	} {
		pub, err := ps.NewPublication(pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: p.topic,
		})
		assert.NoError(t, err)
		*p.pub = pub
	}

	memPs := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	pubVolumeRefConfig, err := memPs.NewPublication(pubsub.PublicationOptions{
		AgentName: "zedmanager",
		TopicType: types.VolumeRefConfig{},
	})
	assert.NoError(t, err)
	subVolumeRefConfig, err := memPs.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedmanager",
		MyAgentName: agentName,
		TopicImpl:   types.VolumeRefConfig{},
		Ctx:         ctx,
	})
	assert.NoError(t, err)
	assert.NoError(t, subVolumeRefConfig.Activate())
	ctx.subVolumeRefConfig = subVolumeRefConfig
	return ctx, pubVolumeRefConfig
}

// newTestContentTree publishes the content tree as it stands after a
// reboot, before its DatastoreConfig arrives: named by its tag, with no
// digest yet.
func newTestContentTree(t *testing.T, ctx *volumemgrContext) *types.ContentTreeStatus {
	t.Helper()
	ct := &types.ContentTreeStatus{
		ContentID:     mustNewUUID(t),
		RelativeURL:   testImageTagURL,
		Format:        zconfig.Format_CONTAINER,
		IsOCIRegistry: true,
		HVTypeKube:    true,
		State:         types.INITIAL,
	}
	publishContentTreeStatus(ctx, ct)
	return ct
}

// latchTestContentTree does what doUpdateContentTree does once the
// tree's datastore is known: take the digest latched at an earlier boot.
func latchTestContentTree(ctx *volumemgrContext, ct *types.ContentTreeStatus) {
	latchContentTreeHash(ctx, ct.ContentID, testImageDigest, uint32(ct.GenerationCounter))
	maybeLatchContentTreeHash(ctx, ct)
	publishContentTreeStatus(ctx, ct)
}

// testImageName is the name the image is created under in containerd.
func testImageName(ct *types.ContentTreeStatus) string {
	return types.KubeContainerImagePrefix + ct.ContentID.String() +
		"-lfedge/evetest-logger-ctr@sha256:" + testImageDigest
}

// newCreatedTestVolume is the volume of the tree as handleDeferredVolumeCreate
// finds it at boot: created already.
func newCreatedTestVolume(t *testing.T, ctx *volumemgrContext,
	ct *types.ContentTreeStatus) *types.VolumeStatus {
	t.Helper()
	status := &types.VolumeStatus{
		VolumeID:                mustNewUUID(t),
		ContentID:               ct.ContentID,
		VolumeContentOriginType: zconfig.VolumeContentOriginType_VCOT_DOWNLOAD,
		IsNativeContainer:       true,
		State:                   types.CREATED_VOLUME,
		SubState:                types.VolumeSubStateCreated,
	}
	setFromContentTree(ctx, status)
	return status
}

// TestVolumeCreatedBeforeContentTreeHasDigest is the regression test for
// a native container on EVE-k that did not start after a reboot: its
// volume was found created before the content tree had its digest, took
// the name of the image from the tag, and the pod asked containerd for an
// image that exists only under the name with the digest
// (ErrImageNeverPull). The volume must have no name until the tree has
// its digest; zedmanager holds the app until it has one.
func TestVolumeCreatedBeforeContentTreeHasDigest(t *testing.T) {
	ctx, _ := initReferenceNameCtx(t)
	ct := newTestContentTree(t, ctx)

	status := newCreatedTestVolume(t, ctx, ct)
	assert.Empty(t, status.ReferenceName,
		"the image must not be named by its tag (%s)", ct.ReferenceID())
	assert.Equal(t, zconfig.Format_CONTAINER, status.ContentFormat,
		"the volume must still say it holds a container, which zedmanager waits on")

	changed, done := doUpdateVol(ctx, status)
	assert.False(t, changed, "nothing to change before the tree has its digest")
	assert.True(t, done)
	assert.Empty(t, status.ReferenceName)
}

// TestDoUpdateVolNamesCreatedVolumeOnceContentTreeHasDigest checks that
// a created volume found before its content tree had its digest is named
// once the tree has it, and that doUpdateVol reports the change so that
// its caller republishes the VolumeStatus and VolumeRefStatus.
func TestDoUpdateVolNamesCreatedVolumeOnceContentTreeHasDigest(t *testing.T) {
	ctx, _ := initReferenceNameCtx(t)
	ct := newTestContentTree(t, ctx)
	status := newCreatedTestVolume(t, ctx, ct)
	assert.Empty(t, status.ReferenceName)

	latchTestContentTree(ctx, ct)
	changed, done := doUpdateVol(ctx, status)
	assert.True(t, changed, "the name changed, so the status must be republished")
	assert.True(t, done)
	assert.Equal(t, testImageName(ct), status.ReferenceName)

	changed, _ = doUpdateVol(ctx, status)
	assert.False(t, changed, "named already: nothing to republish")
}

// TestVolumeRefStatusNamedOnceContentTreeHasDigest follows the race
// through to what zedmanager reads: the volume is found created before
// the DatastoreConfig arrives, and the app's VolumeRefStatus is published
// without a name. The test then stands in for the DatastoreConfig step:
// it latches and publishes the tree and calls
// updateVolumeStatusFromContentID, as updateStatusByDatastore does after
// doUpdateContentTree, rather than running updateStatusByDatastore.
func TestVolumeRefStatusNamedOnceContentTreeHasDigest(t *testing.T) {
	ctx, pubVolumeRefConfig := initReferenceNameCtx(t)
	ct := newTestContentTree(t, ctx)
	status := newCreatedTestVolume(t, ctx, ct)
	publishVolumeStatus(ctx, status)

	vrc := types.VolumeRefConfig{VolumeID: status.VolumeID, AppUUID: mustNewUUID(t)}
	assert.NoError(t, pubVolumeRefConfig.Publish(vrc.Key(), vrc))
	ctx.subVolumeRefConfig.ProcessChange(<-ctx.subVolumeRefConfig.MsgChan())
	updateVolumeRefStatus(ctx, status)
	vrs := lookupVolumeRefStatus(ctx, vrc.Key())
	if assert.NotNil(t, vrs) {
		assert.Empty(t, vrs.ReferenceName)
	}

	latchTestContentTree(ctx, ct)
	updateVolumeStatusFromContentID(ctx, ct.ContentID)

	vs := ctx.LookupVolumeStatus(status.Key())
	if assert.NotNil(t, vs) {
		assert.Equal(t, testImageName(ct), vs.ReferenceName)
	}
	vrs = lookupVolumeRefStatus(ctx, vrc.Key())
	if assert.NotNil(t, vrs) {
		assert.Equal(t, testImageName(ct), vrs.ReferenceName)
	}
}

// TestDoUpdateVolKeepsCreatedVolumeImageName checks that a created volume
// that has a name keeps it when its content tree comes to name another
// image, as after a changed ContentTreeConfig for the same content ID:
// the image of a created volume must not change under it, least of all
// to an image that may not be in containerd yet.
func TestDoUpdateVolKeepsCreatedVolumeImageName(t *testing.T) {
	ctx, _ := initReferenceNameCtx(t)
	ct := newTestContentTree(t, ctx)
	latchTestContentTree(ctx, ct)
	status := newCreatedTestVolume(t, ctx, ct)
	assert.Equal(t, testImageName(ct), status.ReferenceName)

	const otherDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	changedCt := *ct
	changedCt.ContentSha256 = otherDigest
	changedCt.RelativeURL = "lfedge/evetest-logger-ctr@sha256:" + otherDigest
	publishContentTreeStatus(ctx, &changedCt)
	assert.NotEqual(t, status.ReferenceName, volumeReferenceName(&changedCt))

	changed, done := doUpdateVol(ctx, status)
	assert.False(t, changed)
	assert.True(t, done)
	assert.Equal(t, testImageName(ct), status.ReferenceName)
}

// TestVolumeCreatedAfterContentTreeHasDigest is the order that always
// worked: the DatastoreConfig arrives first, the tree takes its digest,
// and the volume found at boot is named by it right away.
func TestVolumeCreatedAfterContentTreeHasDigest(t *testing.T) {
	ctx, _ := initReferenceNameCtx(t)
	ct := newTestContentTree(t, ctx)
	latchTestContentTree(ctx, ct)

	status := newCreatedTestVolume(t, ctx, ct)
	assert.Equal(t, testImageName(ct), status.ReferenceName)
	assert.Equal(t, zconfig.Format_CONTAINER, status.ContentFormat)

	changed, done := doUpdateVol(ctx, status)
	assert.False(t, changed)
	assert.True(t, done)
	assert.Equal(t, testImageName(ct), status.ReferenceName)
}
