// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/volumehandlers"
	"github.com/lf-edge/eve/pkg/pillar/worker"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const workTestBlock = "testblock"

var (
	snapshotTestApp      = uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	snapshotTestOtherApp = uuid.Must(uuid.FromString("33333333-3333-3333-3333-333333333333"))
)

// snapshotConfigs stands in for a subscription to what zedmanager or zedagent
// publish.
type snapshotConfigs struct {
	pubsub.Subscription
	items map[string]interface{}
}

func (c *snapshotConfigs) Get(key string) (interface{}, error) {
	if item, ok := c.items[key]; ok {
		return item, nil
	}
	return nil, errors.New("not found")
}

func (c *snapshotConfigs) GetAll() map[string]interface{} {
	return c.items
}

// fakeSnapshotVolumes replaces the volume handlers and the records on disk.
// It notes the calls made as "<action> <volume>", fails those listed in
// fail, and holds every call back while block is set.
type fakeSnapshotVolumes struct {
	sync.Mutex
	calls []string
	// records has what is saved for each snapshot
	records map[string]types.VolumesSnapshotStatus
	// saveFails and removeFails make the record of the snapshot unwritable
	saveFails   map[string]bool
	removeFails map[string]bool
	fail        map[string]error
	block       chan struct{}
}

func (f *fakeSnapshotVolumes) call(action string, volume *types.VolumeStatus) error {
	if f.block != nil {
		<-f.block
	}
	f.Lock()
	defer f.Unlock()
	name := action + " " + volume.DisplayName
	f.calls = append(f.calls, name)
	return f.fail[name]
}

func (f *fakeSnapshotVolumes) made() []string {
	f.Lock()
	defer f.Unlock()
	return append([]string(nil), f.calls...)
}

type fakeSnapshotHandler struct {
	volumehandlers.VolumeHandler
	fake   *fakeSnapshotVolumes
	volume *types.VolumeStatus
}

func (h fakeSnapshotHandler) CreateSnapshot() (interface{}, time.Time, error) {
	if err := h.fake.call("create", h.volume); err != nil {
		return "", time.Time{}, err
	}
	return "meta of " + h.volume.DisplayName, time.Unix(1, 0), nil
}

func (h fakeSnapshotHandler) RollbackToSnapshot(interface{}) error {
	return h.fake.call("rollback", h.volume)
}

func (h fakeSnapshotHandler) DeleteSnapshot(interface{}) error {
	return h.fake.call("delete", h.volume)
}

// newSnapshotTestContext returns a volumemgr that runs: zedagent has published
// the volumes and zedmanager its snapshot configs.
func newSnapshotTestContext(t *testing.T) (*volumemgrContext, pubsub.Publication, *fakeSnapshotVolumes) {
	t.Helper()
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	newPub := func(topic interface{}) pubsub.Publication {
		pub, err := ps.NewPublication(pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: topic,
		})
		assert.NoError(t, err)
		return pub
	}
	pub := newPub(types.VolumesSnapshotStatus{})
	ctx := &volumemgrContext{
		pubVolumesSnapStatus:     pub,
		subVolumesSnapConfig:     &snapshotConfigs{items: map[string]interface{}{}},
		pubVolumeStatus:          newPub(types.VolumeStatus{}),
		pubVolumeRefStatus:       newPub(types.VolumeRefStatus{}),
		subVolumeRefConfig:       &snapshotConfigs{items: map[string]interface{}{}},
		subVolumeConfig:          &snapshotConfigs{items: map[string]interface{}{}},
		pubContentTreeStatus:     newPub(types.ContentTreeStatus{}),
		snapshotOpInFlight:       make(map[uuid.UUID]string),
		snapshotsWaiting:         make(map[string]bool),
		snapshotDeletionRetries:  make(map[string]bool),
		snapshotConfigsComplete:  true,
		signalledRestartedStatus: true,
	}
	// workTestBlock keeps a worker busy until told.
	ctx.worker = worker.NewPool(log, ctx, 0, map[string]worker.Handler{
		workSnapshot: {Request: snapshotWorker, Response: processSnapshotResult},
		workTestBlock: {
			Request: func(_ interface{}, w worker.Work) worker.WorkResult {
				<-w.Description.(chan struct{})
				return worker.WorkResult{Key: w.Key}
			},
			Response: func(ctxPtr interface{}, _ worker.WorkResult) error {
				driveSnapshots(ctxPtr.(*volumemgrContext))
				return nil
			},
		},
	})
	t.Cleanup(ctx.worker.Done)

	fake := &fakeSnapshotVolumes{
		fail:        map[string]error{},
		records:     map[string]types.VolumesSnapshotStatus{},
		saveFails:   map[string]bool{},
		removeFails: map[string]bool{},
	}
	savedHandler, savedSave, savedRemove := getSnapshotVolumeHandler, saveVolumesSnapshotStatus, removeVolumesSnapshotStatus
	getSnapshotVolumeHandler = func(_ *volumemgrContext, status *types.VolumeStatus) volumehandlers.VolumeHandler {
		return fakeSnapshotHandler{fake: fake, volume: status}
	}
	saveVolumesSnapshotStatus = func(snapshotID string, status *types.VolumesSnapshotStatus) error {
		if fake.saveFails[snapshotID] {
			return errors.New("disk full")
		}
		record := *status
		record.VolumeSnapshotMeta = make(map[string]interface{}, len(status.VolumeSnapshotMeta))
		for volumeID, meta := range status.VolumeSnapshotMeta {
			record.VolumeSnapshotMeta[volumeID] = meta
		}
		fake.records[snapshotID] = record
		return nil
	}
	removeVolumesSnapshotStatus = func(snapshotID string) error {
		if fake.removeFails[snapshotID] {
			return errors.New("read-only file system")
		}
		delete(fake.records, snapshotID)
		return nil
	}
	t.Cleanup(func() {
		getSnapshotVolumeHandler, saveVolumesSnapshotStatus, removeVolumesSnapshotStatus = savedHandler, savedSave, savedRemove
	})
	return ctx, pub, fake
}

// snapshotTestVolumes publishes the named volumes, which the test app refers
// to, and returns their IDs.
func snapshotTestVolumes(t *testing.T, ctx *volumemgrContext, names ...string) []uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	for i, name := range names {
		id := uuid.Must(uuid.FromString(fmt.Sprintf("22222222-2222-2222-2222-%012d", i)))
		status := types.VolumeStatus{VolumeID: id, DisplayName: name, State: types.CREATED_VOLUME}
		assert.NoError(t, ctx.pubVolumeStatus.Publish(status.Key(), status))
		ref := types.VolumeRefConfig{VolumeID: id, AppUUID: snapshotTestApp}
		ctx.subVolumeRefConfig.(*snapshotConfigs).items[ref.Key()] = ref
		ids = append(ids, id)
	}
	return ids
}

// snapshotMeta is the VolumeSnapshotMeta of a snapshot of the given volumes.
func snapshotMeta(ids []uuid.UUID) map[string]interface{} {
	meta := map[string]interface{}{}
	for _, id := range ids {
		meta[id.String()] = "meta"
	}
	return meta
}

func snapshotTestConfig(snapshotID string, ids []uuid.UUID, rollbackCount int) types.VolumesSnapshotConfig {
	return types.VolumesSnapshotConfig{
		SnapshotID: snapshotID, AppUUID: snapshotTestApp, VolumeIDs: ids, RollbackCount: rollbackCount,
	}
}

// wantSnapshot publishes the config as zedmanager does: the snapshot is to
// exist, and to be rolled back to if the count says so.
func wantSnapshot(ctx *volumemgrContext, config types.VolumesSnapshotConfig) {
	configs := ctx.subVolumesSnapConfig.(*snapshotConfigs)
	_, known := configs.items[config.Key()]
	configs.items[config.Key()] = config
	if known {
		handleVolumesSnapshotConfigModify(ctx, config.Key(), config, config)
	} else {
		handleVolumesSnapshotConfigCreate(ctx, config.Key(), config)
	}
}

// unwantSnapshot takes the config away as zedmanager does: the snapshot is to
// be deleted.
func unwantSnapshot(ctx *volumemgrContext, snapshotID string) {
	configs := ctx.subVolumesSnapConfig.(*snapshotConfigs)
	config := configs.items[snapshotID]
	delete(configs.items, snapshotID)
	handleVolumesSnapshotConfigDelete(ctx, snapshotID, config)
}

// existingSnapshot publishes a snapshot of the given volumes that was
// created earlier, and that zedmanager wants to keep.
func existingSnapshot(ctx *volumemgrContext, snapshotID string, ids []uuid.UUID) {
	ctx.subVolumesSnapConfig.(*snapshotConfigs).items[snapshotID] = snapshotTestConfig(snapshotID, ids, 0)
	_ = publishVolumesSnapshotStatus(ctx, &types.VolumesSnapshotStatus{
		SnapshotID:         snapshotID,
		AppUUID:            snapshotTestApp,
		VolumeSnapshotMeta: snapshotMeta(ids),
		State:              types.VolumesSnapshotStateCreated,
		RollbackCountKnown: true,
	})
}

// finishSnapshotWork does what the main loop does with the result of a worker.
func finishSnapshotWork(t *testing.T, ctx *volumemgrContext) {
	t.Helper()
	select {
	case res := <-ctx.worker.MsgChan():
		assert.NoError(t, res.Process(ctx, true))
	case <-time.After(10 * time.Second):
		t.Fatal("no result from the worker")
	}
}

// snapshotStatus returns the published status of the snapshot, and whether it
// is published at all.
func snapshotStatus(pub pubsub.Publication, snapshotID string) (types.VolumesSnapshotStatus, bool) {
	st, err := pub.Get(snapshotID)
	if err != nil {
		return types.VolumesSnapshotStatus{}, false
	}
	return st.(types.VolumesSnapshotStatus), true
}

// What is done to a snapshot follows from whether zedmanager wants it, which
// is its config, and from what volumemgr has, which is its status. An action
// that failed is not repeated by itself.
func TestWhatIsDoneToASnapshot(t *testing.T) {
	config := func(rollbackCount int) *types.VolumesSnapshotConfig {
		return &types.VolumesSnapshotConfig{SnapshotID: "s1", RollbackCount: rollbackCount}
	}
	status := func(state types.VolumesSnapshotState, rollbackCount int, failed bool) *types.VolumesSnapshotStatus {
		st := types.VolumesSnapshotStatus{SnapshotID: "s1", State: state, RollbackCount: rollbackCount}
		if failed {
			st.SetErrorWithSourceAndDescription(
				types.ErrorDescription{Error: "qemu-img failed"}, types.VolumesSnapshotStatus{})
		}
		return &st
	}
	const (
		creating    = types.VolumesSnapshotStateCreating
		created     = types.VolumesSnapshotStateCreated
		rollingBack = types.VolumesSnapshotStateRollingBack
		deleting    = types.VolumesSnapshotStateDeleting
	)
	tests := []struct {
		name   string
		config *types.VolumesSnapshotConfig
		status *types.VolumesSnapshotStatus
		want   snapshotAction
	}{
		{"wanted and not there", config(0), nil, snapshotCreate},
		{"neither wanted nor there", nil, nil, snapshotNothing},
		{"wanted and there", config(0), status(created, 0, false), snapshotNothing},
		{"there and not wanted", nil, status(created, 0, false), snapshotDelete},
		{"rollback asked for", config(2), status(created, 1, false), snapshotRollback},
		{"rollback done", config(2), status(created, 2, false), snapshotNothing},
		{"an older rollback count", config(1), status(created, 2, false), snapshotNothing},

		{"creation waits for a worker", config(0), status(creating, 0, false), snapshotCreate},
		{"creation that did not start, not wanted any more", nil, status(creating, 0, false), snapshotDrop},
		{"creation failed", config(0), status(creating, 0, true), snapshotNothing},
		{"creation failed, a rollback is no way out", config(1), status(creating, 0, true), snapshotNothing},
		{"creation failed, not wanted any more", nil, status(creating, 0, true), snapshotDelete},

		{"rollback waits for a worker", config(2), status(rollingBack, 2, false), snapshotRollback},
		{"rollback failed", config(2), status(rollingBack, 2, true), snapshotNothing},
		{"rollback failed, another one asked for", config(3), status(rollingBack, 2, true), snapshotRollback},
		{"rollback failed, not wanted any more", nil, status(rollingBack, 2, true), snapshotDelete},
		{"rollback waits, not wanted any more", nil, status(rollingBack, 2, false), snapshotDelete},

		{"deletion waits for a worker", nil, status(deleting, 0, false), snapshotDelete},
		{"deletion failed", nil, status(deleting, 0, true), snapshotNothing},
		{"deletion is not taken back", config(0), status(deleting, 0, false), snapshotDelete},
		{"deletion failed and is not taken back", config(5), status(deleting, 0, true), snapshotNothing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &volumemgrContext{snapshotConfigsComplete: true}
			assert.Equal(t, tt.want, snapshotActionNeeded(ctx, tt.config, tt.status))
		})
	}

	// After a boot volumemgr has the snapshots before zedmanager has
	// published the first config.
	t.Run("a missing config says nothing before zedmanager has published its configs", func(t *testing.T) {
		ctx := &volumemgrContext{}
		for _, st := range []*types.VolumesSnapshotStatus{
			status(created, 0, false), status(creating, 0, true),
			status(rollingBack, 1, true), status(rollingBack, 1, false),
		} {
			assert.Equal(t, snapshotNothing, snapshotActionNeeded(ctx, nil, st), st.State.String())
		}
		assert.Equal(t, snapshotDelete, snapshotActionNeeded(ctx, nil, status(deleting, 0, false)),
			"what was being deleted before the reboot is not wanted")
		assert.Equal(t, snapshotRollback, snapshotActionNeeded(ctx, config(1), status(rollingBack, 1, false)),
			"a rollback that a reboot cut off goes on once zedmanager wants the snapshot")
	})
}

// A snapshot exists only if every volume has it. Until then zedmanager has to
// see that it is being created, and a creation that failed stays what it is.
func TestSnapshotCreation(t *testing.T) {
	t.Run("all volumes", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a", "b")
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 0))
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateCreating, status.State)
		assert.True(t, status.Busy())
		finishSnapshotWork(t, ctx)

		status, _ = snapshotStatus(pub, "s1")
		assert.False(t, status.HasError())
		assert.Equal(t, types.VolumesSnapshotStateCreated, status.State)
		assert.Len(t, status.VolumeSnapshotMeta, 2)
		assert.WithinDuration(t, time.Unix(1, 0), status.TimeCreated, 0)
		assert.True(t, status.RollbackCountKnown)
		assert.ElementsMatch(t, []string{"create a", "create b"}, fake.made())
		assert.Equal(t, types.VolumesSnapshotStateCreated, fake.records["s1"].State,
			"the record is what the snapshot is known by after a reboot")
		assert.Empty(t, ctx.snapshotOpInFlight)
	})
	t.Run("one volume fails", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		fake.fail["create a"] = errors.New("no space")
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 0))
		finishSnapshotWork(t, ctx)

		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateCreating, status.State, "it is not a snapshot")
		assert.False(t, status.Busy())
		assert.Contains(t, status.Error, "no space")
		assert.Contains(t, status.Error, ids[0].String())
		assert.Empty(t, status.VolumeSnapshotMeta)
		assert.Contains(t, fake.records["s1"].Error, "no space", "the failure has to be known after a reboot")

		// zedmanager goes on wanting it.
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 0))
		driveSnapshots(ctx)
		assert.Equal(t, []string{"create a"}, fake.made(), "it is not tried again")
		assert.Empty(t, ctx.snapshotOpInFlight)
	})
	t.Run("the volumes before the failing one lose what they got", func(t *testing.T) {
		for attempt := 0; attempt < 20; attempt++ {
			ctx, pub, fake := newSnapshotTestContext(t)
			ids := snapshotTestVolumes(t, ctx, "a", "b")
			fake.fail["create b"] = errors.New("no space")
			wantSnapshot(ctx, snapshotTestConfig("s1", ids, 0))
			finishSnapshotWork(t, ctx)
			status, _ := snapshotStatus(pub, "s1")
			assert.Empty(t, status.VolumeSnapshotMeta)
			// The volumes are taken in no particular order.
			if made := fake.made(); len(made) == 3 {
				assert.Equal(t, []string{"create a", "create b", "delete a"}, made)
				return
			}
		}
		t.Fatal("volume a never came first")
	})
	t.Run("a volume that keeps what it got stays known", func(t *testing.T) {
		for attempt := 0; attempt < 20; attempt++ {
			ctx, pub, fake := newSnapshotTestContext(t)
			ids := snapshotTestVolumes(t, ctx, "a", "b")
			fake.fail["create b"] = errors.New("no space")
			fake.fail["delete a"] = errors.New("qemu-img failed")
			wantSnapshot(ctx, snapshotTestConfig("s1", ids, 0))
			finishSnapshotWork(t, ctx)
			if len(fake.made()) != 3 {
				continue
			}
			status, _ := snapshotStatus(pub, "s1")
			assert.Equal(t, map[string]interface{}{ids[0].String(): "meta of a"}, status.VolumeSnapshotMeta,
				"or the deletion of the snapshot could not remove it")
			return
		}
		t.Fatal("volume a never came first")
	})
	t.Run("unknown volume", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		wantSnapshot(ctx, snapshotTestConfig("s1", []uuid.UUID{uuid.Must(uuid.NewV4())}, 0))
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateCreating, status.State)
		assert.Contains(t, status.Error, "not found")
		assert.Empty(t, fake.made())
		assert.Empty(t, ctx.snapshotOpInFlight)
	})
	t.Run("the record cannot be saved", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		fake.saveFails["s1"] = true
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 0))
		finishSnapshotWork(t, ctx)
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateCreating, status.State,
			"a snapshot that is gone after a reboot must not pass for one")
		assert.Contains(t, status.Error, "Failed to save the record")
	})
}

// A rollback is asked for with a RollbackCount in the config that is higher
// than the one of the status. The status takes the count when volumemgr takes
// up the rollback, and is Created again when it is done.
func TestSnapshotRollback(t *testing.T) {
	t.Run("works", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a", "b")
		existingSnapshot(ctx, "s1", ids)
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 4))
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateRollingBack, status.State)
		assert.Equal(t, 4, status.RollbackCount, "zedmanager has to see that its request was taken up")
		assert.True(t, status.Busy())
		assert.Equal(t, types.VolumesSnapshotStateRollingBack, fake.records["s1"].State,
			"or a reboot now would lose the rollback")
		finishSnapshotWork(t, ctx)

		status, _ = snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateCreated, status.State)
		assert.Equal(t, 4, status.RollbackCount)
		assert.False(t, status.HasError())
		assert.ElementsMatch(t, []string{"rollback a", "rollback b"}, fake.made())

		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 4))
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 3))
		assert.Len(t, fake.made(), 2, "only a higher count asks for another rollback")
	})
	t.Run("fails", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", ids)
		fake.fail["rollback a"] = errors.New("qemu-img failed")
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 1))
		finishSnapshotWork(t, ctx)
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateRollingBack, status.State)
		assert.Equal(t, 1, status.RollbackCount)
		assert.Contains(t, status.Error, "qemu-img failed")
		assert.False(t, status.Busy())

		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 1))
		driveSnapshots(ctx)
		assert.Len(t, fake.made(), 1, "it is not tried again by itself")

		// The snapshot is as good as before, so it can be asked for again.
		delete(fake.fail, "rollback a")
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 2))
		status, _ = snapshotStatus(pub, "s1")
		assert.True(t, status.Busy(), "the error of the first attempt is not the outcome of the second")
		finishSnapshotWork(t, ctx)
		status, _ = snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateCreated, status.State)
		assert.Equal(t, 2, status.RollbackCount)
		assert.False(t, status.HasError())
	})
	t.Run("fails half way", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a", "b")
		existingSnapshot(ctx, "s1", ids)
		fake.fail["rollback a"] = errors.New("qemu-img failed")
		fake.fail["rollback b"] = errors.New("qemu-img failed")
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 1))
		finishSnapshotWork(t, ctx)
		assert.Len(t, fake.made(), 1, "the volumes after the failing one are left alone")

		delete(fake.fail, fake.made()[0])
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 2))
		finishSnapshotWork(t, ctx)
		status, _ := snapshotStatus(pub, "s1")
		if len(fake.made()) == 3 {
			assert.Contains(t, status.Error, "1 of 2 volumes are rolled back")
		}
	})
	t.Run("unknown volume", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		existingSnapshot(ctx, "s1", []uuid.UUID{uuid.Must(uuid.NewV4())})
		wantSnapshot(ctx, snapshotTestConfig("s1", nil, 1))
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateRollingBack, status.State)
		assert.Equal(t, 1, status.RollbackCount, "the request is answered")
		assert.Contains(t, status.Error, "not found")
		assert.Empty(t, fake.made())
	})
	t.Run("not to a snapshot that the volumes do not all have", func(t *testing.T) {
		for name, state := range map[string]types.VolumesSnapshotState{
			"its creation failed": types.VolumesSnapshotStateCreating,
			"its deletion failed": types.VolumesSnapshotStateDeleting,
		} {
			t.Run(name, func(t *testing.T) {
				ctx, pub, fake := newSnapshotTestContext(t)
				ids := snapshotTestVolumes(t, ctx, "a")
				partial := types.VolumesSnapshotStatus{
					SnapshotID: "s1", AppUUID: snapshotTestApp, VolumeSnapshotMeta: snapshotMeta(ids), State: state,
				}
				partial.SetErrorWithSourceAndDescription(
					types.ErrorDescription{Error: "qemu-img failed"}, types.VolumesSnapshotStatus{})
				_ = publishVolumesSnapshotStatus(ctx, &partial)
				before, _ := snapshotStatus(pub, "s1")

				for count := 1; count <= 2; count++ {
					wantSnapshot(ctx, snapshotTestConfig("s1", ids, count))
				}
				after, _ := snapshotStatus(pub, "s1")
				assert.Equal(t, before, after)
				assert.Empty(t, fake.made(), "no volume must be touched")
				assert.Empty(t, ctx.snapshotOpInFlight)
			})
		}
	})
}

// A snapshot without a config is deleted. A deletion that worked takes the
// status away. One that failed leaves the snapshot in the state Deleting with
// the error, and goes through all volumes first: each one that loses the
// snapshot frees space.
func TestSnapshotDeletion(t *testing.T) {
	t.Run("works", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a", "b")
		existingSnapshot(ctx, "s1", ids)
		unwantSnapshot(ctx, "s1")
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateDeleting, status.State)
		assert.True(t, status.Busy())
		assert.Equal(t, types.VolumesSnapshotStateDeleting, fake.records["s1"].State,
			"it must not be whole again after a reboot")
		finishSnapshotWork(t, ctx)

		_, published := snapshotStatus(pub, "s1")
		assert.False(t, published)
		assert.ElementsMatch(t, []string{"delete a", "delete b"}, fake.made())
		assert.NotContains(t, fake.records, "s1", "or the snapshot is back after a reboot")
	})
	t.Run("fails", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a", "b")
		existingSnapshot(ctx, "s1", ids)
		fake.fail["delete b"] = errors.New("qemu-img failed")
		unwantSnapshot(ctx, "s1")
		finishSnapshotWork(t, ctx)

		status, published := snapshotStatus(pub, "s1")
		if assert.True(t, published, "the failure must be visible") {
			assert.Equal(t, types.VolumesSnapshotStateDeleting, status.State)
			assert.False(t, status.Busy())
			assert.Contains(t, status.Error, ids[1].String())
			assert.Equal(t, map[string]interface{}{ids[1].String(): "meta"}, status.VolumeSnapshotMeta,
				"a volume that lost the snapshot has nothing left to delete")
		}
		assert.Equal(t, status.VolumeSnapshotMeta, fake.records["s1"].VolumeSnapshotMeta)
		assert.ElementsMatch(t, []string{"delete a", "delete b"}, fake.made())

		driveSnapshots(ctx)
		assert.Len(t, fake.made(), 2, "it must not be tried again in a loop")
		assert.Empty(t, ctx.snapshotOpInFlight)

		// It is not a snapshot any more, whatever zedmanager says.
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 1))
		assert.Len(t, fake.made(), 2)
		status, _ = snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateDeleting, status.State)
	})
	t.Run("that failed is tried again with the next action for the app", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", ids)
		existingSnapshot(ctx, "s2", ids)
		existingSnapshot(ctx, "of-another-app", ids)
		other, _ := snapshotStatus(pub, "of-another-app")
		other.AppUUID = snapshotTestOtherApp
		other.State = types.VolumesSnapshotStateDeleting
		other.SetErrorWithSourceAndDescription(
			types.ErrorDescription{Error: "qemu-img failed"}, types.VolumesSnapshotStatus{})
		_ = publishVolumesSnapshotStatus(ctx, &other)
		delete(ctx.subVolumesSnapConfig.(*snapshotConfigs).items, "of-another-app")

		fake.fail["delete a"] = errors.New("qemu-img failed")
		unwantSnapshot(ctx, "s1")
		finishSnapshotWork(t, ctx)
		delete(fake.fail, "delete a")

		// zedmanager asks for a rollback, so the app is down.
		wantSnapshot(ctx, snapshotTestConfig("s2", ids, 1))
		status, _ := snapshotStatus(pub, "s1")
		assert.True(t, status.Busy())
		finishSnapshotWork(t, ctx)
		_, published := snapshotStatus(pub, "s1")
		assert.False(t, published)
		// zedmanager starts the app when the rollback is over, and may not
		// have seen by then that the deletion is busy.
		rollback, _ := snapshotStatus(pub, "s2")
		assert.True(t, rollback.Busy(), "the deletion has to be over before the rollback is")
		finishSnapshotWork(t, ctx)
		rollback, _ = snapshotStatus(pub, "s2")
		assert.Equal(t, types.VolumesSnapshotStateCreated, rollback.State)
		assert.Equal(t, []string{"delete a", "delete a", "rollback a"}, fake.made())
		other, _ = snapshotStatus(pub, "of-another-app")
		assert.True(t, other.HasError(), "the other app may be running")
	})
	t.Run("that is tried again is over before a creation that set it off is dropped", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", ids)
		fake.fail["delete a"] = errors.New("qemu-img failed")
		unwantSnapshot(ctx, "s1")
		finishSnapshotWork(t, ctx)

		fake.block = make(chan struct{})
		wantSnapshot(ctx, snapshotTestConfig("s2", ids, 0))
		// zedmanager does not want the new snapshot any more, and starts
		// the app when its status is gone.
		unwantSnapshot(ctx, "s2")
		_, published := snapshotStatus(pub, "s2")
		assert.True(t, published, "the deletion of s1 is still running")
		close(fake.block)
		finishSnapshotWork(t, ctx)
		_, published = snapshotStatus(pub, "s2")
		assert.False(t, published)
		assert.Equal(t, []string{"delete a", "delete a"}, fake.made())
		assert.Empty(t, ctx.snapshotsWaiting)
	})
	t.Run("failed deletions do not set each other off", func(t *testing.T) {
		ctx, _, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", ids)
		existingSnapshot(ctx, "s2", ids)
		fake.fail["delete a"] = errors.New("qemu-img failed")
		unwantSnapshot(ctx, "s1")
		finishSnapshotWork(t, ctx)
		// The deletion of s2 takes s1 along once.
		unwantSnapshot(ctx, "s2")
		finishSnapshotWork(t, ctx)
		finishSnapshotWork(t, ctx)
		for i := 0; i < 20; i++ {
			time.Sleep(time.Millisecond)
			driveSnapshots(ctx)
		}
		assert.Len(t, fake.made(), 3)
		assert.Empty(t, ctx.snapshotOpInFlight)
		assert.Empty(t, ctx.snapshotsWaiting)
	})
	t.Run("of what a failed creation left", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", ids)
		failed, _ := snapshotStatus(pub, "s1")
		failed.State = types.VolumesSnapshotStateCreating
		failed.SetErrorWithSourceAndDescription(
			types.ErrorDescription{Error: "no space"}, types.VolumesSnapshotStatus{})
		_ = publishVolumesSnapshotStatus(ctx, &failed)

		unwantSnapshot(ctx, "s1")
		finishSnapshotWork(t, ctx)
		_, published := snapshotStatus(pub, "s1")
		assert.False(t, published)
		assert.Equal(t, []string{"delete a"}, fake.made())
	})
	t.Run("on a volume that is gone", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", append(ids, uuid.Must(uuid.NewV4())))
		unwantSnapshot(ctx, "s1")
		finishSnapshotWork(t, ctx)
		_, published := snapshotStatus(pub, "s1")
		assert.False(t, published, "the snapshot went with the volume")
		assert.Equal(t, []string{"delete a"}, fake.made())
	})
	t.Run("the record cannot be removed", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", ids)
		fake.removeFails["s1"] = true
		unwantSnapshot(ctx, "s1")
		finishSnapshotWork(t, ctx)
		status, published := snapshotStatus(pub, "s1")
		if assert.True(t, published, "it would be back after a reboot") {
			assert.Equal(t, types.VolumesSnapshotStateDeleting, status.State)
			assert.Contains(t, status.Error, "Failed to remove the record")
		}
	})
}

// After a boot volumemgr has the snapshots from its records before zedmanager
// has published the first config. Only when zedmanager says that it has
// published them all is a snapshot without a config one to delete.
func TestSnapshotIsNotDeletedBeforeZedmanagerHasPublishedItsConfigs(t *testing.T) {
	ctx, pub, fake := newSnapshotTestContext(t)
	ctx.snapshotConfigsComplete = false
	ids := snapshotTestVolumes(t, ctx, "a")
	existingSnapshot(ctx, "kept", ids)
	existingSnapshot(ctx, "not-wanted", ids)
	delete(ctx.subVolumesSnapConfig.(*snapshotConfigs).items, "not-wanted")

	reconcileSnapshot(ctx, "not-wanted")
	driveSnapshots(ctx)
	handleVolumesSnapshotConfigRestarted(ctx, 0)
	status, _ := snapshotStatus(pub, "not-wanted")
	assert.Equal(t, types.VolumesSnapshotStateCreated, status.State)
	assert.Empty(t, fake.made())

	handleVolumesSnapshotConfigRestarted(ctx, 1)
	finishSnapshotWork(t, ctx)
	_, published := snapshotStatus(pub, "not-wanted")
	assert.False(t, published)
	status, _ = snapshotStatus(pub, "kept")
	assert.Equal(t, types.VolumesSnapshotStateCreated, status.State)
	assert.Equal(t, []string{"delete a"}, fake.made())
}

// The snapshot actions of an app use the same disk images and depend on
// each other. Only one of them runs at a time, and what the config says last
// is what happens in the end.
func TestSnapshotActionsOfAnAppRunOneAtATime(t *testing.T) {
	t.Run("a snapshot that is not wanted any more while it is created", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		fake.block = make(chan struct{})
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 0))
		unwantSnapshot(ctx, "s1")
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateCreating, status.State, "the worker is busy with it")

		close(fake.block)
		finishSnapshotWork(t, ctx)
		status, _ = snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateDeleting, status.State)
		finishSnapshotWork(t, ctx)
		_, published := snapshotStatus(pub, "s1")
		assert.False(t, published)
		assert.Equal(t, []string{"create a", "delete a"}, fake.made())
	})
	t.Run("another snapshot of the app", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		fake.block = make(chan struct{})
		existingSnapshot(ctx, "s0", ids)
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 0))
		wantSnapshot(ctx, snapshotTestConfig("s0", ids, 1))
		status, _ := snapshotStatus(pub, "s0")
		assert.Equal(t, types.VolumesSnapshotStateRollingBack, status.State,
			"zedmanager has to see that the rollback is not done")
		assert.Equal(t, 1, ctx.worker.NumPending(), "the rollback must wait for the creation")

		close(fake.block)
		finishSnapshotWork(t, ctx)
		finishSnapshotWork(t, ctx)
		status, _ = snapshotStatus(pub, "s0")
		assert.Equal(t, types.VolumesSnapshotStateCreated, status.State)
		assert.Equal(t, 1, status.RollbackCount)
		assert.Equal(t, []string{"create a", "rollback a"}, fake.made())
	})
	t.Run("a snapshot of another app does not wait", func(t *testing.T) {
		ctx, _, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		fake.block = make(chan struct{})
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 0))
		other := snapshotTestConfig("s2", ids, 0)
		other.AppUUID = snapshotTestOtherApp
		wantSnapshot(ctx, other)
		assert.Len(t, ctx.snapshotOpInFlight, 2)
		close(fake.block)
		finishSnapshotWork(t, ctx)
		finishSnapshotWork(t, ctx)
	})
	t.Run("deletion asked for during a rollback", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		fake.block = make(chan struct{})
		existingSnapshot(ctx, "s0", ids)
		wantSnapshot(ctx, snapshotTestConfig("s0", ids, 1))
		unwantSnapshot(ctx, "s0")

		close(fake.block)
		finishSnapshotWork(t, ctx)
		status, _ := snapshotStatus(pub, "s0")
		assert.Equal(t, types.VolumesSnapshotStateDeleting, status.State)
		finishSnapshotWork(t, ctx)
		_, published := snapshotStatus(pub, "s0")
		assert.False(t, published)
		assert.Equal(t, []string{"rollback a", "delete a"}, fake.made())
	})
	t.Run("second rollback asked for during the first", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		fake.block = make(chan struct{})
		existingSnapshot(ctx, "s0", ids)
		wantSnapshot(ctx, snapshotTestConfig("s0", ids, 1))
		wantSnapshot(ctx, snapshotTestConfig("s0", ids, 2))

		close(fake.block)
		finishSnapshotWork(t, ctx)
		status, _ := snapshotStatus(pub, "s0")
		assert.Equal(t, types.VolumesSnapshotStateRollingBack, status.State)
		assert.Equal(t, 2, status.RollbackCount)
		finishSnapshotWork(t, ctx)
		status, _ = snapshotStatus(pub, "s0")
		assert.Equal(t, types.VolumesSnapshotStateCreated, status.State)
		assert.Equal(t, 2, status.RollbackCount)
		assert.Equal(t, []string{"rollback a", "rollback a"}, fake.made())
	})
}

// A full worker pool means the device is busy with other volume work. A
// snapshot action must then wait for a worker, not fail and not run on top of
// it. If the snapshot is not wanted any more by then, nothing is done at all.
func TestSnapshotActionWaitsForAFreeWorker(t *testing.T) {
	busyPool := func(t *testing.T, ctx *volumemgrContext) chan struct{} {
		release := make(chan struct{})
		assert.NoError(t, ctx.worker.Submit(
			worker.Work{Kind: workTestBlock, Key: "busy", Description: release}))
		ctx.worker.(*worker.Pool).SetMaxWorkers(1)
		return release
	}
	// The worker takes work again a moment after it delivered its result.
	driveUntilStarted := func(ctx *volumemgrContext) {
		for i := 0; i < 1000 && len(ctx.snapshotOpInFlight) == 0; i++ {
			time.Sleep(time.Millisecond)
			driveSnapshots(ctx)
		}
	}

	t.Run("and then runs", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", ids)
		release := busyPool(t, ctx)

		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 1))
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateRollingBack, status.State)
		assert.Empty(t, ctx.snapshotOpInFlight)
		assert.Empty(t, fake.made())

		close(release)
		finishSnapshotWork(t, ctx)
		driveUntilStarted(ctx)
		finishSnapshotWork(t, ctx)
		status, _ = snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateCreated, status.State)
		assert.False(t, status.HasError())
		assert.Equal(t, []string{"rollback a"}, fake.made())
	})
	t.Run("creation that is not wanted any more by then", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		release := busyPool(t, ctx)
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 0))
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateCreating, status.State)

		unwantSnapshot(ctx, "s1")
		_, published := snapshotStatus(pub, "s1")
		assert.False(t, published, "nothing was created, so there is nothing to delete")
		assert.NotContains(t, fake.records, "s1")

		close(release)
		finishSnapshotWork(t, ctx)
		for i := 0; i < 20; i++ {
			time.Sleep(time.Millisecond)
			driveSnapshots(ctx)
		}
		assert.Empty(t, fake.made(), "no snapshot must be created that nobody wants")
		assert.Empty(t, ctx.snapshotOpInFlight)
	})
}

// The statuses are not kept across a reboot, the records on disk are. A
// record is the status as it was published last. What a reboot cut off is
// taken up again, and zedmanager must be told once volumemgr has published
// them all: a snapshot it knows nothing of is one it would create.
func TestSnapshotsAfterAReboot(t *testing.T) {
	const (
		creating    = types.VolumesSnapshotStateCreating
		created     = types.VolumesSnapshotStateCreated
		rollingBack = types.VolumesSnapshotStateRollingBack
		deleting    = types.VolumesSnapshotStateDeleting
	)
	// rebooted returns a volumemgr that starts with the given records. The
	// volumes are not there yet, and zedmanager has published nothing.
	rebooted := func(t *testing.T, records ...types.VolumesSnapshotStatus) (*volumemgrContext, pubsub.Publication, *fakeSnapshotVolumes) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ctx.snapshotConfigsComplete = false
		ctx.signalledRestartedStatus = false
		savedList, savedLoad := listSnapshotRecords, loadVolumesSnapshotStatus
		t.Cleanup(func() { listSnapshotRecords, loadVolumesSnapshotStatus = savedList, savedLoad })
		var listed []string
		for _, record := range records {
			fake.records[record.SnapshotID] = record
			listed = append(listed, record.SnapshotID)
		}
		listSnapshotRecords = func() []string { return append(listed, "unreadable") }
		loadVolumesSnapshotStatus = func(snapshotID string) (*types.VolumesSnapshotStatus, error) {
			record, ok := fake.records[snapshotID]
			if !ok {
				return nil, errors.New("no such file")
			}
			return &record, nil
		}
		assert.False(t, pub.(*pubsub.PublicationImpl).IsRestarted())
		restoreVolumesSnapshotStatuses(ctx)
		assert.True(t, pub.(*pubsub.PublicationImpl).IsRestarted())
		_, published := snapshotStatus(pub, "unreadable")
		assert.False(t, published)
		return ctx, pub, fake
	}
	volumeID := uuid.Must(uuid.FromString("22222222-2222-2222-2222-000000000000"))
	record := func(state types.VolumesSnapshotState, failed bool) types.VolumesSnapshotStatus {
		st := types.VolumesSnapshotStatus{
			SnapshotID:         "s1",
			AppUUID:            snapshotTestApp,
			VolumeSnapshotMeta: snapshotMeta([]uuid.UUID{volumeID}),
			TimeCreated:        time.Unix(1, 0),
			State:              state,
			RollbackCount:      3,
			RollbackCountKnown: true,
		}
		if failed {
			st.SetErrorWithSourceAndDescription(
				types.ErrorDescription{Error: "qemu-img failed"}, types.VolumesSnapshotStatus{})
		}
		return st
	}

	t.Run("a snapshot that nothing was being done to", func(t *testing.T) {
		for _, saved := range []types.VolumesSnapshotStatus{
			record(created, false), record(creating, true), record(rollingBack, true),
		} {
			ctx, pub, _ := rebooted(t, saved)
			status, _ := snapshotStatus(pub, "s1")
			assert.Equal(t, saved.State, status.State)
			assert.Equal(t, saved.Error, status.Error, "a failure has to be known after a reboot as well")
			assert.Equal(t, 3, status.RollbackCount)
			assert.True(t, status.RollbackCountKnown)
			assert.Empty(t, ctx.snapshotsWaiting)
		}
	})
	t.Run("the record of a version that kept no state", func(t *testing.T) {
		old := record(0, true)
		old.RollbackCount, old.RollbackCountKnown = 0, false
		_, pub, _ := rebooted(t, old)
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, created, status.State, "only a snapshot that was created had a record")
		assert.False(t, status.HasError())
		assert.False(t, status.RollbackCountKnown, "it cannot tell whether the app was rolled back to it")
		assert.WithinDuration(t, time.Unix(1, 0), status.TimeCreated, 0)
	})
	t.Run("a creation that was cut off", func(t *testing.T) {
		ctx, pub, _ := rebooted(t, record(creating, false))
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, creating, status.State)
		assert.Contains(t, status.Error, "interrupted by a reboot", "what the volumes got of it is not known")
		assert.Empty(t, ctx.snapshotsWaiting)
	})
	t.Run("a rollback that was cut off", func(t *testing.T) {
		ctx, pub, fake := rebooted(t, record(rollingBack, false))
		status, _ := snapshotStatus(pub, "s1")
		assert.True(t, status.Busy(), "zedmanager has to keep the app down")
		driveSnapshots(ctx)
		assert.Empty(t, fake.made(), "zedmanager may not want the snapshot any more")

		// zedmanager publishes the config before zedagent the volumes.
		wantSnapshot(ctx, snapshotTestConfig("s1", nil, 3))
		assert.Empty(t, fake.made())
		status, _ = snapshotStatus(pub, "s1")
		assert.False(t, status.HasError(), "a volume that is not there yet is not one that is gone")

		snapshotTestVolumes(t, ctx, "a")
		ctx.signalledRestartedStatus = true
		driveSnapshots(ctx)
		finishSnapshotWork(t, ctx)
		status, _ = snapshotStatus(pub, "s1")
		assert.Equal(t, created, status.State)
		assert.Equal(t, 3, status.RollbackCount)
		assert.Equal(t, []string{"rollback a"}, fake.made())
	})
	t.Run("a deletion that was cut off or that failed", func(t *testing.T) {
		for _, failed := range []bool{false, true} {
			ctx, pub, fake := rebooted(t, record(deleting, failed))
			status, _ := snapshotStatus(pub, "s1")
			assert.Equal(t, deleting, status.State)
			assert.True(t, status.Busy(), "zedmanager has to keep the app down for another attempt")
			driveSnapshots(ctx)
			assert.Empty(t, fake.made(), "the volumes are not there yet")

			snapshotTestVolumes(t, ctx, "a")
			ctx.signalledRestartedStatus = true
			driveSnapshots(ctx)
			finishSnapshotWork(t, ctx)
			_, published := snapshotStatus(pub, "s1")
			assert.False(t, published)
			assert.Equal(t, []string{"delete a"}, fake.made())
		}
	})
	t.Run("a deletion whose volume is gone", func(t *testing.T) {
		ctx, pub, fake := rebooted(t, record(deleting, true))
		ctx.signalledRestartedStatus = true
		driveSnapshots(ctx)
		finishSnapshotWork(t, ctx)
		_, published := snapshotStatus(pub, "s1")
		assert.False(t, published)
		assert.Empty(t, fake.made())
	})
	// The image of such a volume may well be there.
	t.Run("a volume that volumemgr could not take up keeps the snapshot", func(t *testing.T) {
		ctx, pub, fake := rebooted(t, record(deleting, true))
		failed := types.VolumeStatus{VolumeID: volumeID, DisplayName: "a", State: types.INITIAL}
		failed.SetErrorWithSource("no vhost target", types.VolumeStatus{}, time.Now())
		assert.NoError(t, ctx.pubVolumeStatus.Publish(failed.Key(), failed))
		ctx.signalledRestartedStatus = true
		driveSnapshots(ctx)
		status, published := snapshotStatus(pub, "s1")
		if assert.True(t, published, "nothing would know of what is left on the volume") {
			assert.Contains(t, status.Error, "no vhost target")
			assert.Len(t, status.VolumeSnapshotMeta, 1)
			assert.False(t, status.Busy())
		}
		assert.Empty(t, fake.made())
	})
	// volumemgr creates such a volume when zedmanager asks for it, and
	// zedmanager does not while a snapshot of the app is busy.
	t.Run("a volume that has no image is not waited for", func(t *testing.T) {
		for _, state := range []types.VolumesSnapshotState{deleting, rollingBack} {
			ctx, pub, fake := rebooted(t, record(state, false))
			noImage := types.VolumeStatus{VolumeID: volumeID, DisplayName: "a", State: types.INITIAL}
			assert.NoError(t, ctx.pubVolumeStatus.Publish(noImage.Key(), noImage))
			ctx.signalledRestartedStatus = true
			wantSnapshot(ctx, snapshotTestConfig("s1", nil, 3))
			driveSnapshots(ctx)
			if state == deleting {
				unwantSnapshot(ctx, "s1")
				finishSnapshotWork(t, ctx)
			}
			status, published := snapshotStatus(pub, "s1")
			assert.False(t, published && status.Busy(), "the app would be kept down for good")
			assert.Empty(t, fake.made())
			assert.Empty(t, ctx.snapshotsWaiting)
		}
	})
}

// What is known of a snapshot after a reboot is its record, so the record
// follows the status.
// An app that is uninstalled takes its snapshots along. zedmanager takes the
// configs away once volumemgr has let go of the volumes, and nothing is done
// to the images of volumes that are on their way out.
func TestSnapshotsGoWithTheVolumesOfAnUninstalledApp(t *testing.T) {
	leave := func(t *testing.T, ctx *volumemgrContext, id uuid.UUID) *types.VolumeStatus {
		t.Helper()
		volume := ctx.lookupVolumeStatusByUUID(id.String())
		volume.SubState = types.VolumeSubStateCreated
		volume.RefCount = 0
		maybeDeleteVolume(ctx, volume)
		return ctx.lookupVolumeStatusByUUID(id.String())
	}
	t.Run("nothing is running", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", ids)

		volume := leave(t, ctx, ids[0])
		assert.Equal(t, types.VolumeSubStateDeleting, volume.SubState)
		unwantSnapshot(ctx, "s1")
		finishSnapshotWork(t, ctx)

		_, published := snapshotStatus(pub, "s1")
		assert.False(t, published)
		assert.NotContains(t, fake.records, "s1")
		assert.Empty(t, fake.made(), "the snapshot goes with the image")
	})
	t.Run("a worker has the image in use", func(t *testing.T) {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", ids)
		fake.block = make(chan struct{})
		wantSnapshot(ctx, snapshotTestConfig("s1", ids, 1))

		volume := leave(t, ctx, ids[0])
		assert.Equal(t, types.VolumeSubStateCreated, volume.SubState,
			"the image must not be destroyed under the worker")
		unwantSnapshot(ctx, "s1")
		status, _ := snapshotStatus(pub, "s1")
		assert.Equal(t, types.VolumesSnapshotStateRollingBack, status.State)

		close(fake.block)
		finishSnapshotWork(t, ctx)
		volume = ctx.lookupVolumeStatusByUUID(ids[0].String())
		assert.Equal(t, types.VolumeSubStateDeleting, volume.SubState)
		assert.Empty(t, ctx.volumesAwaitingSnapshot)
		finishSnapshotWork(t, ctx)
		_, published := snapshotStatus(pub, "s1")
		assert.False(t, published, "the outcome of the rollback is of no use any more")
		assert.NotContains(t, fake.records, "s1")
		assert.Equal(t, []string{"rollback a"}, fake.made())
	})
}

// A snapshot knows its volume by the UUID only, and during a purge volumemgr
// has two generations of it. The one with the image is the one to work on: a
// deletion that picked the new generation would drop the snapshot without
// taking it off the image.
func TestSnapshotOfAVolumeWithTwoGenerations(t *testing.T) {
	for i := 0; i < 20; i++ {
		ctx, pub, fake := newSnapshotTestContext(t)
		ids := snapshotTestVolumes(t, ctx, "a")
		existingSnapshot(ctx, "s1", ids)
		purged := types.VolumeStatus{VolumeID: ids[0], GenerationCounter: 1, DisplayName: "new a",
			State: types.INITIAL}
		assert.NoError(t, ctx.pubVolumeStatus.Publish(purged.Key(), purged))

		unwantSnapshot(ctx, "s1")
		finishSnapshotWork(t, ctx)

		_, published := snapshotStatus(pub, "s1")
		assert.False(t, published)
		if !assert.Equal(t, []string{"delete a"}, fake.made()) {
			break
		}
	}
}

func TestSnapshotRecordFollowsTheStatus(t *testing.T) {
	ctx, pub, fake := newSnapshotTestContext(t)
	same := func(msg string) {
		t.Helper()
		status, _ := snapshotStatus(pub, "s1")
		record := fake.records["s1"]
		assert.Equal(t, status.State, record.State, msg)
		assert.Equal(t, status.Error, record.Error, msg)
		assert.Equal(t, status.RollbackCount, record.RollbackCount, msg)
		assert.Equal(t, status.VolumeSnapshotMeta, record.VolumeSnapshotMeta, msg)
	}
	ids := snapshotTestVolumes(t, ctx, "a")
	fake.block = make(chan struct{})
	wantSnapshot(ctx, snapshotTestConfig("s1", ids, 0))
	same("being created")
	close(fake.block)
	finishSnapshotWork(t, ctx)
	same("created")

	fake.fail["rollback a"] = errors.New("qemu-img failed")
	wantSnapshot(ctx, snapshotTestConfig("s1", ids, 1))
	same("being rolled back to")
	finishSnapshotWork(t, ctx)
	status, _ := snapshotStatus(pub, "s1")
	assert.True(t, status.HasError())
	same("rollback failed")

	unwantSnapshot(ctx, "s1")
	same("being deleted")
	finishSnapshotWork(t, ctx)
	assert.Empty(t, fake.records)
}
