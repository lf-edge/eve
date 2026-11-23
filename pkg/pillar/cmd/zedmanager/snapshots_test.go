// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"errors"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

var snapshotTestApp = uuid.Must(uuid.FromString(appA))

func snapshotDesc(id string, snapshotType types.SnapshotType) types.SnapshotDesc {
	return types.SnapshotDesc{SnapshotID: id, SnapshotType: snapshotType}
}

// snapshotTestConfig is the config of an app that lists the given snapshots,
// all of them to be taken at once.
func snapshotTestConfig(maxSnapshots uint32, ids ...string) types.AppInstanceConfig {
	config := types.AppInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: snapshotTestApp, Version: "2"},
	}
	config.Snapshot.MaxSnapshots = maxSnapshots
	for _, id := range ids {
		config.Snapshot.Snapshots = append(config.Snapshot.Snapshots,
			snapshotDesc(id, types.SnapshotTypeImmediate))
	}
	return config
}

// createdAt is a snapshot of the test app that was created at the given time.
func createdAt(id string, seconds int64) types.VolumesSnapshotStatus {
	created := existingSnapshot(id, snapshotTestApp)
	created.TimeCreated = time.Unix(seconds, 0)
	return created
}

// failedSnapshot is a snapshot of the test app that volumemgr left in the
// given state when it failed.
func failedSnapshot(id string, state types.VolumesSnapshotState) types.VolumesSnapshotStatus {
	failed := types.VolumesSnapshotStatus{
		SnapshotID: id,
		AppUUID:    snapshotTestApp,
		State:      state,
	}
	failed.SetErrorWithSourceAndDescription(
		types.ErrorDescription{Error: "qemu-img failed", ErrorTime: time.Unix(100, 0)},
		types.VolumesSnapshotStatus{})
	return failed
}

// beingCreated is a snapshot of the test app that volumemgr works on.
func beingCreated(id string) types.VolumesSnapshotStatus {
	return types.VolumesSnapshotStatus{
		SnapshotID: id, AppUUID: snapshotTestApp, State: types.VolumesSnapshotStateCreating,
	}
}

// knownSnapshots is a context in which volumemgr reports the given snapshots
// and zedmanager has published the given configs. The controller has sent a
// config.
func knownSnapshots(t *testing.T, configs []types.VolumesSnapshotConfig,
	statuses ...types.VolumesSnapshotStatus) *zedmanagerContext {
	t.Helper()
	ctx := newSnapshotWaitTestContext(t, configs, statuses)
	ctx.configFromController = true
	return ctx
}

func creationOf(id string) types.VolumesSnapshotConfig {
	return types.VolumesSnapshotConfig{SnapshotID: id, AppUUID: snapshotTestApp}
}

func ids(snaps []types.SnapshotDesc) []string {
	var out []string
	for _, snap := range snaps {
		out = append(out, snap.SnapshotID)
	}
	return out
}

// A snapshot is taken if the config lists it and volumemgr knows nothing of
// it. A snapshot whose creation failed is one volumemgr knows: it is reported
// and not tried again. Nothing is taken for missing before volumemgr has told
// what exists, or every snapshot would be created again after a reboot.
func TestWhichSnapshotsAreTaken(t *testing.T) {
	config := snapshotTestConfig(3, "s1", "s2", "s3")

	t.Run("those that volumemgr knows nothing of", func(t *testing.T) {
		ctx := knownSnapshots(t, nil, createdAt("s1", 1),
			failedSnapshot("s2", types.VolumesSnapshotStateCreating))
		assert.Equal(t, []string{"s3"}, ids(snapshotsToTake(ctx, config)))
		assert.Equal(t, types.SnapshotImmediate, snapshotRequestedType(ctx, config))
	})
	t.Run("not those that were asked for", func(t *testing.T) {
		ctx := knownSnapshots(t, []types.VolumesSnapshotConfig{creationOf("s2"), creationOf("s3")},
			createdAt("s1", 1), beingCreated("s2"))
		assert.Empty(t, snapshotsToTake(ctx, config))
		assert.Equal(t, []string{"s3"}, ids(pendingSnapshots(ctx, config)))
		assert.Equal(t, types.NoSnapshotTake, snapshotRequestedType(ctx, config))
	})
	t.Run("none before volumemgr has told what exists", func(t *testing.T) {
		ctx := knownSnapshots(t, nil)
		ctx.snapshotsRestored = false
		assert.Empty(t, snapshotsToTake(ctx, config))
	})
	t.Run("none if the config lists more than the limit", func(t *testing.T) {
		ctx := knownSnapshots(t, nil)
		assert.Empty(t, snapshotsToTake(ctx, snapshotTestConfig(2, "s1", "s2", "s3")))
		assert.Equal(t, []string{"s1", "s2"}, ids(snapshotsToTake(ctx, snapshotTestConfig(2, "s1", "s2"))))
	})
	t.Run("on upgrade", func(t *testing.T) {
		ctx := knownSnapshots(t, nil)
		onUpgrade := snapshotTestConfig(1)
		onUpgrade.Snapshot.Snapshots = []types.SnapshotDesc{snapshotDesc("s1", types.SnapshotTypeAppUpdate)}
		assert.Equal(t, types.SnapshotOnUpgrade, snapshotRequestedType(ctx, onUpgrade))
	})
}

// A snapshot is deleted if the config does not list it. A config that lists a
// snapshot again before it is deleted keeps it. A config that lists more
// snapshots than the limit is not one to delete anything for.
func TestWhichSnapshotsAreDeleted(t *testing.T) {
	t.Run("those the config does not list", func(t *testing.T) {
		ctx := knownSnapshots(t, nil, createdAt("s1", 1), createdAt("s2", 2),
			existingSnapshot("of-another-app", uuid.Must(uuid.FromString(appB))))
		assert.Equal(t, []string{"s1"}, snapshotsToDelete(ctx, snapshotTestConfig(2, "s2")))
		assert.Empty(t, snapshotsToDelete(ctx, snapshotTestConfig(2, "s1", "s2")), "listed again")
	})
	t.Run("only if the config is from the controller", func(t *testing.T) {
		// A saved config can be older than the snapshot.
		ctx := knownSnapshots(t, nil, createdAt("s1", 1))
		ctx.configFromController = false
		assert.Empty(t, snapshotsToDelete(ctx, snapshotTestConfig(2)))
	})
	t.Run("none before volumemgr has told what exists", func(t *testing.T) {
		ctx := knownSnapshots(t, nil, createdAt("s1", 1))
		ctx.snapshotsRestored = false
		assert.Empty(t, snapshotsToDelete(ctx, snapshotTestConfig(2)))
	})
	t.Run("none if the config lists more than the limit", func(t *testing.T) {
		ctx := knownSnapshots(t, nil, createdAt("s0", 5), createdAt("s1", 10), createdAt("s2", 20))
		assert.Empty(t, snapshotsToDelete(ctx, snapshotTestConfig(2, "s1", "s2", "s3")))
		assert.Equal(t, []string{"s0"}, snapshotsToDelete(ctx, snapshotTestConfig(2, "s1", "s2")))
	})
	t.Run("whatever state they are in, unless volumemgr is at it already", func(t *testing.T) {
		ctx := knownSnapshots(t, nil,
			beingCreated("creating"),
			failedSnapshot("create-failed", types.VolumesSnapshotStateCreating),
			failedSnapshot("rollback-failed", types.VolumesSnapshotStateRollingBack),
			failedSnapshot("delete-failed", types.VolumesSnapshotStateDeleting))
		assert.Equal(t, []string{"create-failed", "creating", "rollback-failed"},
			snapshotsToDelete(ctx, snapshotTestConfig(1)))
	})
}

// The controller is told what volumemgr has, with the error of a creation,
// rollback or deletion that failed: it waits for that outcome. A snapshot
// that is not created yet is not reported, as that would pass for done.
func TestSnapshotsThatAreReported(t *testing.T) {
	savedLoad := loadSnapshotRecord
	t.Cleanup(func() { loadSnapshotRecord = savedLoad })
	loadSnapshotRecord = func(snapshotID string) (*types.SnapshotInstanceStatus, error) {
		if snapshotID != "s1" {
			return nil, errors.New("no record")
		}
		return &types.SnapshotInstanceStatus{
			Snapshot:      snapshotDesc("s1", types.SnapshotTypeAppUpdate),
			AppInstanceID: snapshotTestApp,
			ConfigVersion: types.UUIDandVersion{UUID: snapshotTestApp, Version: "1"},
		}, nil
	}
	config := creationOf("create-failed")
	config.SnapshotType = types.SnapshotTypeImmediate
	config.ConfigVersion = types.UUIDandVersion{UUID: snapshotTestApp, Version: "7"}
	ctx := knownSnapshots(t, []types.VolumesSnapshotConfig{config, creationOf("creating")},
		createdAt("s1", 5),
		failedSnapshot("create-failed", types.VolumesSnapshotStateCreating),
		failedSnapshot("rollback-failed", types.VolumesSnapshotStateRollingBack),
		failedSnapshot("delete-failed", types.VolumesSnapshotStateDeleting),
		beingCreated("creating"),
		existingSnapshot("of-another-app", uuid.Must(uuid.FromString(appB))),
	)
	status := types.AppInstanceStatus{UUIDandVersion: types.UUIDandVersion{UUID: snapshotTestApp}}

	refreshSnapshots(ctx, &status)

	assert.Equal(t, []string{"create-failed", "delete-failed", "rollback-failed", "s1"},
		snapshotIDs(status.SnapStatus.Snapshots))
	created := lookupSnapshot(&status, "s1")
	assert.WithinDuration(t, time.Unix(5, 0), created.TimeCreated, 0)
	assert.Equal(t, "1", created.ConfigVersion.Version, "from the record that survives a reboot")
	assert.Equal(t, types.SnapshotTypeAppUpdate, created.Snapshot.SnapshotType)
	assert.Empty(t, created.Error.Error)
	createFailed := lookupSnapshot(&status, "create-failed")
	assert.Equal(t, "qemu-img failed", createFailed.Error.Error)
	assert.Equal(t, "7", createFailed.ConfigVersion.Version, "there is no record, but the config")
	assert.Equal(t, "qemu-img failed", lookupSnapshot(&status, "rollback-failed").Error.Error)
	assert.Equal(t, "qemu-img failed", lookupSnapshot(&status, "delete-failed").Error.Error)
}

func snapshotIDs(snaps []types.SnapshotInstanceStatus) []string {
	var out []string
	for _, snap := range snaps {
		out = append(out, snap.Snapshot.SnapshotID)
	}
	return out
}

// volumemgr deletes a snapshot that has no config, so that is how zedmanager
// asks for it. A deletion that failed is tried again by volumemgr.
func TestSnapshotDeletionIsAskedForByTakingTheConfigAway(t *testing.T) {
	unlisted, listed := createdAt("s1", 1), createdAt("s2", 2)
	deleteFailed := failedSnapshot("s3", types.VolumesSnapshotStateDeleting)
	ctx := knownSnapshots(t, kept(unlisted, listed), unlisted, listed, deleteFailed)

	triggerSnapshotDeletion(ctx, snapshotTestConfig(1, "s2"))

	assert.Nil(t, snapshotConfig(ctx, "s1"))
	assert.NotNil(t, snapshotConfig(ctx, "s2"))
	assert.Nil(t, snapshotConfig(ctx, "s3"), "a config would not make volumemgr try again")
}

// What zedmanager knows of a snapshot beyond what volumemgr reports comes
// with its config, which is gone after a reboot. So it is saved once the
// snapshot exists, and only then: a record is taken for a snapshot.
func TestSnapshotRecordIsKeptOnceCreated(t *testing.T) {
	var saved []types.SnapshotInstanceStatus
	savedLoad, savedSave := loadSnapshotRecord, saveSnapshotRecord
	t.Cleanup(func() { loadSnapshotRecord, saveSnapshotRecord = savedLoad, savedSave })
	loadSnapshotRecord = func(string) (*types.SnapshotInstanceStatus, error) {
		if len(saved) == 0 {
			return nil, errors.New("no record")
		}
		return &saved[0], nil
	}
	saveSnapshotRecord = func(record *types.SnapshotInstanceStatus) error {
		saved = append(saved, *record)
		return nil
	}
	config := creationOf("s2")
	config.SnapshotType = types.SnapshotTypeImmediate

	ctx, appConfig := newIdleAppTestContext(t, []types.VolumesSnapshotConfig{config}, nil)
	app := appConfig.UUIDandVersion.UUID
	created := createdAt("s2", 5)
	created.AppUUID = app
	// As after a reboot, for a snapshot that zedmanager has no record of.
	handleVolumesSnapshotStatusImpl(ctx, created, false)
	assert.Empty(t, saved, "there is nothing to tell of the snapshot")

	config.ConfigVersion = types.UUIDandVersion{UUID: snapshotTestApp, Version: "7"}
	useSnapshotState(t, ctx, []types.VolumesSnapshotConfig{config}, nil)
	failed := failedSnapshot("s2", types.VolumesSnapshotStateCreating)
	failed.AppUUID = app
	handleVolumesSnapshotStatusImpl(ctx, failed, true)
	assert.Empty(t, saved)

	handleVolumesSnapshotStatusImpl(ctx, created, false)
	if assert.Len(t, saved, 1) {
		assert.Equal(t, snapshotDesc("s2", types.SnapshotTypeImmediate), saved[0].Snapshot)
		assert.Equal(t, "7", saved[0].ConfigVersion.Version)
		assert.WithinDuration(t, time.Unix(5, 0), saved[0].TimeCreated, 0)
		assert.Equal(t, app, saved[0].AppInstanceID)
		assert.True(t, saved[0].Reported, "an older version only deletes a snapshot with this set")
	}

	// What volumemgr says of the snapshot later, as after a rollback.
	handleVolumesSnapshotStatusImpl(ctx, created, false)
	assert.Len(t, saved, 1, "the record is written once")
}

// The controller takes a snapshot that is missing from the report for
// deleted. At boot the app is reported before volumemgr has published its
// snapshots, so the list has to come from the records on disk until then.
func TestSnapshotsAreReportedBeforeVolumemgrKnowsThem(t *testing.T) {
	savedList, savedLoad, savedLoadVolumes := listSnapshotRecords, loadSnapshotRecord, loadVolumesSnapshot
	t.Cleanup(func() {
		listSnapshotRecords, loadSnapshotRecord, loadVolumesSnapshot = savedList, savedLoad, savedLoadVolumes
	})
	listSnapshotRecords = func() []string {
		return []string{"s1", "of-another-app", "unreadable", "create-failed", "rollback-failed", "old"}
	}
	// zedmanager has a record of the snapshots that were created.
	loadSnapshotRecord = func(snapshotID string) (*types.SnapshotInstanceStatus, error) {
		record := types.SnapshotInstanceStatus{
			Snapshot:      snapshotDesc(snapshotID, types.SnapshotTypeImmediate),
			AppInstanceID: snapshotTestApp,
			TimeCreated:   time.Unix(5, 0),
		}
		switch snapshotID {
		case "unreadable", "create-failed":
			return nil, errors.New("no record")
		case "of-another-app":
			record.AppInstanceID = uuid.Must(uuid.FromString(appB))
		}
		return &record, nil
	}
	// volumemgr has one of every snapshot, with the outcome of the last
	// action. A version before that had it only for the created ones.
	loadVolumesSnapshot = func(snapshotID string) (*types.VolumesSnapshotStatus, error) {
		switch snapshotID {
		case "create-failed":
			st := failedSnapshot(snapshotID, types.VolumesSnapshotStateCreating)
			return &st, nil
		case "rollback-failed":
			st := failedSnapshot(snapshotID, types.VolumesSnapshotStateRollingBack)
			return &st, nil
		case "s1":
			st := createdAt(snapshotID, 5)
			return &st, nil
		}
		return nil, errors.New("no record")
	}
	ctx := knownSnapshots(t, nil)
	ctx.snapshotsRestored = false
	status := types.AppInstanceStatus{UUIDandVersion: types.UUIDandVersion{UUID: snapshotTestApp}}

	updateSnapshotsInAIStatus(ctx, &status, snapshotTestConfig(1, "s1"))

	if assert.Equal(t, []string{"s1", "create-failed", "rollback-failed", "old"}, snapshotIDs(status.SnapStatus.Snapshots)) {
		assert.WithinDuration(t, time.Unix(5, 0), status.SnapStatus.Snapshots[0].TimeCreated, 0)
		assert.Empty(t, status.SnapStatus.Snapshots[0].Error.Error)
		assert.Equal(t, "qemu-img failed", status.SnapStatus.Snapshots[1].Error.Error,
			"a creation that failed must not look deleted for a moment")
		assert.Equal(t, "qemu-img failed", status.SnapStatus.Snapshots[2].Error.Error)
		assert.Empty(t, status.SnapStatus.Snapshots[3].Error.Error)
	}
	assert.Equal(t, types.NoSnapshotTake, status.SnapStatus.SnapshotTakenType)
}

// A config that drops a snapshot before it was taken takes back the plan to
// take it.
func TestUnlistedSnapshotIsNotTaken(t *testing.T) {
	ctx := knownSnapshots(t, nil)
	status := types.AppInstanceStatus{UUIDandVersion: types.UUIDandVersion{UUID: snapshotTestApp}}
	status.SnapStatus.PreparedVolumesSnapshotConfigs = []types.VolumesSnapshotConfig{creationOf("s1"), creationOf("s2")}

	updateSnapshotsInAIStatus(ctx, &status, snapshotTestConfig(2, "s2"))

	assert.Equal(t, []types.VolumesSnapshotConfig{creationOf("s2")}, status.SnapStatus.PreparedVolumesSnapshotConfigs)
	assert.Equal(t, uint32(2), status.SnapStatus.MaxSnapshots)
}

// The snapshot keeps the volumes and the config that the app had before the
// change that triggers it.
func TestSnapshotIsPreparedFromTheConfigBeforeTheChange(t *testing.T) {
	ctx := knownSnapshots(t, nil, createdAt("s1", 1))
	oldConfig := snapshotTestConfig(2, "s1")
	oldConfig.UUIDandVersion.Version = "1"
	volume := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	oldConfig.VolumeRefConfigList = []types.VolumeRefConfig{{VolumeID: volume}}
	config := snapshotTestConfig(2, "s1", "s2")

	prepared := prepareVolumesSnapshotConfigs(ctx, oldConfig, config)

	assert.Equal(t, []types.VolumesSnapshotConfig{{
		SnapshotID:    "s2",
		AppUUID:       snapshotTestApp,
		VolumeIDs:     []uuid.UUID{volume},
		SnapshotType:  types.SnapshotTypeImmediate,
		ConfigVersion: oldConfig.UUIDandVersion,
	}}, prepared)
}

// Once volumemgr has told which snapshots exist, the apps that were created
// before that have to look at them.
func TestAppsLearnOfTheSnapshotsThatExist(t *testing.T) {
	ctx, config := newIdleAppTestContext(t, nil, nil)
	useSnapshotState(t, ctx, nil,
		[]types.VolumesSnapshotStatus{existingSnapshot("s1", config.UUIDandVersion.UUID)})
	ctx.snapshotsRestored = false
	status := lookupAppInstanceStatus(ctx, config.Key())
	status.SnapStatus.Snapshots = nil
	publishAppInstanceStatus(ctx, status)

	handleVolumesSnapshotStatusRestarted(ctx, 1)

	assert.True(t, ctx.snapshotsRestored)
	assert.Equal(t, []string{"s1"}, snapshotIDs(lookupAppInstanceStatus(ctx, config.Key()).SnapStatus.Snapshots))
}

// volumemgr deletes a snapshot that has no config. After a boot it has the
// snapshots before zedmanager has published anything, so zedmanager publishes
// a config for each one it does not want deleted right now, and then says
// that these are all.
func TestSnapshotConfigsArePublishedAfterABoot(t *testing.T) {
	savedLoad := loadSnapshotRecord
	t.Cleanup(func() { loadSnapshotRecord = savedLoad })
	loadSnapshotRecord = func(snapshotID string) (*types.SnapshotInstanceStatus, error) {
		if snapshotID != "s1" {
			return nil, errors.New("no record")
		}
		return &types.SnapshotInstanceStatus{
			Snapshot:      snapshotDesc("s1", types.SnapshotTypeAppUpdate),
			ConfigVersion: types.UUIDandVersion{UUID: snapshotTestApp, Version: "1"},
		}, nil
	}
	ctx, config := newIdleAppTestContext(t, nil, nil)
	app := config.UUIDandVersion.UUID
	volume := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	created := existingSnapshot("s1", app)
	created.VolumeSnapshotMeta = map[string]interface{}{volume.String(): "meta"}
	created.RollbackCount = 3
	// Not listed by the config of the app, which may be an old one.
	unlisted := existingSnapshot("unlisted", app)
	ofUnknownApp := existingSnapshot("of-an-app-without-config", uuid.Must(uuid.FromString(appB)))
	beingDeleted := existingSnapshot("being-deleted", app)
	beingDeleted.State = types.VolumesSnapshotStateDeleting
	useSnapshotState(t, ctx, nil, []types.VolumesSnapshotStatus{created, unlisted, ofUnknownApp, beingDeleted})
	ctx.snapshotsRestored = false
	pub := ctx.pubVolumesSnapConfig.(*pubsub.PublicationImpl)
	assert.False(t, pub.IsRestarted())

	handleVolumesSnapshotStatusRestarted(ctx, 0)
	assert.False(t, ctx.snapshotsRestored, "volumemgr has not published its snapshots yet")
	assert.Empty(t, ctx.pubVolumesSnapConfig.GetAll())

	handleVolumesSnapshotStatusRestarted(ctx, 1)

	assert.True(t, pub.IsRestarted(), "volumemgr must not take a missing config for a wish before this")
	assert.Equal(t, types.VolumesSnapshotConfig{
		SnapshotID:    "s1",
		AppUUID:       app,
		VolumeIDs:     []uuid.UUID{volume},
		RollbackCount: 3,
		SnapshotType:  types.SnapshotTypeAppUpdate,
		ConfigVersion: types.UUIDandVersion{UUID: snapshotTestApp, Version: "1"},
	}, *snapshotConfig(ctx, "s1"))
	assert.NotNil(t, snapshotConfig(ctx, "unlisted"), "it goes when the controller has confirmed that")
	assert.NotNil(t, snapshotConfig(ctx, "of-an-app-without-config"), "the config of the app may be still to come")
	assert.Nil(t, snapshotConfig(ctx, "being-deleted"), "volumemgr goes on with the deletion")
}

// A rollback that the controller asked for and that volumemgr never got, as
// the device went down, is handed over before the app is started.
func TestRollbackLeftOverIsAskedForAfterABoot(t *testing.T) {
	leftOver := func(t *testing.T) (*zedmanagerContext, types.AppInstanceConfig) {
		ctx, config := newIdleAppTestContext(t, nil, nil)
		config.Snapshot.ActiveSnapshot = rollbackTestSnapshot
		config.Snapshot.RollbackCmd.Counter = 4
		useAppConfig(t, ctx, config)
		created := existingSnapshot(rollbackTestSnapshot, config.UUIDandVersion.UUID)
		created.RollbackCount = 3
		useSnapshotState(t, ctx, nil, []types.VolumesSnapshotStatus{created})
		return ctx, config
	}
	t.Run("the app is known when volumemgr has published its snapshots", func(t *testing.T) {
		ctx, config := leftOver(t)
		ctx.snapshotsRestored = false
		handleVolumesSnapshotStatusRestarted(ctx, 1)
		assert.Equal(t, 4, snapshotConfig(ctx, rollbackTestSnapshot).RollbackCount)
		assert.True(t, snapshotOpInProgress(ctx, config.UUIDandVersion.UUID), "the app must wait for the rollback")
	})
	t.Run("the config of the app comes later", func(t *testing.T) {
		ctx, config := leftOver(t)
		unpublishAppInstanceStatus(ctx, lookupAppInstanceStatus(ctx, config.Key()))
		useAppConfig(t, ctx, types.AppInstanceConfig{})
		ctx.snapshotsRestored = false
		handleVolumesSnapshotStatusRestarted(ctx, 1)
		assert.Equal(t, 3, snapshotConfig(ctx, rollbackTestSnapshot).RollbackCount)

		config.FixedResources.Memory, config.FixedResources.VCpus = 1024, 1
		useAppConfig(t, ctx, config)
		handleCreateAppInstanceStatus(ctx, config)
		assert.Equal(t, 4, snapshotConfig(ctx, rollbackTestSnapshot).RollbackCount)
		assert.Empty(t, lookupAppInstanceStatus(ctx, config.Key()).Error)
		assert.Empty(t, ctx.pubVolumeRefConfig.GetAll(), "the app must wait for the rollback")
	})
}

// An app whose config comes before volumemgr has told which snapshots exist
// has to wait. It must be there when the wait is over: what ends the wait
// finds the app by its status.
func TestAppCreatedBeforeTheSnapshotsAreKnownIsTakenUpLater(t *testing.T) {
	ctx, config := newIdleAppTestContext(t, nil, nil)
	unpublishAppInstanceStatus(ctx, lookupAppInstanceStatus(ctx, config.Key()))
	config.FixedResources.Memory, config.FixedResources.VCpus = 1024, 1
	useAppConfig(t, ctx, config)
	ctx.snapshotsRestored = false

	handleCreateAppInstanceStatus(ctx, config)

	status := lookupAppInstanceStatus(ctx, config.Key())
	if assert.NotNil(t, status, "nothing would take the app up again") {
		assert.Empty(t, status.Error)
	}
	assert.Empty(t, ctx.pubVolumeRefConfig.GetAll(), "the app has to wait")

	handleVolumesSnapshotStatusRestarted(ctx, 1)
	assert.NotEmpty(t, ctx.pubVolumeRefConfig.GetAll(), "the app goes on once the snapshots are known")
}

// An app that is uninstalled takes its snapshots along. volumemgr drops a
// snapshot without working on images that are on their way out, so the
// configs of the snapshots are taken away only when volumemgr has let go of
// the volumes.
func TestUninstallTakesTheSnapshotsAlong(t *testing.T) {
	ctx, config := newRollbackTestContext(t)
	appUUID := config.UUIDandVersion.UUID
	ref := config.VolumeRefConfigList[0]
	publishVolumeRefConfig(ctx, &ref)
	held := types.VolumeRefStatus{VolumeID: ref.VolumeID, AppUUID: appUUID}
	status := &types.AppInstanceStatus{
		UUIDandVersion:      config.UUIDandVersion,
		VolumeRefStatusList: []types.VolumeRefStatus{held},
	}

	// doRemove is what removeAIStatus goes by: the status of the app has to
	// stay until the uninstall is done, or nothing comes back to finish it.
	ctx.subVolumeRefStatus = newDoInstallTestContext(t, []types.VolumeRefStatus{held}).subVolumeRefStatus
	_, done := doRemove(ctx, status, true)
	assert.False(t, done)
	assert.Empty(t, ctx.pubVolumeRefConfig.GetAll())
	assert.NotNil(t, snapshotConfig(ctx, rollbackTestSnapshot),
		"volumemgr would work on the image of a volume that it is about to destroy")

	ctx.subVolumeRefStatus = newDoInstallTestContext(t, nil).subVolumeRefStatus
	_, done = doRemove(ctx, status, true)
	assert.True(t, done)
	assert.Nil(t, snapshotConfig(ctx, rollbackTestSnapshot))
}
