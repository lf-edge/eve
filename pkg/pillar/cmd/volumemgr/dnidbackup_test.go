// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// newVolumeGateCtx mirrors zedmanager's newGateCtx (cmd/zedmanager/dnidbackup_test.go):
// a bare context wired with a stubbed isCurrentlyBackupDNIDFunc that records how many
// times it was called and always answers backup, so a test can assert whether the
// (expensive, live-API) health check was ever reached.
func newVolumeGateCtx(backup bool) (*volumemgrContext, *int) {
	calls := 0
	ctx := &volumemgrContext{
		hvTypeKube:   true,
		globalConfig: types.DefaultConfigItemValueMap(),
		isCurrentlyBackupDNIDFunc: func(*base.LogObject, kubeapi.NodeHealthLookup,
			string, bool, types.Affinity, time.Duration) bool {
			calls++
			return backup
		},
	}
	return ctx, &calls
}

func replicatedVolumeConfig(designatedNodeUUID string, affinity types.Affinity) types.VolumeConfig {
	u, _ := uuid.NewV4()
	return types.VolumeConfig{
		VolumeID:           u,
		IsReplicated:       true,
		DesignatedNodeUUID: designatedNodeUUID,
		AffinityType:       affinity,
	}
}

// isCurrentlyBackupDNIDForVolume must refuse before spending an API call on the
// cases that cannot possibly qualify -- mirrors zedmanager's
// TestBackupDNIDForAppEarlyOuts for the same reason.
func TestBackupDNIDForVolumeEarlyOuts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*volumemgrContext, *types.VolumeConfig)
		wantCall bool
	}{{
		name: "not the lease holder",
		mutate: func(ctx *volumemgrContext, _ *types.VolumeConfig) {
			ctx.isAppOpLeader = false
		},
		wantCall: false,
	}, {
		name: "not a cluster build",
		mutate: func(ctx *volumemgrContext, _ *types.VolumeConfig) {
			ctx.isAppOpLeader = true
			ctx.hvTypeKube = false
		},
		wantCall: false,
	}, {
		name: "volume has no designated node",
		mutate: func(ctx *volumemgrContext, cfg *types.VolumeConfig) {
			ctx.isAppOpLeader = true
			cfg.DesignatedNodeUUID = ""
		},
		wantCall: false,
	}, {
		name: "nil config",
		mutate: func(ctx *volumemgrContext, cfg *types.VolumeConfig) {
			ctx.isAppOpLeader = true
			*cfg = types.VolumeConfig{}
		},
		wantCall: false,
	}, {
		name: "eligible to ask",
		mutate: func(ctx *volumemgrContext, _ *types.VolumeConfig) {
			ctx.isAppOpLeader = true
		},
		wantCall: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, calls := newVolumeGateCtx(true)
			config := replicatedVolumeConfig("designated-node-uuid", types.PreferredDuringScheduling)
			tc.mutate(ctx, &config)

			if tc.name == "nil config" {
				isCurrentlyBackupDNIDForVolume(ctx, nil)
			} else {
				isCurrentlyBackupDNIDForVolume(ctx, &config)
			}
			if got := *calls > 0; got != tc.wantCall {
				t.Errorf("health check consulted = %v, want %v", got, tc.wantCall)
			}
		})
	}
}

func TestVolumeDnidOutageThreshold(t *testing.T) {
	ctx := &volumemgrContext{globalConfig: types.DefaultConfigItemValueMap()}
	if got := dnidOutageThreshold(ctx); got != 10*time.Minute {
		t.Errorf("default threshold = %v, want 10m", got)
	}

	ctx.globalConfig.SetGlobalValueInt(types.DnidOutageThresholdForUsage, 120)
	if got := dnidOutageThreshold(ctx); got != 2*time.Minute {
		t.Errorf("configured threshold = %v, want 2m", got)
	}

	// A context with no config yet must not claim a threshold has passed.
	if got := dnidOutageThreshold(&volumemgrContext{}); got != 0 {
		t.Errorf("threshold with no config = %v, want 0", got)
	}
}

// TestHandleKubeLeaderElectInfo exercises the create/modify/delete transitions
// directly, mirroring the plain state-flip zedmanager's own handlers make (untested
// there too -- these are thin enough that the value is in the transition table).
func TestHandleKubeLeaderElectInfo(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-volumemgr", 0)

	// Gaining the lease re-drives reevaluateBackupDNIDVolumes/Content at
	// once, which need a real (if empty) pubVolumeStatus/pubContentTreeStatus
	// to range over.
	logger := logrus.StandardLogger()
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)
	pubVolumeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumeStatus{},
	})
	if err != nil {
		t.Fatalf("NewPublication(VolumeStatus): %v", err)
	}
	pubContentTreeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ContentTreeStatus{},
	})
	if err != nil {
		t.Fatalf("NewPublication(ContentTreeStatus): %v", err)
	}
	ctx := &volumemgrContext{
		pubVolumeStatus:      pubVolumeStatus,
		pubContentTreeStatus: pubContentTreeStatus,
	}
	handleKubeLeaderElectInfoCreate(ctx, "eve-app-op",
		types.KubeLeaderElectInfo{IsAppOpLeader: false})
	if ctx.isAppOpLeader {
		t.Fatalf("isAppOpLeader = true after a not-leader Create, want false")
	}

	handleKubeLeaderElectInfoModify(ctx, "eve-app-op",
		types.KubeLeaderElectInfo{IsAppOpLeader: true}, types.KubeLeaderElectInfo{})
	if !ctx.isAppOpLeader {
		t.Fatalf("isAppOpLeader = false after a leader Modify, want true")
	}

	handleKubeLeaderElectInfoDelete(ctx, "eve-app-op", types.KubeLeaderElectInfo{})
	if ctx.isAppOpLeader {
		t.Fatalf("isAppOpLeader = true after Delete, want false")
	}
}

// TestDoUpdateVolReplicatedGate is the regression/behavior-change test for the
// live-confirmed bug: a replicated volume must still park at CREATED_VOLUME when
// backup-DNID eligibility cannot be determined (config not found -- the pre-existing
// behavior, preserved), but must NOT be force-parked there once this node is
// confirmed eligible to act as backup DNID for it (the fix).
func TestDoUpdateVolReplicatedGate(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-volumemgr", 0)

	t.Run("no VolumeConfig found: still parks at CREATED_VOLUME", func(t *testing.T) {
		ctx, _ := initVolumeModifyCtxForTest(t)
		status := &types.VolumeStatus{
			VolumeID:     mustNewUUID(t),
			IsReplicated: true,
			State:        types.INITIAL,
		}
		changed, ok := doUpdateVol(ctx, status)
		if !changed || !ok {
			t.Errorf("doUpdateVol returned (%v, %v), want (true, true)", changed, ok)
		}
		if status.State != types.CREATED_VOLUME || status.SubState != types.VolumeSubStateCreated {
			t.Errorf("status = %v/%v, want CREATED_VOLUME/VolumeSubStateCreated",
				status.State, status.SubState)
		}
	})

	t.Run("eligible backup DNID: does not force CREATED_VOLUME", func(t *testing.T) {
		ctx, pubVolumeConfig := initVolumeModifyCtxForTest(t)
		ctx.hvTypeKube = true
		ctx.isAppOpLeader = true
		ctx.isCurrentlyBackupDNIDFunc = func(*base.LogObject, kubeapi.NodeHealthLookup,
			string, bool, types.Affinity, time.Duration) bool {
			return true
		}

		volID := mustNewUUID(t)
		config := types.VolumeConfig{
			VolumeID:           volID,
			IsReplicated:       true,
			DesignatedNodeUUID: "designated-node-uuid",
			AffinityType:       types.PreferredDuringScheduling,
		}
		publishTestVolumeConfig(t, ctx, pubVolumeConfig, config)

		status := &types.VolumeStatus{
			VolumeID:     volID,
			IsReplicated: true,
			State:        types.INITIAL,
		}
		changed, ok := doUpdateVol(ctx, status)
		if changed && ok && status.SubState == types.VolumeSubStateCreated {
			t.Errorf("doUpdateVol took the replicated short-circuit (state %v/%v) despite eligible backup DNID",
				status.State, status.SubState)
		}
	})
}

func mustNewUUID(t *testing.T) uuid.UUID {
	t.Helper()
	u, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("uuid.NewV4: %v", err)
	}
	return u
}

// initVolumeModifyCtxForTest builds on the package's own initVolumeModifyCtx
// (handlevolume_test.go) -- which wires up everything doUpdateVol's call
// chain touches (subVolumeRefConfig, pubVolumeStatus, globalConfig, etc.),
// but over EmptyDriver, so nothing is ever actually found by a lookup -- and
// replaces just its subVolumeConfig with one over pubsub.NewMemoryDriver,
// which (unlike EmptyDriver) actually routes a Publish to a Subscription in
// the same process, so ctx.LookupVolumeConfig can be exercised with real
// data. Returns the matching Publication too, for a test to publish with.
func initVolumeModifyCtxForTest(t *testing.T) (*volumemgrContext, pubsub.Publication) {
	t.Helper()
	ctx := initVolumeModifyCtx(t)

	logger := logrus.StandardLogger()
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	pubVolumeConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "zedagent",
		TopicType: types.VolumeConfig{},
	})
	if err != nil {
		t.Fatalf("NewPublication(VolumeConfig): %v", err)
	}

	subVolumeConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.VolumeConfig{},
		Ctx:         ctx,
	})
	if err != nil {
		t.Fatalf("NewSubscription(VolumeConfig): %v", err)
	}
	ctx.subVolumeConfig = subVolumeConfig
	if err := subVolumeConfig.Activate(); err != nil {
		t.Fatalf("Activate(VolumeConfig): %v", err)
	}
	return ctx, pubVolumeConfig
}

func publishTestVolumeConfig(t *testing.T, ctx *volumemgrContext,
	pub pubsub.Publication, config types.VolumeConfig) {
	t.Helper()
	if err := pub.Publish(config.Key(), config); err != nil {
		t.Fatalf("Publish(VolumeConfig): %v", err)
	}
	// MemoryDriver notifies asynchronously over a channel; ProcessChange
	// drains and applies it, matching every real subscription's usage of
	// MsgChan()/ProcessChange() in the main select loop.
	change := <-ctx.subVolumeConfig.MsgChan()
	ctx.subVolumeConfig.ProcessChange(change)
}

// isCurrentlyBackupDNIDForContentTree must refuse before spending an API
// call on the cases that cannot possibly qualify -- same shape as
// TestBackupDNIDForVolumeEarlyOuts, for the content-tree counterpart.
func TestBackupDNIDForContentTreeEarlyOuts(t *testing.T) {
	contentTreeConfig := func(designatedNodeUUID string) types.ContentTreeConfig {
		return types.ContentTreeConfig{
			ContentID:          mustNewUUID(t),
			DesignatedNodeUUID: designatedNodeUUID,
		}
	}

	for _, tc := range []struct {
		name     string
		mutate   func(*volumemgrContext, *types.ContentTreeConfig)
		wantCall bool
	}{{
		name: "not the lease holder",
		mutate: func(ctx *volumemgrContext, _ *types.ContentTreeConfig) {
			ctx.isAppOpLeader = false
		},
		wantCall: false,
	}, {
		name: "not a cluster build",
		mutate: func(ctx *volumemgrContext, _ *types.ContentTreeConfig) {
			ctx.isAppOpLeader = true
			ctx.hvTypeKube = false
		},
		wantCall: false,
	}, {
		name: "content tree has no designated node",
		mutate: func(ctx *volumemgrContext, cfg *types.ContentTreeConfig) {
			ctx.isAppOpLeader = true
			cfg.DesignatedNodeUUID = ""
		},
		wantCall: false,
	}, {
		name: "eligible to ask",
		mutate: func(ctx *volumemgrContext, _ *types.ContentTreeConfig) {
			ctx.isAppOpLeader = true
		},
		wantCall: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, calls := newVolumeGateCtx(true)
			// contentTreeAffinity's own scan needs a real, if empty,
			// subscription -- no volume references this tree in these cases.
			ps := pubsub.New(&pubsub.EmptyDriver{}, logrus.StandardLogger(), log)
			subVolumeConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
				AgentName:   "zedagent",
				MyAgentName: agentName,
				TopicImpl:   types.VolumeConfig{},
				Ctx:         ctx,
			})
			if err != nil {
				t.Fatalf("NewSubscription(VolumeConfig): %v", err)
			}
			ctx.subVolumeConfig = subVolumeConfig
			if err := subVolumeConfig.Activate(); err != nil {
				t.Fatalf("Activate(VolumeConfig): %v", err)
			}

			config := contentTreeConfig("designated-node-uuid")
			tc.mutate(ctx, &config)

			isCurrentlyBackupDNIDForContentTree(ctx, &config)
			if got := *calls > 0; got != tc.wantCall {
				t.Errorf("health check consulted = %v, want %v", got, tc.wantCall)
			}
		})
	}

	t.Run("nil config", func(t *testing.T) {
		ctx, calls := newVolumeGateCtx(true)
		ctx.isAppOpLeader = true
		isCurrentlyBackupDNIDForContentTree(ctx, nil)
		if *calls != 0 {
			t.Errorf("health check consulted for a nil config, want not consulted")
		}
	})
}

// contentTreeAffinity must merge to Required if any referencing volume is,
// and default to Preferred when nothing references the content tree yet.
func TestContentTreeAffinity(t *testing.T) {
	contentID := mustNewUUID(t)

	t.Run("no referencing volume: Preferred", func(t *testing.T) {
		ctx, pubVolumeConfig := initVolumeModifyCtxForTest(t)
		other := types.VolumeConfig{VolumeID: mustNewUUID(t), ContentID: mustNewUUID(t)}
		publishTestVolumeConfig(t, ctx, pubVolumeConfig, other)

		if got := contentTreeAffinity(ctx, contentID); got != types.PreferredDuringScheduling {
			t.Errorf("affinity = %v, want PreferredDuringScheduling", got)
		}
	})

	t.Run("referencing volume is Required: Required", func(t *testing.T) {
		ctx, pubVolumeConfig := initVolumeModifyCtxForTest(t)
		referencing := types.VolumeConfig{
			VolumeID:     mustNewUUID(t),
			ContentID:    contentID,
			AffinityType: types.RequiredDuringScheduling,
		}
		publishTestVolumeConfig(t, ctx, pubVolumeConfig, referencing)

		if got := contentTreeAffinity(ctx, contentID); got != types.RequiredDuringScheduling {
			t.Errorf("affinity = %v, want RequiredDuringScheduling", got)
		}
	})
}
