// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

func init() {
	if log == nil {
		logger = logrus.StandardLogger()
		log = base.NewSourceLogObject(logger, "test-zedmanager", 0)
	}
}

// onTheDeviceForApp's placement terms must decide without consulting the
// backup question, because answering that costs a live Kubernetes read on
// every app on every pass.
func TestOnTheDeviceForApp(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      *types.ENClusterAppStatus
		backup      bool
		want        bool
		wantBackupQ bool // was the expensive question asked?
	}{{
		name:        "this node owns it",
		status:      &types.ENClusterAppStatus{IsDNidNode: true},
		backup:      false,
		want:        true,
		wantBackupQ: false,
	}, {
		name:        "pod already scheduled here",
		status:      &types.ENClusterAppStatus{ScheduledOnThisNode: true},
		backup:      false,
		want:        true,
		wantBackupQ: false,
	}, {
		name:        "elsewhere, not backup",
		status:      &types.ENClusterAppStatus{},
		backup:      false,
		want:        false,
		wantBackupQ: true,
	}, {
		name:        "elsewhere, standing in",
		status:      &types.ENClusterAppStatus{},
		backup:      true,
		want:        true,
		wantBackupQ: true,
	}, {
		// Never placed anywhere: only a node standing in for a downed
		// owner should act.
		name:        "no cluster status, not backup",
		status:      nil,
		backup:      false,
		want:        false,
		wantBackupQ: true,
	}, {
		name:        "no cluster status, standing in",
		status:      nil,
		backup:      true,
		want:        true,
		wantBackupQ: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			asked := false
			got := onTheDeviceForApp(tc.status, func() bool {
				asked = true
				return tc.backup
			})
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
			if asked != tc.wantBackupQ {
				t.Errorf("backup question asked = %v, want %v", asked, tc.wantBackupQ)
			}
		})
	}
}

// newGateCtx builds a context whose backup decision is stubbed, recording
// whether it was consulted.
func newGateCtx(backup bool) (*zedmanagerContext, *int) {
	calls := 0
	ctx := &zedmanagerContext{
		hvTypeKube:   true,
		globalConfig: types.DefaultConfigItemValueMap(),
		isCurrentlyBackupDNIDFunc: func(*base.LogObject, string, bool,
			types.Affinity, time.Duration) bool {
			calls++
			return backup
		},
	}
	return ctx, &calls
}

func clusterAppConfig(isDNID bool, affinity types.Affinity) types.AppInstanceConfig {
	u, _ := uuid.NewV4()
	dnid, _ := uuid.NewV4()
	return types.AppInstanceConfig{
		UUIDandVersion:     types.UUIDandVersion{UUID: u},
		IsDesignatedNodeID: isDNID,
		DesignatedNodeUUID: dnid.String(),
		AffinityType:       affinity,
	}
}

// isCurrentlyBackupDNIDForApp refuses before spending an API call on the cases
// that cannot possibly qualify.
func TestBackupDNIDForAppEarlyOuts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*zedmanagerContext, *types.AppInstanceConfig)
		wantCall bool
	}{{
		name: "not the lease holder",
		mutate: func(ctx *zedmanagerContext, _ *types.AppInstanceConfig) {
			ctx.isAppOpLeader = false
		},
		wantCall: false,
	}, {
		name: "not a cluster build",
		mutate: func(ctx *zedmanagerContext, _ *types.AppInstanceConfig) {
			ctx.isAppOpLeader = true
			ctx.hvTypeKube = false
		},
		wantCall: false,
	}, {
		name: "app has no designated node",
		mutate: func(ctx *zedmanagerContext, cfg *types.AppInstanceConfig) {
			ctx.isAppOpLeader = true
			cfg.DesignatedNodeUUID = ""
		},
		wantCall: false,
	}, {
		name: "this node is the designated node",
		mutate: func(ctx *zedmanagerContext, cfg *types.AppInstanceConfig) {
			ctx.isAppOpLeader = true
			cfg.IsDesignatedNodeID = true
		},
		wantCall: false,
	}, {
		name: "eligible to ask",
		mutate: func(ctx *zedmanagerContext, _ *types.AppInstanceConfig) {
			ctx.isAppOpLeader = true
		},
		wantCall: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, calls := newGateCtx(true)
			config := clusterAppConfig(false, types.PreferredDuringScheduling)
			tc.mutate(ctx, &config)

			isCurrentlyBackupDNIDForApp(ctx, config)
			if got := *calls > 0; got != tc.wantCall {
				t.Errorf("health check consulted = %v, want %v", got, tc.wantCall)
			}
		})
	}
}

// The threshold comes from config, in seconds.
func TestDnidOutageThreshold(t *testing.T) {
	ctx := &zedmanagerContext{globalConfig: types.DefaultConfigItemValueMap()}
	if got := dnidOutageThreshold(ctx); got != 10*time.Minute {
		t.Errorf("default threshold = %v, want 10m", got)
	}

	ctx.globalConfig.SetGlobalValueInt(types.DnidOutageThresholdForUsage, 120)
	if got := dnidOutageThreshold(ctx); got != 2*time.Minute {
		t.Errorf("configured threshold = %v, want 2m", got)
	}

	// A context with no config yet must not claim a threshold has passed.
	if got := dnidOutageThreshold(&zedmanagerContext{}); got != 0 {
		t.Errorf("threshold with no config = %v, want 0", got)
	}
}
