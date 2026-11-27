// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types_test

import (
	"testing"
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestClusterNodeConnectionToProto pins what is reported for each
// quorum state: only a lost quorum marks the cluster as down, as
// readiness of the node itself is not this report's business.
func TestClusterNodeConnectionToProto(t *testing.T) {
	cases := []struct {
		name       string
		conn       types.ClusterNodeConnection
		wantQuorum info.ZInfoClusterNodeQuorum
		wantStatus info.ZInfoClusterNodeStatus
		wantError  bool
	}{
		{
			name:       "unknown",
			conn:       types.ClusterNodeConnection{ClusterID: "c1"},
			wantQuorum: info.ZInfoClusterNodeQuorum_Z_INFO_CLUSTER_NODE_QUORUM_UNSPECIFIED,
			wantStatus: info.ZInfoClusterNodeStatus_Z_INFO_CLUSTER_NODE_STATUS_UNSPECIFIED,
		},
		{
			name:       "quorum established",
			conn:       types.ClusterNodeConnection{ClusterID: "c1", Quorum: types.ClusterQuorumEstablished},
			wantQuorum: info.ZInfoClusterNodeQuorum_Z_INFO_CLUSTER_NODE_QUORUM_ESTABLISHED,
			wantStatus: info.ZInfoClusterNodeStatus_Z_INFO_CLUSTER_NODE_STATUS_UNSPECIFIED,
		},
		{
			name: "lost quorum",
			conn: types.ClusterNodeConnection{
				ClusterID: "c1",
				Quorum:    types.ClusterQuorumLost,
			},
			wantQuorum: info.ZInfoClusterNodeQuorum_Z_INFO_CLUSTER_NODE_QUORUM_LOST,
			wantStatus: info.ZInfoClusterNodeStatus_Z_INFO_CLUSTER_NODE_STATUS_DOWN,
			wantError:  true,
		},
	}
	cases[2].conn.Error.SetErrorDescription(types.ErrorDescription{Error: "etcdserver: no leader"})
	for _, c := range cases {
		got := c.conn.ZInfoClusterNode()
		if got.GetClusterId() != "c1" {
			t.Errorf("%s: cluster id = %q, want c1", c.name, got.GetClusterId())
		}
		if got.GetQuorum() != c.wantQuorum {
			t.Errorf("%s: quorum = %v, want %v", c.name, got.GetQuorum(), c.wantQuorum)
		}
		if got.GetNodeStatus() != c.wantStatus {
			t.Errorf("%s: node status = %v, want %v", c.name, got.GetNodeStatus(), c.wantStatus)
		}
		if (got.GetError() != nil) != c.wantError {
			t.Errorf("%s: error set = %v, want %v", c.name, got.GetError() != nil, c.wantError)
		}
	}
}

// TestClusterNodeConnectionQuorumChangeTime pins that the time is carried
// when set and left out when not, so an unknown quorum reports no time.
func TestClusterNodeConnectionQuorumChangeTime(t *testing.T) {
	changed := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	conn := types.ClusterNodeConnection{
		ClusterID:        "c1",
		Quorum:           types.ClusterQuorumEstablished,
		QuorumChangeTime: changed,
	}
	if got := conn.ZInfoClusterNode().GetQuorumChangeTime(); got == nil || !got.AsTime().Equal(changed) {
		t.Errorf("quorum change time = %v, want %v", got, changed)
	}
	if got := (types.ClusterNodeConnection{ClusterID: "c1"}).ZInfoClusterNode().GetQuorumChangeTime(); got != nil {
		t.Errorf("unknown quorum reported change time %v, want none", got)
	}
}
