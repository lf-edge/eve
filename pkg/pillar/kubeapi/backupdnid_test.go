// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/sirupsen/logrus"
)

func testLog() *base.LogObject {
	return base.NewSourceLogObject(logrus.StandardLogger(), "test-kubeapi", 0)
}

// nodeWithReady builds a node carrying the device UUID label and a Ready
// condition in the given state, last transitioned the given time ago.
func nodeWithReady(name, uuid string, status corev1.ConditionStatus,
	ago time.Duration) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{nodeUUIDLabel: uuid},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{
				Type:               corev1.NodeReady,
				Status:             status,
				LastTransitionTime: metav1.NewTime(time.Now().Add(-ago)),
			}},
		},
	}
}

// nodeWithoutCondition builds a node that has never reported readiness.
func nodeWithoutCondition(name, uuid string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{nodeUUIDLabel: uuid},
		},
	}
}

func TestIsCurrentlyBackupDNIDWithClient(t *testing.T) {
	const threshold = 10 * time.Minute

	for _, tc := range []struct {
		name    string
		node    *corev1.Node
		want    bool
		wantErr bool
	}{{
		// The designated node is fine; nobody stands in for it.
		name: "ready node",
		node: nodeWithReady("n1", "uuid-1", corev1.ConditionTrue, time.Hour),
		want: false,
	}, {
		// A hard power-off leaves Ready at Unknown, not False. This is the
		// case the whole feature exists for, so it must be the one that
		// most clearly returns true.
		name: "unknown past threshold",
		node: nodeWithReady("n1", "uuid-1", corev1.ConditionUnknown, time.Hour),
		want: true,
	}, {
		name: "unknown under threshold",
		node: nodeWithReady("n1", "uuid-1", corev1.ConditionUnknown, time.Minute),
		want: false,
	}, {
		// A node reporting itself broken counts too.
		name: "false past threshold",
		node: nodeWithReady("n1", "uuid-1", corev1.ConditionFalse, time.Hour),
		want: true,
	}, {
		name: "false under threshold",
		node: nodeWithReady("n1", "uuid-1", corev1.ConditionFalse, time.Minute),
		want: false,
	}, {
		// time.Since of the zero time is centuries, which would clear any
		// threshold instantly. Unusable, not unhealthy.
		name:    "zero transition time",
		node:    nodeWithReady("n1", "uuid-1", corev1.ConditionUnknown, 0),
		want:    false,
		wantErr: false,
	}, {
		name:    "no ready condition",
		node:    nodeWithoutCondition("n1", "uuid-1"),
		want:    false,
		wantErr: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			nodeNameByUUID.Delete("uuid-1")
			client := fake.NewSimpleClientset(tc.node)
			got, err := isCurrentlyBackupDNIDWithClient(testLog(), client,
				"uuid-1", threshold)
			if got != tc.want {
				t.Errorf("got %v, want %v (err %v)", got, tc.want, err)
			}
			if tc.wantErr && err == nil {
				t.Error("expected an error explaining why it could not confirm")
			}
		})
	}
}

// A zero LastTransitionTime must not read as an eternity of downtime. Asserted
// separately because metav1.NewTime of the zero time is what a node object
// that never reported actually carries.
func TestZeroTransitionTimeIsNotAnOutage(t *testing.T) {
	nodeNameByUUID.Delete("uuid-z")
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nz",
			Labels: map[string]string{nodeUUIDLabel: "uuid-z"},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{
				Type:   corev1.NodeReady,
				Status: corev1.ConditionUnknown,
				// LastTransitionTime deliberately left zero.
			}},
		},
	}
	client := fake.NewSimpleClientset(node)
	got, err := isCurrentlyBackupDNIDWithClient(testLog(), client, "uuid-z",
		time.Minute)
	if got {
		t.Error("a zero Ready timestamp was treated as a crossed threshold")
	}
	if err == nil {
		t.Error("expected an error naming the unusable timestamp")
	}
}

// Required affinity is excluded by IsCurrentlyBackupDNID, not by
// backupDNIDEligible underneath it: the exclusion exists to stop a peer
// creating resources on a node the app can never run on, which only applies
// to a caller that would place something.
func TestRequiredAffinityExcludedOnlyForCreate(t *testing.T) {
	if IsCurrentlyBackupDNID(testLog(), "uuid-1", true,
		types.RequiredDuringScheduling, time.Minute) {
		t.Error("Required affinity was allowed through the activate path")
	}
}

// backupDNIDEligible refuses before touching the API when this node does
// not hold the lease or the app has no designated node, so a non-leader
// costs nothing per app per tick.
func TestBackupDNIDEarlyOuts(t *testing.T) {
	for _, tc := range []struct {
		name          string
		dnid          string
		isAppOpLeader bool
	}{
		{"not the lease holder", "uuid-1", false},
		{"no designated node", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if backupDNIDEligible(testLog(), tc.dnid, tc.isAppOpLeader,
				time.Minute) {
				t.Error("eligible despite the early-out condition")
			}
		})
	}
}

// The UUID-to-name lookup uses the label kube-init stamps, and caches it so
// the label-selector List stays off the health path.
func TestNodeNameFromUUIDCaches(t *testing.T) {
	nodeNameByUUID.Delete("uuid-c")
	client := fake.NewSimpleClientset(
		nodeWithReady("cached-node", "uuid-c", corev1.ConditionTrue, time.Hour))

	name, err := nodeNameForHealth(testLog(), client, "uuid-c")
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if name != "cached-node" {
		t.Errorf("got %q, want cached-node", name)
	}
	if _, ok := nodeNameByUUID.Load("uuid-c"); !ok {
		t.Error("the mapping was not cached")
	}

	// An empty client still answers from the cache.
	if again, err := nodeNameForHealth(testLog(), fake.NewSimpleClientset(),
		"uuid-c"); err != nil || again != "cached-node" {
		t.Errorf("cache miss: got %q err %v", again, err)
	}
}

// An unlabeled cluster cannot be resolved, and that has to surface as an error
// rather than as a false claim about health.
func TestNodeNameFromUUIDUnknown(t *testing.T) {
	nodeNameByUUID.Delete("uuid-missing")
	if _, err := nodeNameForHealth(testLog(), fake.NewSimpleClientset(),
		"uuid-missing"); err == nil {
		t.Error("expected an error for an unresolvable UUID")
	}
}
