// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestPruneStaleMasterDue(t *testing.T) {
	now := time.Now()
	recent := now.Add(-time.Minute)
	old := now.Add(-pruneStaleMasterInterval * time.Second)

	assert.True(t, pruneStaleMasterDue(true, recent, now),
		"a pending sweep is retried on every tick")
	assert.False(t, pruneStaleMasterDue(false, recent, now),
		"a completed sweep is not repeated before the interval")
	assert.True(t, pruneStaleMasterDue(false, old, now),
		"a completed sweep is repeated once the interval has passed")
	assert.True(t, pruneStaleMasterDue(false, time.Time{}, now),
		"the first sweep is not delayed by the interval")
}

func masterNode(name, nodeUUID string) *corev1.Node {
	labels := map[string]string{controlPlaneRoleLabel: "true"}
	if nodeUUID != "" {
		labels[nodeUUIDLabel] = nodeUUID
	}
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func nodeNames(t *testing.T, client *fake.Clientset) []string {
	nodes, err := client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	assert.NoError(t, err)
	var names []string
	for _, n := range nodes.Items {
		names = append(names, n.Name)
	}
	return names
}

func TestDeleteStaleMasterNodes(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-zedkube", 0)
	client := fake.NewSimpleClientset(
		masterNode("kept", "kept-uuid"),
		masterNode("stale", "stale-uuid"),
		masterNode("self", "self-uuid"),
		masterNode("unlabeled", ""),
	)
	keep := map[string]struct{}{"kept-uuid": {}}

	assert.True(t, deleteStaleMasterNodes(client, keep, "self-uuid"))
	assert.ElementsMatch(t, []string{"kept", "self", "unlabeled"}, nodeNames(t, client))
}

func TestDeleteStaleMasterNodesFailureLeavesSweepPending(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-zedkube", 0)
	client := fake.NewSimpleClientset(masterNode("stale", "stale-uuid"))
	client.PrependReactor("delete", "nodes",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver unavailable")
		})

	assert.False(t, deleteStaleMasterNodes(client, map[string]struct{}{}, "self-uuid"))
}

func TestDeleteStaleMasterNodesListFailure(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-zedkube", 0)
	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "nodes",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver unavailable")
		})

	assert.False(t, deleteStaleMasterNodes(client, map[string]struct{}{}, "self-uuid"))
}
