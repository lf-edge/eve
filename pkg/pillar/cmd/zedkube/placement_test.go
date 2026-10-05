// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func designatedHere(name string) types.AppInstanceConfig {
	aiconfig := mkAppInstanceConfig(name, true, types.PV)
	aiconfig.DesignatedNodeUUID = "this-node-uuid"
	return aiconfig
}

func TestIsMisplaced(t *testing.T) {
	runningElsewhere := types.ENClusterAppStatus{AppKubeStatus: types.AppKubeStatusRunningState}

	notDesignated := mkAppInstanceConfig("not-designated", false, types.PV)
	notDesignated.DesignatedNodeUUID = "other-node-uuid"
	// Without a designated node every node counts as designated.
	noDesignatedNode := mkAppInstanceConfig("no-designated-node", true, types.PV)
	required := designatedHere("required")
	required.AffinityType = types.RequiredDuringScheduling

	tests := []struct {
		name     string
		aiconfig types.AppInstanceConfig
		status   types.ENClusterAppStatus
		want     bool
	}{
		{"designated here, running elsewhere", designatedHere("app"), runningElsewhere, true},
		{"designated here, running here", designatedHere("app"),
			types.ENClusterAppStatus{ScheduledOnThisNode: true,
				AppKubeStatus: types.AppKubeStatusRunningState}, false},
		{"designated here, not running", designatedHere("app"),
			types.ENClusterAppStatus{AppKubeStatus: types.AppKubeStatusNotRunningState}, false},
		{"designated here, API unreachable", designatedHere("app"),
			types.ENClusterAppStatus{AppKubeStatus: types.AppKubeStatusAPIUnreachable}, false},
		{"designated elsewhere", notDesignated, runningElsewhere, false},
		{"no designated node", noDesignatedNode, runningElsewhere, false},
		{"required affinity", required, runningElsewhere, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isMisplaced(tt.aiconfig, tt.status))
		})
	}
}

func appPod(name, nodeName, affinityNode string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
			Affinity: hypervisor.SetKubeAffinity(affinityNode, types.PreferredDuringScheduling),
		},
	}
}

func TestPlanPlacement(t *testing.T) {
	failedOver := designatedHere("failed-over")
	reassigned := designatedHere("reassigned")
	reassignedNative := mkAppInstanceConfig("reassigned-native", true, types.NOHYPER)
	reassignedNative.DesignatedNodeUUID = "this-node-uuid"
	gone := designatedHere("gone")

	terminating := appPod(appKubeName(failedOver)+"-old", testNodeName, testNodeName)
	terminating.DeletionTimestamp = &metav1.Time{}
	pods := []corev1.Pod{
		terminating,
		// Moved away by a failover: still prefers this node.
		appPod("virt-launcher-"+appKubeName(failedOver)+"-abcde", "other-node", testNodeName),
		// Designated here after it started: prefers the other node.
		appPod("virt-launcher-"+appKubeName(reassigned)+"-abcde", "other-node", "other-node"),
		appPod(appKubeName(reassignedNative)+"-abcde", "other-node", "other-node"),
	}

	plan := planPlacement(testNodeName,
		[]types.AppInstanceConfig{failedOver, reassigned, reassignedNative, gone}, pods)

	assert.Len(t, plan.deschedule, 1)
	assert.Equal(t, "failed-over", plan.deschedule[0].aiconfig.DisplayName,
		"a failed-over app is the descheduler's to move")
	assert.Len(t, plan.stale, 2)
	stale := map[string]misplacedApp{}
	for _, app := range plan.stale {
		stale[app.aiconfig.DisplayName] = app
	}
	assert.True(t, stale["reassigned"].isVMI)
	assert.False(t, stale["reassigned-native"].isVMI)
	assert.Equal(t, appKubeName(reassignedNative)+"-abcde", stale["reassigned-native"].pod.Name)
}

func TestPlanPlacementNothingToDeschedule(t *testing.T) {
	reassigned := designatedHere("reassigned")
	pods := []corev1.Pod{
		appPod("virt-launcher-"+appKubeName(reassigned)+"-abcde", "other-node", "other-node"),
	}
	plan := planPlacement(testNodeName, []types.AppInstanceConfig{reassigned}, pods)
	assert.Empty(t, plan.deschedule)
	assert.Len(t, plan.stale, 1)
}

func TestMoveReplicaSetPod(t *testing.T) {
	const rsName = "native-app-abcde-0"
	const podName = rsName + "-fghij"
	clientset := fake.NewSimpleClientset(
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: rsName, Namespace: kubeapi.EVEKubeNameSpace},
			Spec: appsv1.ReplicaSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Affinity: hypervisor.SetKubeAffinity("other-node", types.PreferredDuringScheduling),
			}}},
		},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: kubeapi.EVEKubeNameSpace}},
	)

	err := moveReplicaSetPod(clientset, testNodeName, rsName, podName,
		types.PreferredDuringScheduling)
	assert.NoError(t, err)

	rs, err := clientset.AppsV1().ReplicaSets(kubeapi.EVEKubeNameSpace).Get(
		context.Background(), rsName, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, testNodeName, affinityNode(rs.Spec.Template.Spec.Affinity))
	_, err = clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).Get(
		context.Background(), podName, metav1.GetOptions{})
	assert.True(t, k8serrors.IsNotFound(err), "the pod must be deleted, got %v", err)
}

func TestMoveReplicaSetPodPodAlreadyGone(t *testing.T) {
	const rsName = "native-app-abcde-0"
	clientset := fake.NewSimpleClientset(&appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: rsName, Namespace: kubeapi.EVEKubeNameSpace},
	})
	err := moveReplicaSetPod(clientset, testNodeName, rsName, rsName+"-fghij",
		types.PreferredDuringScheduling)
	assert.NoError(t, err)
}

func TestAffinityNode(t *testing.T) {
	assert.Equal(t, testNodeName,
		affinityNode(hypervisor.SetKubeAffinity(testNodeName, types.PreferredDuringScheduling)))
	assert.Equal(t, testNodeName,
		affinityNode(hypervisor.SetKubeAffinity(testNodeName, types.RequiredDuringScheduling)))
	assert.Equal(t, "", affinityNode(nil))
	assert.Equal(t, "", affinityNode(&corev1.Affinity{}))
}
