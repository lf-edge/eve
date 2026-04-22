// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	gomock "go.uber.org/mock/gomock"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

func newTestLog() *base.LogObject {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	return base.NewSourceLogObject(logger, "test", 0)
}

func readyNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
			},
		},
	}
}

// seedSetupResources pre-populates all four descheduler RBAC/config resources
// so ensureDeschedulerSetupWithClient hits Update rather than Create.
func seedSetupResources(ctx context.Context, t *testing.T, client *fake.Clientset) {
	t.Helper()
	if _, err := client.CoreV1().ServiceAccounts(deschedulerNamespace).Create(ctx,
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: deschedulerSAName, Namespace: deschedulerNamespace}},
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoreV1().ConfigMaps(deschedulerNamespace).Create(ctx,
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: deschedulerConfigMapName, Namespace: deschedulerNamespace}},
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RbacV1().ClusterRoles().Create(ctx,
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: deschedulerClusterRoleName}},
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RbacV1().ClusterRoleBindings().Create(ctx,
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: deschedulerClusterRoleBindingName}},
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// --- IsDeschedulerReady ---

func TestIsDeschedulerReady_Unschedulable(t *testing.T) {
	node := readyNode("node1")
	node.Spec.Unschedulable = true
	client := fake.NewSimpleClientset(node)

	ready, err := isDeschedulerReadyWithClient(newTestLog(), client, "node1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ready {
		t.Fatal("expected not-ready for unschedulable node")
	}
}

func TestIsDeschedulerReady_NodeNotReady(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node1"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionFalse},
			},
		},
	}
	client := fake.NewSimpleClientset(node)

	ready, err := isDeschedulerReadyWithClient(newTestLog(), client, "node1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ready {
		t.Fatal("expected not-ready for not-Ready node")
	}
}

// --- ensureDeschedulerSetup ---

func TestEnsureDeschedulerSetup_CreateOnMissing(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	if err := ensureDeschedulerSetupWithClient(ctx, client); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := client.CoreV1().ServiceAccounts(deschedulerNamespace).Get(ctx, deschedulerSAName, metav1.GetOptions{}); err != nil {
		t.Errorf("service account not created: %v", err)
	}
	if _, err := client.RbacV1().ClusterRoles().Get(ctx, deschedulerClusterRoleName, metav1.GetOptions{}); err != nil {
		t.Errorf("cluster role not created: %v", err)
	}
	if _, err := client.RbacV1().ClusterRoleBindings().Get(ctx, deschedulerClusterRoleBindingName, metav1.GetOptions{}); err != nil {
		t.Errorf("cluster role binding not created: %v", err)
	}
	if _, err := client.CoreV1().ConfigMaps(deschedulerNamespace).Get(ctx, deschedulerConfigMapName, metav1.GetOptions{}); err != nil {
		t.Errorf("configmap not created: %v", err)
	}
}

func TestEnsureDeschedulerSetup_UpdateOnExisting(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	seedSetupResources(ctx, t, client)

	// A second call must not fail — all resources exist so every branch hits Update.
	if err := ensureDeschedulerSetupWithClient(ctx, client); err != nil {
		t.Fatalf("unexpected error on update pass: %v", err)
	}
}

// --- TriggerDescheduler ---

func TestTriggerDescheduler_ActiveJobSkipsDelete(t *testing.T) {
	ctx := context.Background()
	activeJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: deschedulerJobName, Namespace: deschedulerNamespace},
		Status:     batchv1.JobStatus{Active: 1},
	}
	client := fake.NewSimpleClientset(activeJob)
	seedSetupResources(ctx, t, client)

	if err := triggerDeschedulerWithClient(newTestLog(), client, "node1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Job must still exist with Active==1 — no Delete+Create should have occurred.
	job, err := client.BatchV1().Jobs(deschedulerNamespace).Get(ctx, deschedulerJobName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("job missing after call: %v", err)
	}
	if job.Status.Active != 1 {
		t.Errorf("job was replaced (Active: got %d, want 1)", job.Status.Active)
	}
}

func TestTriggerDescheduler_RecreateOnCompletion(t *testing.T) {
	ctx := context.Background()
	completedJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: deschedulerJobName, Namespace: deschedulerNamespace},
		Status:     batchv1.JobStatus{Succeeded: 1},
	}
	client := fake.NewSimpleClientset(completedJob)
	seedSetupResources(ctx, t, client)

	if err := triggerDeschedulerWithClient(newTestLog(), client, "node1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := client.BatchV1().Jobs(deschedulerNamespace).Get(ctx, deschedulerJobName, metav1.GetOptions{}); err != nil {
		t.Errorf("job not recreated: %v", err)
	}
}

// --- EnsureVMsDeschedulerAnnotated ---

func TestEnsureVMsDeschedulerAnnotated_AlreadyAnnotated(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)
	mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
	mockVMI := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)

	annotatedVMIRS := v1.VirtualMachineInstanceReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: "vmirs-1"},
		Spec: v1.VirtualMachineInstanceReplicaSetSpec{
			Template: &v1.VirtualMachineInstanceTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{DeschedulerEvictAnnotation: "true"},
				},
			},
		},
	}
	annotatedVMI := v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "vmi-1",
			Annotations: map[string]string{DeschedulerEvictAnnotation: "true"},
		},
	}

	mockClient.EXPECT().ReplicaSet(EVEKubeNameSpace).Return(mockRS)
	mockRS.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&v1.VirtualMachineInstanceReplicaSetList{Items: []v1.VirtualMachineInstanceReplicaSet{annotatedVMIRS}}, nil)
	// No Patch expectation — gomock fails the test on any unexpected call.

	mockClient.EXPECT().VirtualMachineInstance(EVEKubeNameSpace).Return(mockVMI)
	mockVMI.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&v1.VirtualMachineInstanceList{Items: []v1.VirtualMachineInstance{annotatedVMI}}, nil)

	if err := ensureVMsDeschedulerAnnotatedWithClient(newTestLog(), mockClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnsureVMsDeschedulerAnnotated_PatchesMissing(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)
	mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
	mockVMI := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)

	unannotatedVMIRS := v1.VirtualMachineInstanceReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: "vmirs-1"},
		Spec: v1.VirtualMachineInstanceReplicaSetSpec{
			Template: &v1.VirtualMachineInstanceTemplateSpec{},
		},
	}

	// ReplicaSet() is called twice: once for List and once for Patch.
	mockClient.EXPECT().ReplicaSet(EVEKubeNameSpace).Return(mockRS).Times(2)
	mockRS.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&v1.VirtualMachineInstanceReplicaSetList{Items: []v1.VirtualMachineInstanceReplicaSet{unannotatedVMIRS}}, nil)
	mockRS.EXPECT().Patch(gomock.Any(), "vmirs-1", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)

	mockClient.EXPECT().VirtualMachineInstance(EVEKubeNameSpace).Return(mockVMI)
	mockVMI.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&v1.VirtualMachineInstanceList{}, nil)

	if err := ensureVMsDeschedulerAnnotatedWithClient(newTestLog(), mockClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnsureVMsDeschedulerAnnotated_PatchesUnannotatedVMI(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)
	mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
	mockVMI := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)

	unannotatedVMI := v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "vmi-1"},
	}

	mockClient.EXPECT().ReplicaSet(EVEKubeNameSpace).Return(mockRS)
	mockRS.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&v1.VirtualMachineInstanceReplicaSetList{}, nil)

	// VirtualMachineInstance() is called twice: once for List and once for Patch.
	mockClient.EXPECT().VirtualMachineInstance(EVEKubeNameSpace).Return(mockVMI).Times(2)
	mockVMI.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&v1.VirtualMachineInstanceList{Items: []v1.VirtualMachineInstance{unannotatedVMI}}, nil)
	mockVMI.EXPECT().Patch(gomock.Any(), "vmi-1", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil)

	if err := ensureVMsDeschedulerAnnotatedWithClient(newTestLog(), mockClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
