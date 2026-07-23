// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"errors"
	"os"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	gomock "go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

func TestMain(m *testing.M) {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	log = base.NewSourceLogObject(l, "test", 0)
	os.Exit(m.Run())
}

// --- helpers -----------------------------------------------------------------

const (
	testNode = "node-a"
	testNS   = "eve-kube-app"
)

// vmirsPreferred builds a VMIRS with the standard EVE preferred-scheduling
// node affinity and a KernelBoot container image.
func vmirsPreferred(nodeName, image string) virtv1.VirtualMachineInstanceReplicaSet {
	return virtv1.VirtualMachineInstanceReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: "vmirs-" + nodeName},
		Spec: virtv1.VirtualMachineInstanceReplicaSetSpec{
			Template: &virtv1.VirtualMachineInstanceTemplateSpec{
				Spec: virtv1.VirtualMachineInstanceSpec{
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
								{
									Preference: corev1.NodeSelectorTerm{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{Key: "kubernetes.io/hostname", Values: []string{nodeName}},
										},
									},
								},
							},
						},
					},
					Domain: virtv1.DomainSpec{
						Firmware: &virtv1.Firmware{
							KernelBoot: &virtv1.KernelBoot{
								Container: &virtv1.KernelBootContainer{Image: image},
							},
						},
					},
				},
			},
		},
	}
}

// vmirsRequired builds a VMIRS with required-scheduling node affinity.
func vmirsRequired(nodeName, image string) virtv1.VirtualMachineInstanceReplicaSet {
	return virtv1.VirtualMachineInstanceReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: "vmirs-req-" + nodeName},
		Spec: virtv1.VirtualMachineInstanceReplicaSetSpec{
			Template: &virtv1.VirtualMachineInstanceTemplateSpec{
				Spec: virtv1.VirtualMachineInstanceSpec{
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
								NodeSelectorTerms: []corev1.NodeSelectorTerm{
									{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{Key: "kubernetes.io/hostname", Values: []string{nodeName}},
										},
									},
								},
							},
						},
					},
					Domain: virtv1.DomainSpec{
						Firmware: &virtv1.Firmware{
							KernelBoot: &virtv1.KernelBoot{
								Container: &virtv1.KernelBootContainer{Image: image},
							},
						},
					},
				},
			},
		},
	}
}

func mockClientWithRS(ctrl *gomock.Controller, ns string) (*kubecli.MockKubevirtClient, *kubecli.MockReplicaSetInterface) {
	mc := kubecli.NewMockKubevirtClient(ctrl)
	mrs := kubecli.NewMockReplicaSetInterface(ctrl)
	mc.EXPECT().ReplicaSet(ns).Return(mrs).AnyTimes()
	return mc, mrs
}

// --- vmirsAffinityNode -------------------------------------------------------

func TestVMIRSAffinityNode_Preferred(t *testing.T) {
	v := vmirsPreferred("node-a", extBootImgLatest)
	if got := vmirsAffinityNode(&v); got != "node-a" {
		t.Fatalf("got %q, want node-a", got)
	}
}

func TestVMIRSAffinityNode_Required(t *testing.T) {
	v := vmirsRequired("node-b", extBootImgLatest)
	if got := vmirsAffinityNode(&v); got != "node-b" {
		t.Fatalf("got %q, want node-b", got)
	}
}

func TestVMIRSAffinityNode_NoAffinity(t *testing.T) {
	v := virtv1.VirtualMachineInstanceReplicaSet{
		Spec: virtv1.VirtualMachineInstanceReplicaSetSpec{
			Template: &virtv1.VirtualMachineInstanceTemplateSpec{},
		},
	}
	if got := vmirsAffinityNode(&v); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestVMIRSAffinityNode_NilTemplate(t *testing.T) {
	v := virtv1.VirtualMachineInstanceReplicaSet{}
	if got := vmirsAffinityNode(&v); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

// --- kubeVirtCondAvailable ---------------------------------------------------

func TestKubeVirtCondAvailable_True(t *testing.T) {
	ctrl := gomock.NewController(t)
	mc := kubecli.NewMockKubevirtClient(ctrl)
	mkv := kubecli.NewMockKubeVirtInterface(ctrl)
	mc.EXPECT().KubeVirt("kubevirt").Return(mkv)
	mkv.EXPECT().Get(gomock.Any(), "kubevirt", metav1.GetOptions{}).Return(&virtv1.KubeVirt{
		Status: virtv1.KubeVirtStatus{
			Conditions: []virtv1.KubeVirtCondition{
				{Type: virtv1.KubeVirtConditionAvailable, Status: corev1.ConditionTrue},
			},
		},
	}, nil)
	if !kubeVirtCondAvailable(mc) {
		t.Fatal("expected true")
	}
}

func TestKubeVirtCondAvailable_ConditionFalse(t *testing.T) {
	ctrl := gomock.NewController(t)
	mc := kubecli.NewMockKubevirtClient(ctrl)
	mkv := kubecli.NewMockKubeVirtInterface(ctrl)
	mc.EXPECT().KubeVirt("kubevirt").Return(mkv)
	mkv.EXPECT().Get(gomock.Any(), "kubevirt", metav1.GetOptions{}).Return(&virtv1.KubeVirt{
		Status: virtv1.KubeVirtStatus{
			Conditions: []virtv1.KubeVirtCondition{
				{Type: virtv1.KubeVirtConditionAvailable, Status: corev1.ConditionFalse},
			},
		},
	}, nil)
	if kubeVirtCondAvailable(mc) {
		t.Fatal("expected false")
	}
}

func TestKubeVirtCondAvailable_GetError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mc := kubecli.NewMockKubevirtClient(ctrl)
	mkv := kubecli.NewMockKubeVirtInterface(ctrl)
	mc.EXPECT().KubeVirt("kubevirt").Return(mkv)
	mkv.EXPECT().Get(gomock.Any(), "kubevirt", metav1.GetOptions{}).Return(nil, errors.New("not found"))
	if kubeVirtCondAvailable(mc) {
		t.Fatal("expected false on Get error")
	}
}

// --- migrateLocalVMIRSBootImages ---------------------------------------------

func TestMigrateLocalVMIRS_AlreadyLatest(t *testing.T) {
	ctrl := gomock.NewController(t)
	mc, mrs := mockClientWithRS(ctrl, testNS)
	v := vmirsPreferred(testNode, extBootImgLatest)
	mrs.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&virtv1.VirtualMachineInstanceReplicaSetList{Items: []virtv1.VirtualMachineInstanceReplicaSet{v}}, nil)
	// No Patch expectation — gomock fails on unexpected calls.
	done, err := migrateLocalVMIRSBootImages(testNode, testNS, mc)
	if err != nil || !done {
		t.Fatalf("got done=%v err=%v, want done=true err=nil", done, err)
	}
}

func TestMigrateLocalVMIRS_AffinityMismatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	mc, mrs := mockClientWithRS(ctrl, testNS)
	v := vmirsPreferred("other-node", "docker.io/lfedge/eve-external-boot-image:1.2.3")
	mrs.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&virtv1.VirtualMachineInstanceReplicaSetList{Items: []virtv1.VirtualMachineInstanceReplicaSet{v}}, nil)
	done, err := migrateLocalVMIRSBootImages(testNode, testNS, mc)
	if err != nil || !done {
		t.Fatalf("got done=%v err=%v, want done=true err=nil", done, err)
	}
}

func TestMigrateLocalVMIRS_NoKernelBoot(t *testing.T) {
	ctrl := gomock.NewController(t)
	mc, mrs := mockClientWithRS(ctrl, testNS)
	v := virtv1.VirtualMachineInstanceReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: "vmirs-no-kb"},
		Spec: virtv1.VirtualMachineInstanceReplicaSetSpec{
			Template: &virtv1.VirtualMachineInstanceTemplateSpec{
				Spec: virtv1.VirtualMachineInstanceSpec{
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
								{Preference: corev1.NodeSelectorTerm{MatchExpressions: []corev1.NodeSelectorRequirement{
									{Key: "kubernetes.io/hostname", Values: []string{testNode}},
								}}},
							},
						},
					},
					Domain: virtv1.DomainSpec{}, // no Firmware/KernelBoot
				},
			},
		},
	}
	mrs.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&virtv1.VirtualMachineInstanceReplicaSetList{Items: []virtv1.VirtualMachineInstanceReplicaSet{v}}, nil)
	done, err := migrateLocalVMIRSBootImages(testNode, testNS, mc)
	if err != nil || !done {
		t.Fatalf("got done=%v err=%v, want done=true err=nil", done, err)
	}
}

func TestMigrateLocalVMIRS_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	mc, mrs := mockClientWithRS(ctrl, testNS)
	v := vmirsPreferred(testNode, "docker.io/lfedge/eve-external-boot-image:1.2.3")
	mrs.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&virtv1.VirtualMachineInstanceReplicaSetList{Items: []virtv1.VirtualMachineInstanceReplicaSet{v}}, nil)
	mrs.EXPECT().Patch(gomock.Any(), v.Name, gomock.Any(), gomock.Any(), gomock.Any()).Return(&v, nil)
	done, err := migrateLocalVMIRSBootImages(testNode, testNS, mc)
	if err != nil || !done {
		t.Fatalf("got done=%v err=%v, want done=true err=nil", done, err)
	}
}

func TestMigrateLocalVMIRS_RequiredAffinitySuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	mc, mrs := mockClientWithRS(ctrl, testNS)
	v := vmirsRequired(testNode, "docker.io/lfedge/eve-external-boot-image:1.2.3")
	mrs.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&virtv1.VirtualMachineInstanceReplicaSetList{Items: []virtv1.VirtualMachineInstanceReplicaSet{v}}, nil)
	mrs.EXPECT().Patch(gomock.Any(), v.Name, gomock.Any(), gomock.Any(), gomock.Any()).Return(&v, nil)
	done, err := migrateLocalVMIRSBootImages(testNode, testNS, mc)
	if err != nil || !done {
		t.Fatalf("got done=%v err=%v, want done=true err=nil", done, err)
	}
}

func TestMigrateLocalVMIRS_PatchFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	mc, mrs := mockClientWithRS(ctrl, testNS)
	v := vmirsPreferred(testNode, "docker.io/lfedge/eve-external-boot-image:1.2.3")
	mrs.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&virtv1.VirtualMachineInstanceReplicaSetList{Items: []virtv1.VirtualMachineInstanceReplicaSet{v}}, nil)
	mrs.EXPECT().Patch(gomock.Any(), v.Name, gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("conflict"))
	done, err := migrateLocalVMIRSBootImages(testNode, testNS, mc)
	if err != nil || done {
		t.Fatalf("got done=%v err=%v, want done=false err=nil", done, err)
	}
}

func TestMigrateLocalVMIRS_ListError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mc, mrs := mockClientWithRS(ctrl, testNS)
	mrs.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(nil, errors.New("api unavailable"))
	_, err := migrateLocalVMIRSBootImages(testNode, testNS, mc)
	if err == nil {
		t.Fatal("expected error from List failure")
	}
}

// --- bootImgMigrator.step ----------------------------------------------------

// kvClientAlwaysFalse returns a mock KubevirtClient whose KubeVirt.Get reports
// Available=False, keeping the migrator in WaitReady.
func kvClientAlwaysFalse(ctrl *gomock.Controller) kubecli.KubevirtClient {
	mc := kubecli.NewMockKubevirtClient(ctrl)
	mkv := kubecli.NewMockKubeVirtInterface(ctrl)
	mc.EXPECT().KubeVirt("kubevirt").Return(mkv).AnyTimes()
	mkv.EXPECT().Get(gomock.Any(), "kubevirt", metav1.GetOptions{}).Return(&virtv1.KubeVirt{}, nil).AnyTimes()
	return mc
}

func TestBootImgMigratorStep_WaitReadyNeitherReady(t *testing.T) {
	ctrl := gomock.NewController(t)
	// extBootImgLatestPresent() will return false (no real containerd socket in tests).
	// kubeVirtCondAvailable returns false.
	m := bootImgMigrator{}
	m.step(testNode, testNS, kvClientAlwaysFalse(ctrl))
	if m.state != bootImgStateWaitReady {
		t.Fatalf("state=%v, want WaitReady", m.state)
	}
}

func TestBootImgMigratorStep_WaitReadyKubeVirtNotReady(t *testing.T) {
	ctrl := gomock.NewController(t)
	// Simulate image already confirmed ready from a prior tick.
	m := bootImgMigrator{imageReady: true}
	m.step(testNode, testNS, kvClientAlwaysFalse(ctrl))
	if m.state != bootImgStateWaitReady {
		t.Fatalf("state=%v, want WaitReady", m.state)
	}
}

func TestBootImgMigratorStep_EmptyNodeNameStaysWaitReady(t *testing.T) {
	ctrl := gomock.NewController(t)
	// nodeName unknown (EdgeNodeInfo not yet received): must not advance, even
	// with image already confirmed ready, or it would latch to Done having
	// skipped every VMIRS. No KubeVirt/ReplicaSet calls are expected.
	mc := kubecli.NewMockKubevirtClient(ctrl)
	m := bootImgMigrator{imageReady: true}
	m.step("", testNS, mc)
	if m.state != bootImgStateWaitReady {
		t.Fatalf("state=%v, want WaitReady", m.state)
	}
}

func TestBootImgMigratorStep_WaitReadyBothReady_CollapsesToDone(t *testing.T) {
	ctrl := gomock.NewController(t)
	// When both readiness conditions are met, step() collapses
	// WaitReady → Migrate → Done in a single tick (empty VMIRS list, nothing to
	// patch) rather than spending a tick per transition. This keeps the window
	// where the descheduler could reschedule an app onto this node before the
	// VMIRS is patched as small as possible.
	mc := kubecli.NewMockKubevirtClient(ctrl)
	mkv := kubecli.NewMockKubeVirtInterface(ctrl)
	mrs := kubecli.NewMockReplicaSetInterface(ctrl)
	mc.EXPECT().KubeVirt("kubevirt").Return(mkv).AnyTimes()
	mkv.EXPECT().Get(gomock.Any(), "kubevirt", metav1.GetOptions{}).Return(&virtv1.KubeVirt{
		Status: virtv1.KubeVirtStatus{Conditions: []virtv1.KubeVirtCondition{
			{Type: virtv1.KubeVirtConditionAvailable, Status: corev1.ConditionTrue},
		}},
	}, nil).AnyTimes()
	mc.EXPECT().ReplicaSet(testNS).Return(mrs).AnyTimes()
	mrs.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&virtv1.VirtualMachineInstanceReplicaSetList{}, nil)

	m := bootImgMigrator{imageReady: true}
	m.step(testNode, testNS, mc)
	if m.state != bootImgStateDone {
		t.Fatalf("state=%v, want Done", m.state)
	}
}

func TestBootImgMigratorStep_MigrateNothingToDo(t *testing.T) {
	ctrl := gomock.NewController(t)
	mc, mrs := mockClientWithRS(ctrl, testNS)
	mrs.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&virtv1.VirtualMachineInstanceReplicaSetList{}, nil)

	m := bootImgMigrator{state: bootImgStateMigrate}
	m.step(testNode, testNS, mc)
	if m.state != bootImgStateDone {
		t.Fatalf("state=%v, want Done", m.state)
	}
}

func TestBootImgMigratorStep_MigratePatchFails_StaysMigrate(t *testing.T) {
	ctrl := gomock.NewController(t)
	mc, mrs := mockClientWithRS(ctrl, testNS)
	v := vmirsPreferred(testNode, "docker.io/lfedge/eve-external-boot-image:1.2.3")
	mrs.EXPECT().List(gomock.Any(), metav1.ListOptions{}).Return(
		&virtv1.VirtualMachineInstanceReplicaSetList{Items: []virtv1.VirtualMachineInstanceReplicaSet{v}}, nil)
	mrs.EXPECT().Patch(gomock.Any(), v.Name, gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("conflict"))

	m := bootImgMigrator{state: bootImgStateMigrate}
	m.step(testNode, testNS, mc)
	if m.state != bootImgStateMigrate {
		t.Fatalf("state=%v, want Migrate", m.state)
	}
}

func TestBootImgMigratorStep_DoneIsNoop(t *testing.T) {
	// No mock expectations — any unexpected call fails the test.
	ctrl := gomock.NewController(t)
	mc := kubecli.NewMockKubevirtClient(ctrl)
	m := bootImgMigrator{state: bootImgStateDone}
	m.step(testNode, testNS, mc)
	if m.state != bootImgStateDone {
		t.Fatalf("state=%v, want Done", m.state)
	}
}
