// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	gomock "go.uber.org/mock/gomock"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

const testNodeName = "this-node"

func mkAppInstanceConfig(displayName string, isDesignated bool, virtMode types.VmMode) types.AppInstanceConfig {
	return types.AppInstanceConfig{
		UUIDandVersion:     types.UUIDandVersion{UUID: uuid.Must(uuid.NewV4())},
		DisplayName:        displayName,
		IsDesignatedNodeID: isDesignated,
		AffinityType:       types.PreferredDuringScheduling,
		FixedResources:     types.VmConfig{VirtualizationMode: virtMode},
	}
}

func vmirsNameFor(aiconfig types.AppInstanceConfig) string {
	return base.GetAppKubeNameWithPurge(aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID,
		aiconfig.PurgeCmd.Counter+aiconfig.LocalPurgeCmd.Counter)
}

func TestReconcileVMIRSAffinityWithClient_AlreadyCorrectSkipsUpdate(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-zedkube", 0)

	aiconfig := mkAppInstanceConfig("app1", true, types.PV)
	name := vmirsNameFor(aiconfig)
	correct := hypervisor.SetKubeAffinity(testNodeName, aiconfig.AffinityType)

	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)
	mockRS := kubecli.NewMockReplicaSetInterface(ctrl)

	mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS)
	mockRS.EXPECT().Get(gomock.Any(), name, metav1.GetOptions{}).Return(
		&virtv1.VirtualMachineInstanceReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: virtv1.VirtualMachineInstanceReplicaSetSpec{
				Template: &virtv1.VirtualMachineInstanceTemplateSpec{
					Spec: virtv1.VirtualMachineInstanceSpec{Affinity: correct},
				},
			},
		}, nil)
	// No Update expectation: gomock fails the test if Update is called.

	wdCalls := 0
	reconcileVMIRSAffinityWithClient(testNodeName, mockClient,
		map[string]interface{}{aiconfig.Key(): aiconfig}, func() { wdCalls++ })

	assert.Equal(t, 1, wdCalls)
}

func TestReconcileVMIRSAffinityWithClient_StaleUpdatesToThisNode(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-zedkube", 0)

	aiconfig := mkAppInstanceConfig("app2", true, types.PV)
	name := vmirsNameFor(aiconfig)
	stale := hypervisor.SetKubeAffinity("other-node", aiconfig.AffinityType)

	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)
	mockRS := kubecli.NewMockReplicaSetInterface(ctrl)

	mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).Times(2)
	mockRS.EXPECT().Get(gomock.Any(), name, metav1.GetOptions{}).Return(
		&virtv1.VirtualMachineInstanceReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: virtv1.VirtualMachineInstanceReplicaSetSpec{
				Template: &virtv1.VirtualMachineInstanceTemplateSpec{
					Spec: virtv1.VirtualMachineInstanceSpec{Affinity: stale},
				},
			},
		}, nil)
	mockRS.EXPECT().Update(gomock.Any(), gomock.Any(), metav1.UpdateOptions{}).DoAndReturn(
		func(_ context.Context, obj *virtv1.VirtualMachineInstanceReplicaSet, _ metav1.UpdateOptions) (*virtv1.VirtualMachineInstanceReplicaSet, error) {
			assert.Equal(t, hypervisor.SetKubeAffinity(testNodeName, aiconfig.AffinityType), obj.Spec.Template.Spec.Affinity)
			return obj, nil
		})

	reconcileVMIRSAffinityWithClient(testNodeName, mockClient,
		map[string]interface{}{aiconfig.Key(): aiconfig}, func() {})
}

func TestReconcileVMIRSAffinityWithClient_NotFoundIsSwallowed(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-zedkube", 0)

	aiconfig := mkAppInstanceConfig("app3", true, types.PV)
	name := vmirsNameFor(aiconfig)

	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)
	mockRS := kubecli.NewMockReplicaSetInterface(ctrl)

	mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS)
	mockRS.EXPECT().Get(gomock.Any(), name, metav1.GetOptions{}).Return(nil,
		k8serrors.NewNotFound(schema.GroupResource{Resource: "virtualmachineinstancereplicasets"}, name))
	// No Update expectation.

	assert.NotPanics(t, func() {
		reconcileVMIRSAffinityWithClient(testNodeName, mockClient,
			map[string]interface{}{aiconfig.Key(): aiconfig}, func() {})
	})
}

func TestReconcileVMIRSAffinityWithClient_SkipsNonDNIDAndNOHYPER(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-zedkube", 0)

	notDesignated := mkAppInstanceConfig("app4", false, types.PV)
	nohyper := mkAppInstanceConfig("app5", true, types.NOHYPER)

	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)
	// No ReplicaSet() expectation at all: gomock fails the test if it's called.

	wdCalls := 0
	reconcileVMIRSAffinityWithClient(testNodeName, mockClient,
		map[string]interface{}{
			notDesignated.Key(): notDesignated,
			nohyper.Key():       nohyper,
		}, func() { wdCalls++ })

	assert.Equal(t, 2, wdCalls)
}
