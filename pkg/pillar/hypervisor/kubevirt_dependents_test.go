// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package hypervisor

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	k8sv1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
)

// swapK8sClientWithObjects is swapK8sClientNoPods with a seeded cluster,
// for the rows where a pod outlives its VMIRS.
func swapK8sClientWithObjects(t *testing.T, objs ...runtime.Object) {
	t.Helper()
	orig := newK8sClient
	fakeClientset := fake.NewSimpleClientset(objs...)
	newK8sClient = func(cfg *rest.Config) (kubernetes.Interface, error) {
		if cfg == nil {
			t.Errorf("newK8sClient called with a nil *rest.Config: " +
				"the caller did not populate kubeConfig")
		}
		return fakeClientset, nil
	}
	t.Cleanup(func() { newK8sClient = orig })
}

// mkVirtLauncherPod builds the pod KubeVirt runs a VMI in, carrying the
// labels a real one carries: "kubevirt.io=virt-launcher" plus the
// App-Domain-Name that CreateReplicaVMIConfig's template sets.
func mkVirtLauncherPod(name, domainNameLabel string) *k8sv1.Pod {
	return &k8sv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: kubeapi.EVEKubeNameSpace,
			Labels: map[string]string{
				"kubevirt.io": "virt-launcher",
				eveLabelKey:   domainNameLabel,
			},
		},
	}
}

// mkAppPod builds a NOHYPER app's container pod, labeled "app=<kubeName>".
func mkAppPod(name, appLabel string) *k8sv1.Pod {
	return &k8sv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: kubeapi.EVEKubeNameSpace,
			Labels:    map[string]string{"app": appLabel},
		},
	}
}

// mkVMI builds a VMI carrying the App-Domain-Name label its VMIRS
// template sets, which is how dependentsPresent finds it.
func mkVMI(name, domainNameLabel string) v1.VirtualMachineInstance {
	return v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: kubeapi.EVEKubeNameSpace,
			Labels:    map[string]string{eveLabelKey: domainNameLabel},
		},
	}
}

// expectVMIList adds a VirtualMachineInstance().List() expectation to
// mockClient that honors the label selector rather than returning the
// fixtures blindly, so a test using it covers the selector dependentsPresent
// builds and not just the mock -- the fake clientset already does this for
// pods. Returns how many times that List was consulted.
//
// Shared rather than folded into dependentMocks below: a caller with its own
// ReplicaSet expectations (e.g. one asserting a specific sequence of Get
// answers) still needs this same VMI side wired in.
func expectVMIList(t *testing.T, ctrl *gomock.Controller,
	mockClient *kubecli.MockKubevirtClient, vmis []v1.VirtualMachineInstance) *int {
	t.Helper()
	vmiCalls := 0
	mockVMI := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
	mockClient.EXPECT().VirtualMachineInstance(gomock.Any()).
		Return(mockVMI).AnyTimes()
	mockVMI.EXPECT().List(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ interface{}, opts interface{}) (*v1.VirtualMachineInstanceList, error) {
			vmiCalls++
			var raw string
			switch o := opts.(type) {
			case metav1.ListOptions:
				raw = o.LabelSelector
			case *metav1.ListOptions:
				raw = o.LabelSelector
			default:
				t.Fatalf("unexpected ListOptions type %T", opts)
			}
			selector, err := labels.Parse(raw)
			if err != nil {
				return nil, err
			}
			matched := &v1.VirtualMachineInstanceList{}
			for _, vmi := range vmis {
				if selector.Matches(labels.Set(vmi.Labels)) {
					matched.Items = append(matched.Items, vmi)
				}
			}
			return matched, nil
		}).AnyTimes()
	return &vmiCalls
}

// dependentMocks wires a kubevirt client whose VMI List returns the given
// VMIs, and reports how many times that List was consulted.
func dependentMocks(t *testing.T, vmirs *v1.VirtualMachineInstanceReplicaSet,
	kubeName string, vmis []v1.VirtualMachineInstance) *int {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)

	mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
	mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).AnyTimes()
	if vmirs == nil {
		mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			nil, apierrors.NewNotFound(
				schema.GroupResource{
					Group:    "kubevirt.io",
					Resource: "virtualmachineinstancereplicasets",
				}, kubeName)).AnyTimes()
	} else {
		mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(vmirs, nil).AnyTimes()
	}

	vmiCalls := expectVMIList(t, ctrl, mockClient, vmis)
	swapKubevirtClient(t, mockClient)
	return vmiCalls
}

// TestDependentsPresent is the truth table for the two objects that can
// outlive a deleted VMIRS. Either one alone means the workload is still
// there, because the pod holds the RWO disk until it is gone.
func TestDependentsPresent(t *testing.T) {
	for _, tc := range []struct {
		name string
		vmi  bool
		pod  bool
		want bool
	}{
		{name: "vmi absent, pod absent", want: false},
		{name: "vmi absent, pod present", pod: true, want: true},
		{name: "vmi present, pod absent", vmi: true, want: true},
		{name: "vmi present, pod present", vmi: true, pod: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task, _ := newInfoTestTask(t, 918273645)
			domainName := task.status.DomainName

			var vmis []v1.VirtualMachineInstance
			if tc.vmi {
				vmis = append(vmis, mkVMI("vmi-0", domainName))
			}
			var pods []runtime.Object
			if tc.pod {
				pods = append(pods, mkVirtLauncherPod("virt-launcher-vmi-0", domainName))
			}
			dependentMocks(t, nil, task.kubeName(), vmis)
			swapK8sClientWithObjects(t, pods...)

			task.kubeConfig = &rest.Config{}
			got, err := task.dependentsPresent(domainName)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestDependentsAreScopedToTheDomain: the labels are per-domainName,
// so another app's - or an older generation's - leftovers must not make
// this domain look alive.
func TestDependentsAreScopedToTheDomain(t *testing.T) {
	task, _ := newInfoTestTask(t, 1)
	dependentMocks(t, nil, task.kubeName(),
		[]v1.VirtualMachineInstance{mkVMI("vmi-other", "someone-else.1.1")})
	swapK8sClientWithObjects(t,
		mkVirtLauncherPod("virt-launcher-other", "someone-else.1.1"))

	task.kubeConfig = &rest.Config{}
	got, err := task.dependentsPresent(task.status.DomainName)
	assert.NoError(t, err)
	assert.False(t, got, "another domain's objects are not this domain's dependents")
}

// TestDependentsPresentNoHyper covers the NOHYPER app, which has no VMI at
// all: its pods carry "app=<kubeName>", already generation-specific.
func TestDependentsPresentNoHyper(t *testing.T) {
	for _, pod := range []bool{false, true} {
		t.Run(fmt.Sprintf("pod present %v", pod), func(t *testing.T) {
			task, _ := newInfoTestTask(t, 1)
			task.status.VirtualizationMode = types.NOHYPER
			task.kubeConfig = &rest.Config{}

			var objs []runtime.Object
			if pod {
				objs = append(objs, mkAppPod("myapp-pod", task.kubeName()))
			}
			swapK8sClientWithObjects(t, objs...)

			got, err := task.dependentsPresent(task.status.DomainName)
			assert.NoError(t, err)
			assert.Equal(t, pod, got)
		})
	}
}

// TestInfoStateFromWorkloadObjects is the truth table for the rule that a
// domain's state follows the existence of its VMIRS, VMI, and pod: HALTED
// with a zero DomainId requires all three absent, and a surviving VMIRS is
// never reported as HALTED regardless of the other two.
//
// The VMIRS-present rows leave vmiList empty, the shortest path through
// Info once existence is confirmed.
func TestInfoStateFromWorkloadObjects(t *testing.T) {
	const lastKnownID = 918273645

	for _, tc := range []struct {
		name         string
		vmirs        bool
		vmi          bool
		pod          bool
		wantState    types.SwState
		wantZeroID   bool
		wantDepCheck bool // are the dependents worth looking up?
	}{{
		name:         "all three absent is the only halted case",
		wantState:    types.HALTED,
		wantZeroID:   true,
		wantDepCheck: true,
	}, {
		name:         "pod outlives the vmirs",
		pod:          true,
		wantState:    types.HALTING,
		wantDepCheck: true,
	}, {
		name:         "vmi outlives the vmirs",
		vmi:          true,
		wantState:    types.HALTING,
		wantDepCheck: true,
	}, {
		name:         "vmi and pod both outlive the vmirs",
		vmi:          true,
		pod:          true,
		wantState:    types.HALTING,
		wantDepCheck: true,
	}, {
		// A live VMIRS settles it on its own, so no dependent lookup runs -
		// keeping a steady-state poll cheap.
		name:      "vmirs present, nothing else",
		vmirs:     true,
		wantState: types.SCHEDULING,
	}, {
		name:      "vmirs and pod present",
		vmirs:     true,
		pod:       true,
		wantState: types.SCHEDULING,
	}, {
		name:      "vmirs and vmi present",
		vmirs:     true,
		vmi:       true,
		wantState: types.SCHEDULING,
	}, {
		name:      "all three present",
		vmirs:     true,
		vmi:       true,
		pod:       true,
		wantState: types.SCHEDULING,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			task, _ := newInfoTestTask(t, lastKnownID)
			domainName := task.status.DomainName

			var live *v1.VirtualMachineInstanceReplicaSet
			if tc.vmirs {
				live = &v1.VirtualMachineInstanceReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Name: task.kubeName(),
						UID:  "live-vmirs-uid",
					},
				}
			}
			var vmis []v1.VirtualMachineInstance
			if tc.vmi {
				vmis = append(vmis, mkVMI("vmi-0", domainName))
			}
			var pods []runtime.Object
			if tc.pod {
				pods = append(pods, mkVirtLauncherPod("virt-launcher-vmi-0", domainName))
			}

			vmiCalls := dependentMocks(t, live, task.kubeName(), vmis)
			swapK8sClientWithObjects(t, pods...)

			id, state, err := task.Info(domainName)
			assert.NoError(t, err)
			assert.Equal(t, tc.wantState, state)

			if tc.wantZeroID {
				assert.Zero(t, id, "all three absent, so the workload is confirmed gone")
			} else {
				assert.NotZero(t, id,
					"a zero id would falsely tell domainmgr the workload is gone")
			}
			assert.Equal(t, tc.wantDepCheck, *vmiCalls > 0,
				"dependents must be looked up only when the VMIRS is absent")
		})
	}
}

// TestInfoUnresolvedDependentsKeepLastID: an unresolved dependent lookup
// must not emit the confirmed-absent token either, the same rule the
// existence check itself follows.
func TestInfoUnresolvedDependentsKeepLastID(t *testing.T) {
	const lastKnownID = 918273645
	task, _ := newInfoTestTask(t, lastKnownID)

	ctrl := gomock.NewController(t)
	mockClient := kubecli.NewMockKubevirtClient(ctrl)
	mockRS := kubecli.NewMockReplicaSetInterface(ctrl)
	mockClient.EXPECT().ReplicaSet(gomock.Any()).Return(mockRS).AnyTimes()
	mockRS.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(
		nil, apierrors.NewNotFound(
			schema.GroupResource{
				Group:    "kubevirt.io",
				Resource: "virtualmachineinstancereplicasets",
			}, task.kubeName())).AnyTimes()
	mockVMI := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
	mockClient.EXPECT().VirtualMachineInstance(gomock.Any()).
		Return(mockVMI).AnyTimes()
	mockVMI.EXPECT().List(gomock.Any(), gomock.Any()).
		Return(nil, assert.AnError).AnyTimes()
	swapKubevirtClient(t, mockClient)
	swapK8sClientWithObjects(t)

	id, state, err := task.Info(task.status.DomainName)
	assert.Error(t, err)
	assert.Equal(t, types.UNKNOWN, state)
	assert.Equal(t, lastKnownID, id)
}

// TestNoHyperPodLabelsMatchTheSelector ties the label CreateReplicaPodConfig
// stamps on a NOHYPER app's pods to the selector dependentsPresent looks
// them up with. The two are written in different places and could drift; a
// selector matching nothing would report every domain as gone.
//
// The pod here is labeled by the production code rather than by the test, so
// the two sides cannot agree merely by construction.
func TestNoHyperPodLabelsMatchTheSelector(t *testing.T) {
	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	domainName := appUUID.String() + ".1.1"

	config := types.DomainConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: appUUID},
		DisplayName:    "myapp",
		PurgeCounter:   1,
		KubeImageName:  "docker.io/library/alpine:3.24",
	}
	domainStatus := types.DomainStatus{
		UUIDandVersion: types.UUIDandVersion{UUID: appUUID},
		DisplayName:    config.DisplayName,
		DomainName:     domainName,
		PurgeCounter:   config.PurgeCounter,
	}
	// Promoted from an embedded struct, so not settable in the literals above.
	config.VirtualizationMode = types.NOHYPER
	domainStatus.VirtualizationMode = types.NOHYPER

	// One VIF, because CreateReplicaPodConfig refuses a pod with no network
	// selections. IoAdapterList stays empty: an IoNetEth entry there would
	// go check for a NAD in a live cluster.
	mac, err := net.ParseMAC("00:16:3e:00:00:01")
	require.NoError(t, err)
	config.VifList = []types.VifConfig{{Mac: mac}}

	file, err := os.CreateTemp(t.TempDir(), "replicaset")
	require.NoError(t, err)
	defer file.Close()

	var ctx kubevirtContext
	ctx.nodeNameMap = map[string]string{"nodename": "node1"}
	ctx.vmiList = make(map[string]*vmiMetaData)
	ctx.prevDomainMetric = make(map[string]types.DomainMetric)

	require.NoError(t, ctx.CreateReplicaPodConfig(domainName, config,
		domainStatus, nil, nil, file))

	meta := ctx.vmiList[domainName]
	require.NotNil(t, meta)
	require.NotNil(t, meta.repPod)
	podLabels := meta.repPod.Spec.Template.Labels
	require.NotEmpty(t, podLabels, "pods with no labels could never be found")

	// The asymmetry that makes this branch differ from the VMI one:
	// App-Domain-Name is stamped on the ReplicaSet object, and is not
	// propagated to its pods, so the pod lookup cannot use it.
	assert.Contains(t, meta.repPod.ObjectMeta.Labels, eveLabelKey,
		"the ReplicaSet object carries the domain-name label")
	assert.NotContains(t, podLabels, eveLabelKey,
		"a NOHYPER app's pods do not carry the domain-name label")

	// dependentsPresent derives the selector from DomainStatus, while the
	// ReplicaSet was named from DomainConfig. Drift between the two would
	// point the lookup at another generation.
	task := ctx.Task(&domainStatus).(kubevirtTask)
	assert.Equal(t, meta.repPod.ObjectMeta.Name, task.kubeName(),
		"kubeName from status must name the ReplicaSet built from config")

	task.kubeConfig = &rest.Config{}
	swapK8sClientWithObjects(t, &k8sv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "myapp-pod",
			Namespace: kubeapi.EVEKubeNameSpace,
			Labels:    podLabels,
		},
	})

	present, err := task.dependentsPresent(domainName)
	assert.NoError(t, err)
	assert.True(t, present,
		"a pod labeled by CreateReplicaPodConfig must match the selector")
}
