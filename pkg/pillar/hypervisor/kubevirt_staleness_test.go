// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package hypervisor

import (
	"testing"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "kubevirt.io/api/core/v1"
)

// mkVMIRS builds a fixture matching what CreateReplicaVMIConfig actually
// creates: the App-Domain-Name label lives on Spec.Selector.MatchLabels,
// not on the object's own ObjectMeta.Labels (which CreateReplicaVMIConfig
// never sets).
func mkVMIRS(name, domainNameLabel string) v1.VirtualMachineInstanceReplicaSet {
	return v1.VirtualMachineInstanceReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1.VirtualMachineInstanceReplicaSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{eveLabelKey: domainNameLabel},
			},
		},
	}
}

// mkPodReplicaSet builds a fixture matching CreateReplicaPodConfig, which
// (unlike the VMIRS case) does set the App-Domain-Name label directly on
// ObjectMeta.Labels.
func mkPodReplicaSet(name, domainNameLabel string) appsv1.ReplicaSet {
	return appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{eveLabelKey: domainNameLabel},
		},
	}
}

func TestStaleGenerationPredicate(t *testing.T) {
	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	otherUUID := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	domainName := appUUID.String() + ".1.0"
	const desiredName = "myapp-a1b2c-2"
	const desiredCounter = uint32(2)

	tests := []struct {
		name   string
		vmirs  v1.VirtualMachineInstanceReplicaSet
		wantOK bool
	}{
		{
			name:   "older generation of this app is stale",
			vmirs:  mkVMIRS("myapp-a1b2c-1", domainName),
			wantOK: true,
		},
		{
			name:   "much older generation of this app is stale",
			vmirs:  mkVMIRS("myapp-a1b2c-0", domainName),
			wantOK: true,
		},
		{
			name:   "the desired generation itself is never stale",
			vmirs:  mkVMIRS(desiredName, domainName),
			wantOK: false,
		},
		{
			name:   "a differently-named object at the same counter is never stale (not strictly less)",
			vmirs:  mkVMIRS("myapp-old-2", domainName),
			wantOK: false,
		},
		{
			name:   "a newer generation is never stale",
			vmirs:  mkVMIRS("myapp-a1b2c-3", domainName),
			wantOK: false,
		},
		{
			name:   "a different app's older-numbered generation is ignored",
			vmirs:  mkVMIRS("otherapp-x9y8z-1", otherUUID.String()+".1.0"),
			wantOK: false,
		},
		{
			name:   "unparseable (non-numeric) trailing suffix is never stale",
			vmirs:  mkVMIRS("myapp-a1b2c-abc", domainName),
			wantOK: false,
		},
		{
			name:   "name with no hyphen is never stale",
			vmirs:  mkVMIRS("myappa1b2c1", domainName),
			wantOK: false,
		},
		{
			name:   "empty App-Domain-Name label is ignored",
			vmirs:  mkVMIRS("myapp-a1b2c-1", ""),
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := staleVMIRSGeneration(tc.vmirs, appUUID, desiredName, desiredCounter)
			assert.Equal(t, tc.wantOK, got)
		})
	}
}

func TestStaleVMIRSNames(t *testing.T) {
	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	otherUUID := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	domainName := appUUID.String() + ".1.0"
	const desiredName = "myapp-a1b2c-2"

	list := []v1.VirtualMachineInstanceReplicaSet{
		mkVMIRS("myapp-a1b2c-0", domainName),
		mkVMIRS("myapp-a1b2c-1", domainName),
		mkVMIRS(desiredName, domainName),
		mkVMIRS("otherapp-x9y8z-0", otherUUID.String()+".1.0"),
	}

	got := staleVMIRSNames(list, appUUID, desiredName, 2)
	assert.ElementsMatch(t, []string{"myapp-a1b2c-0", "myapp-a1b2c-1"}, got)
}

func TestStalePodReplicaSetNames(t *testing.T) {
	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	otherUUID := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	domainName := appUUID.String() + ".1.0"
	const desiredName = "myapp-a1b2c-2"

	list := []appsv1.ReplicaSet{
		mkPodReplicaSet("myapp-a1b2c-0", domainName),
		mkPodReplicaSet("myapp-a1b2c-1", domainName),
		mkPodReplicaSet(desiredName, domainName),
		mkPodReplicaSet("otherapp-x9y8z-0", otherUUID.String()+".1.0"),
	}

	got := stalePodReplicaSetNames(list, appUUID, desiredName, 2)
	assert.ElementsMatch(t, []string{"myapp-a1b2c-0", "myapp-a1b2c-1"}, got)
}

func TestTrailingCounter(t *testing.T) {
	tests := []struct {
		name        string
		wantCounter uint32
		wantOK      bool
	}{
		{name: "myapp-a1b2c-2", wantCounter: 2, wantOK: true},
		{name: "myapp-a1b2c-0", wantCounter: 0, wantOK: true},
		{name: "myapp-a1b2c-", wantOK: false},
		{name: "myapp-a1b2c-abc", wantOK: false},
		{name: "noseparator", wantOK: false},
		{name: "", wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			counter, ok := trailingCounter(tc.name)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantCounter, counter)
			}
		})
	}
}
