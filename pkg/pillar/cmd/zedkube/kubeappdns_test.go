// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func readyKubeAppStatus(niUUID uuid.UUID) types.AppNetworkStatus {
	return types.AppNetworkStatus{
		UUIDandVersion: types.UUIDandVersion{UUID: uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))},
		Activated:      true,
		ConfigInSync:   true,
		DisplayName:    "native-ni-server",
		KubeApp: &types.KubeAppInfo{
			Namespace: "default",
			OwnerName: "native-ni-server",
		},
		AppNetAdapterList: []types.AppNetAdapterStatus{{
			AppNetAdapterConfig: types.AppNetAdapterConfig{Network: niUUID},
			VifInfo: types.VifInfo{VifConfig: types.VifConfig{
				Mac: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
			}},
			AssignedAddresses: types.AssignedAddrs{
				IPv4Addrs: []types.AssignedAddr{{Address: net.ParseIP("10.55.0.101")}},
				IPv6Addrs: []types.AssignedAddr{{Address: net.ParseIP("fd00:55::101")}},
			},
		}},
	}
}

func TestAllocationsForStatusRequiresReadyApp(t *testing.T) {
	niUUID := uuid.Must(uuid.FromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
	niNames := map[uuid.UUID]string{niUUID: "native-conntest-ni"}

	tests := []struct {
		name   string
		mutate func(*types.AppNetworkStatus)
		want   int
	}{
		{name: "ready", want: 1},
		{name: "inactive", mutate: func(s *types.AppNetworkStatus) { s.Activated = false }},
		{name: "pending", mutate: func(s *types.AppNetworkStatus) { s.PendingAdd = true }},
		{name: "not in sync", mutate: func(s *types.AppNetworkStatus) { s.ConfigInSync = false }},
		{name: "errored", mutate: func(s *types.AppNetworkStatus) { s.SetErrorNow("allocation failed") }},
		{name: "invalid NI display name", mutate: func(*types.AppNetworkStatus) {
			niNames[niUUID] = "Not Kubernetes Safe"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := readyKubeAppStatus(niUUID)
			localNINames := map[uuid.UUID]string{niUUID: niNames[niUUID]}
			if tc.mutate != nil {
				tc.mutate(&status)
				localNINames[niUUID] = niNames[niUUID]
			}
			got := allocationsForStatus(status, localNINames, "edge-node-1")
			if len(got) != tc.want {
				t.Fatalf("allocationsForStatus() returned %d allocation(s), want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func TestAllocationsForStatusIncludesControllerManagedEVEApp(t *testing.T) {
	niUUID := uuid.Must(uuid.FromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
	status := readyKubeAppStatus(niUUID)
	status.DisplayName = "enc-conntest-vm"
	status.KubeApp = nil

	got := allocationsForStatus(status,
		map[uuid.UUID]string{niUUID: "enc-conntest-ni"}, "edge-node-1")
	if len(got) != 1 {
		t.Fatalf("controller-managed EVE app produced %d allocation(s), want 1: %+v", len(got), got)
	}
	allocation := got[0]
	if allocation.AppName != "enc-conntest-vm" ||
		allocation.Namespace != kubeapi.EVEKubeNameSpace {
		t.Fatalf("unexpected EVE app DNS identity: %+v", allocation)
	}

	rendered := renderKubeAppDNS(got)
	for _, want := range []string{
		"enc-conntest-vm.eve-kube-app.enc-conntest-ni.internal",
		"enc-conntest-vm.internal",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered CoreDNS config does not contain %q:\n%s", want, rendered)
		}
	}
}

// TestAllocationsForStatusUsesDisplayNameForNativeKubeApp catches a
// regression where the ReplicaSet owner name (including its template hash)
// leaks into DNS instead of the Deployment display name selected by zedkube.
func TestAllocationsForStatusUsesDisplayNameForNativeKubeApp(t *testing.T) {
	niUUID := uuid.Must(uuid.FromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
	status := readyKubeAppStatus(niUUID)
	status.DisplayName = "local-switch-ni-dp"
	status.KubeApp.OwnerName = "local-switch-ni-dp-6d97b5bd87"

	got := allocationsForStatus(status,
		map[uuid.UUID]string{niUUID: "cluster-switch-ni"}, "edge-node-1")
	if len(got) != 1 {
		t.Fatalf("native Kubernetes app produced %d allocation(s), want 1: %+v", len(got), got)
	}
	if got[0].AppName != "local-switch-ni-dp" {
		t.Fatalf("DNS app name is %q, want Deployment display name %q",
			got[0].AppName, "local-switch-ni-dp")
	}
	if got[0].Namespace != "default" {
		t.Fatalf("DNS namespace is %q, want %q", got[0].Namespace, "default")
	}
}

func TestAllocationsForStatusKeepsMACWithoutAddress(t *testing.T) {
	niUUID := uuid.Must(uuid.FromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
	status := readyKubeAppStatus(niUUID)
	status.AppNetAdapterList[0].AssignedAddresses = types.AssignedAddrs{}

	got := allocationsForStatus(status,
		map[uuid.UUID]string{niUUID: "external-switch"}, "edge-node-1")
	if len(got) != 1 {
		t.Fatalf("MAC-only switch allocation was dropped: %+v", got)
	}
	if len(got[0].MACs) != 1 || got[0].MACs[0] != "02:00:00:00:00:01" {
		t.Fatalf("unexpected MAC-only allocation: %+v", got[0])
	}
	if len(got[0].IPv4) != 0 || len(got[0].IPv6) != 0 {
		t.Fatalf("MAC-only allocation unexpectedly has addresses: %+v", got[0])
	}
}

func TestRenderKubeAppDNSCanonicalAndUniqueAlias(t *testing.T) {
	alloc := kubeAppNIAllocation{
		AppUUID:       "11111111-1111-1111-1111-111111111111",
		AppName:       "native-ni-server",
		Namespace:     "default",
		NIUUID:        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		NIDisplayName: "native-conntest-ni",
		NodeName:      "edge-node-1",
		IPv4:          []string{"10.55.0.101"},
		IPv6:          []string{"fd00:55::101"},
	}
	got := renderKubeAppDNS([]kubeAppNIAllocation{alloc})
	for _, want := range []string{
		"10.55.0.101 native-ni-server.default.native-conntest-ni.internal native-ni-server.internal",
		"fd00:55::101 native-ni-server.default.native-conntest-ni.internal native-ni-server.internal",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered CoreDNS config does not contain %q:\n%s", want, got)
		}
	}
}

func TestRenderKubeAppDNSDropsAmbiguousShortAlias(t *testing.T) {
	allocs := []kubeAppNIAllocation{
		{AppUUID: "1", AppName: "api", Namespace: "blue", NIUUID: "a", NIDisplayName: "ni-blue", IPv4: []string{"10.1.0.2"}},
		{AppUUID: "2", AppName: "api", Namespace: "green", NIUUID: "b", NIDisplayName: "ni-green", IPv4: []string{"10.2.0.2"}},
	}
	got := renderKubeAppDNS(allocs)
	if strings.Contains(got, " api.internal") {
		t.Fatalf("ambiguous short alias was rendered:\n%s", got)
	}
	for _, canonical := range []string{
		"api.blue.ni-blue.internal",
		"api.green.ni-green.internal",
	} {
		if !strings.Contains(got, canonical) {
			t.Errorf("canonical name %q missing:\n%s", canonical, got)
		}
	}
}

func TestRenderKubeAppDNSRejectsMalformedAddresses(t *testing.T) {
	alloc := kubeAppNIAllocation{
		AppUUID: "1", AppName: "api", Namespace: "default",
		NIUUID: "a", NIDisplayName: "local-ni",
		IPv4: []string{"10.1.0.2\n    reload", "fd00::1"},
		IPv6: []string{"10.1.0.3", "fd00::2"},
	}
	got := renderKubeAppDNS([]kubeAppNIAllocation{alloc})
	if strings.Contains(got, "reload") || strings.Contains(got, "10.1.0.3") ||
		strings.Contains(got, "fd00::1") {
		t.Fatalf("malformed or wrong-family address reached CoreDNS output:\n%s", got)
	}
	if !strings.Contains(got, "fd00::2 api.default.local-ni.internal") {
		t.Fatalf("valid IPv6 address was dropped:\n%s", got)
	}
}

func TestRenderKubeAppDNSRejectsNonRoutableAddresses(t *testing.T) {
	alloc := kubeAppNIAllocation{
		AppUUID: "1", AppName: "api", Namespace: "default",
		NIUUID: "a", NIDisplayName: "switch-ni",
		IPv4: []string{"127.0.0.1", "169.254.1.2", "224.0.0.1", "192.168.1.190"},
		IPv6: []string{"::1", "fe80::1", "ff02::1", "2600:1700:6d1d:e000::190"},
	}

	got := renderKubeAppDNS([]kubeAppNIAllocation{alloc})
	for _, rejected := range []string{
		"127.0.0.1", "169.254.1.2", "224.0.0.1", "::1", "fe80::1", "ff02::1",
	} {
		if strings.Contains(got, "\n        "+rejected+" ") {
			t.Errorf("non-routable address %q reached CoreDNS output:\n%s", rejected, got)
		}
	}
	for _, want := range []string{"192.168.1.190", "2600:1700:6d1d:e000::190"} {
		if !strings.Contains(got, want) {
			t.Errorf("routable address %q was dropped:\n%s", want, got)
		}
	}
}

func TestReconcileNodeNIAllocationsReplacesOnlyLocalNodeRecords(t *testing.T) {
	existing := map[string]kubeAppNIAllocation{
		"remote-app": {
			AppUUID: "remote-app", AppName: "remote", Namespace: "default",
			NIUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", NIDisplayName: "native-conntest-ni",
			NodeName: "edge-node-2", IPv4: []string{"10.55.0.102"},
		},
		"stale-local-app": {
			AppUUID: "stale-local-app", AppName: "stale", Namespace: "default",
			NIUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", NIDisplayName: "native-conntest-ni",
			NodeName: "edge-node-1", IPv4: []string{"10.55.0.103"},
		},
	}
	payload, err := json.Marshal(kubeAppNIAllocationConfig{Version: 1, Allocations: existing})
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "eve-ni-native-conntest-ni-allocations",
			Namespace: "eve-kube-app",
			Labels: map[string]string{
				"eve.zededa.com/managed-by": "zedkube-ni-dns",
			},
		},
		Data: map[string]string{"allocations.json": string(payload)},
	})
	desired := []kubeAppNIAllocation{{
		AppUUID: "new-local-app", AppName: "new-local", Namespace: "default",
		NIUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", NIDisplayName: "native-conntest-ni",
		NodeName: "edge-node-1", IPv4: []string{"10.55.0.104"},
	}}

	if err := reconcileNodeNIAllocations(context.Background(), client, "edge-node-1", desired); err != nil {
		t.Fatal(err)
	}
	cm, err := client.CoreV1().ConfigMaps("eve-kube-app").Get(context.Background(),
		"eve-ni-native-conntest-ni-allocations", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var got kubeAppNIAllocationConfig
	if err := json.Unmarshal([]byte(cm.Data["allocations.json"]), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Allocations["remote-app"]; !ok {
		t.Error("remote node allocation was removed")
	}
	if _, ok := got.Allocations["stale-local-app"]; ok {
		t.Error("stale allocation owned by the local node was retained")
	}
	if allocation, ok := got.Allocations["new-local-app"]; !ok || allocation.NodeName != "edge-node-1" {
		t.Errorf("new local allocation was not stored: %+v", got.Allocations)
	}
}

func TestReconcileNodeNIAllocationsRejectsNIDisplayNameCollision(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "eve-ni-shared-name-allocations", Namespace: "eve-kube-app",
			Labels: map[string]string{
				"eve.zededa.com/managed-by":       "zedkube-ni-dns",
				"eve.zededa.com/network-instance": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			},
		},
		Data: map[string]string{"allocations.json": `{"version":1,"allocations":{}}`},
	})
	desired := []kubeAppNIAllocation{{
		AppUUID: "new-app", AppName: "new-app", Namespace: "default",
		NIUUID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", NIDisplayName: "shared-name",
		NodeName: "edge-node-1", IPv4: []string{"10.55.0.104"},
	}}

	err := reconcileNodeNIAllocations(context.Background(), client, "edge-node-1", desired)
	if err == nil || !strings.Contains(err.Error(), "display-name collision") {
		t.Fatalf("NI display-name collision was not rejected: %v", err)
	}
}

func TestReconcileNodeNIAllocationsCollisionDoesNotBlockOtherNIs(t *testing.T) {
	client := fake.NewSimpleClientset()
	desired := []kubeAppNIAllocation{
		{AppUUID: "a", AppName: "a", Namespace: "default",
			NIUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", NIDisplayName: "shared-name",
			NodeName: "edge-node-1", IPv4: []string{"10.55.0.101"}},
		{AppUUID: "b", AppName: "b", Namespace: "default",
			NIUUID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", NIDisplayName: "shared-name",
			NodeName: "edge-node-1", IPv4: []string{"10.55.0.102"}},
		{AppUUID: "c", AppName: "c", Namespace: "default",
			NIUUID: "cccccccc-cccc-cccc-cccc-cccccccccccc", NIDisplayName: "other-ni",
			NodeName: "edge-node-1", IPv4: []string{"10.55.0.103"}},
	}

	err := reconcileNodeNIAllocations(context.Background(), client, "edge-node-1", desired)
	if err == nil || !strings.Contains(err.Error(), "display-name collision") {
		t.Fatalf("NI display-name collision was not reported: %v", err)
	}
	cmAPI := client.CoreV1().ConfigMaps("eve-kube-app")
	if _, err := cmAPI.Get(context.Background(), "eve-ni-other-ni-allocations",
		metav1.GetOptions{}); err != nil {
		t.Errorf("non-colliding NI was not published: %v", err)
	}
	if _, err := cmAPI.Get(context.Background(), "eve-ni-shared-name-allocations",
		metav1.GetOptions{}); err == nil {
		t.Error("colliding ConfigMap was written")
	}
}

func TestReconcileNodeNIAllocationsCollisionDropsStaleLocalRecords(t *testing.T) {
	payload, err := json.Marshal(kubeAppNIAllocationConfig{Version: 1,
		Allocations: map[string]kubeAppNIAllocation{
			"stale": {AppUUID: "stale", NodeName: "edge-node-1",
				NIUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", NIDisplayName: "shared-name"},
			"foreign": {AppUUID: "foreign", NodeName: "edge-node-2",
				NIUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", NIDisplayName: "shared-name"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "eve-ni-shared-name-allocations", Namespace: "eve-kube-app",
			Labels: map[string]string{"eve.zededa.com/managed-by": "zedkube-ni-dns"},
		},
		Data: map[string]string{"allocations.json": string(payload)},
	})
	desired := []kubeAppNIAllocation{
		{AppUUID: "a", NIUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			NIDisplayName: "shared-name", NodeName: "edge-node-1"},
		{AppUUID: "b", NIUUID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
			NIDisplayName: "shared-name", NodeName: "edge-node-1"},
	}

	err = reconcileNodeNIAllocations(context.Background(), client, "edge-node-1", desired)
	if err == nil || !strings.Contains(err.Error(), "display-name collision") {
		t.Fatalf("NI display-name collision was not reported: %v", err)
	}
	cm, err := client.CoreV1().ConfigMaps("eve-kube-app").Get(context.Background(),
		"eve-ni-shared-name-allocations", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var got kubeAppNIAllocationConfig
	if err := json.Unmarshal([]byte(cm.Data["allocations.json"]), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Allocations["stale"]; ok {
		t.Error("stale local allocation was retained")
	}
	if _, ok := got.Allocations["foreign"]; !ok {
		t.Error("allocation owned by another node was dropped")
	}
	if len(got.Allocations) != 1 {
		t.Errorf("unexpected allocations: %+v", got.Allocations)
	}
}

func TestReconcileNodeNIAllocationsDeletesEmptyConfigMap(t *testing.T) {
	payload, err := json.Marshal(kubeAppNIAllocationConfig{Version: 1,
		Allocations: map[string]kubeAppNIAllocation{
			"gone": {AppUUID: "gone", NodeName: "edge-node-1",
				NIUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", NIDisplayName: "old-ni"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "eve-ni-old-ni-allocations", Namespace: "eve-kube-app",
			Labels: map[string]string{"eve.zededa.com/managed-by": "zedkube-ni-dns"},
		},
		Data: map[string]string{"allocations.json": string(payload)},
	})

	if err := reconcileNodeNIAllocations(context.Background(), client, "edge-node-1", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoreV1().ConfigMaps("eve-kube-app").Get(context.Background(),
		"eve-ni-old-ni-allocations", metav1.GetOptions{}); err == nil {
		t.Error("empty allocation ConfigMap was not deleted")
	}
}

func TestReconcileCoreDNSPreservesForeignDataAndRollsOnlyOnChange(t *testing.T) {
	allocations := map[string]kubeAppNIAllocation{
		"11111111-1111-1111-1111-111111111111": {
			AppUUID: "11111111-1111-1111-1111-111111111111", AppName: "native-ni-server",
			Namespace: "default", NIUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			NIDisplayName: "native-conntest-ni", NodeName: "edge-node-1",
			IPv4: []string{"10.55.0.101"},
		},
	}
	payload, err := json.Marshal(kubeAppNIAllocationConfig{Version: 1, Allocations: allocations})
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: "eve-ni-native-conntest-ni-allocations", Namespace: "eve-kube-app",
				Labels: map[string]string{"eve.zededa.com/managed-by": "zedkube-ni-dns"},
			},
			Data: map[string]string{"allocations.json": string(payload)},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "coredns-custom", Namespace: "kube-system"},
			Data:       map[string]string{"user.server": "example.test:53 { whoami }\n"},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "coredns", Namespace: "kube-system"},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"user": "keep"}},
			}},
		},
	)

	changed, err := reconcileCoreDNS(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first reconcile did not report a CoreDNS content/rollout change")
	}
	cm, err := client.CoreV1().ConfigMaps("kube-system").Get(context.Background(),
		"coredns-custom", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cm.Data["user.server"] != "example.test:53 { whoami }\n" {
		t.Errorf("foreign coredns-custom data was changed: %+v", cm.Data)
	}
	if !strings.Contains(cm.Data["eve-ni.server"],
		"10.55.0.101 native-ni-server.default.native-conntest-ni.internal native-ni-server.internal") {
		t.Errorf("generated CoreDNS data is missing the NI record:\n%s", cm.Data["eve-ni.server"])
	}
	deployment, err := client.AppsV1().Deployments("kube-system").Get(context.Background(),
		"coredns", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	firstHash := deployment.Spec.Template.Annotations["eve.zededa.com/ni-dns-hash"]
	if firstHash == "" || deployment.Spec.Template.Annotations["user"] != "keep" {
		t.Errorf("CoreDNS rollout annotation was not merged safely: %+v",
			deployment.Spec.Template.Annotations)
	}

	changed, err = reconcileCoreDNS(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("identical second reconcile unnecessarily changed or restarted CoreDNS")
	}
}

func TestReconcileCoreDNSCreatesCustomConfigMapOnFirstAllocation(t *testing.T) {
	payload := `{"version":1,"allocations":{"app":{"appUUID":"app","appName":"api","namespace":"default","niUUID":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","niDisplayName":"local-ni","nodeName":"edge-node-1","ipv4":["10.10.0.2"]}}}`
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: "eve-ni-local-ni-allocations", Namespace: "eve-kube-app",
				Labels: map[string]string{"eve.zededa.com/managed-by": "zedkube-ni-dns"},
			},
			Data: map[string]string{"allocations.json": payload},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "coredns", Namespace: "kube-system"},
		},
	)

	changed, err := reconcileCoreDNS(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first allocation did not create CoreDNS configuration")
	}
	cm, err := client.CoreV1().ConfigMaps("kube-system").Get(context.Background(),
		"coredns-custom", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("coredns-custom was not created: %v", err)
	}
	if !strings.Contains(cm.Data["eve-ni.server"],
		"10.10.0.2 api.default.local-ni.internal api.internal") {
		t.Fatalf("new coredns-custom has unexpected data:\n%s", cm.Data["eve-ni.server"])
	}
}

func TestReconcileKubeAppDNSStateHonorsNativeOrchestrationAndLeadership(t *testing.T) {
	niUUID := uuid.Must(uuid.FromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
	status := readyKubeAppStatus(niUUID)
	niNames := map[uuid.UUID]string{niUUID: "native-conntest-ni"}
	disabled := types.EdgeNodeClusterConfig{
		ClusterType: types.ClusterTypeReplicatedStorage,
	}
	disabledClient := fake.NewSimpleClientset()
	if err := reconcileKubeAppDNSState(context.Background(), disabledClient, disabled, true,
		"edge-node-1", []types.AppNetworkStatus{status}, niNames); err != nil {
		t.Fatal(err)
	}
	if actions := disabledClient.Actions(); len(actions) != 0 {
		t.Fatalf("disabled native orchestration made Kubernetes API calls: %+v", actions)
	}

	enabled := disabled
	enabled.EnableNativeK8SOrchestration = true
	emptyNodeClient := fake.NewSimpleClientset()
	if err := reconcileKubeAppDNSState(context.Background(), emptyNodeClient, enabled, true,
		"", []types.AppNetworkStatus{status}, niNames); err != nil {
		t.Fatal(err)
	}
	if actions := emptyNodeClient.Actions(); len(actions) != 0 {
		t.Fatalf("unknown node identity made Kubernetes API calls: %+v", actions)
	}

	client := fake.NewSimpleClientset()
	if err := reconcileKubeAppDNSState(context.Background(), client, enabled, false,
		"edge-node-1", []types.AppNetworkStatus{status}, niNames); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoreV1().ConfigMaps("eve-kube-app").Get(context.Background(),
		"eve-ni-native-conntest-ni-allocations", metav1.GetOptions{}); err != nil {
		t.Fatalf("follower did not publish its node allocation: %v", err)
	}
	if _, err := client.CoreV1().ConfigMaps("kube-system").Get(context.Background(),
		"coredns-custom", metav1.GetOptions{}); err == nil {
		t.Fatal("follower unexpectedly reconciled cluster-wide CoreDNS")
	}
}
