// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// The environment every test in this package shares, and the Kubernetes
// readers they assert through. A file named for a test holds only that test.
//
// Reaching into Kubernetes is a deliberate exception to the framework
// guideline "assert against the EVE API, not internal state" (evetest/
// README.md): two of the three things this suite verifies have no EVE API
// representation -- whether k3s applied the registration manifest, and which
// disks Longhorn was given. The node list is checked through both, and the
// point there is that the two agree.
//
// Kubernetes reads return an error instead of failing the test: on a
// converging cluster "not up yet" is transient and callers retry.

package basemode_test

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	// baseModeDevices is how many EVE devices the suite runs. Every test
	// declares all of them: evetest provisions devices once (the broker
	// refuses a second SetupDevices call and wires the SDN VM's NICs at
	// creation time), and declaring a different set in a later test tears
	// them all down and takes the cluster with them (maybeReuseDevices in
	// evetest/setup.go). Cluster membership is a separate question, answered
	// by the cluster config; the setup test leaves the last device out.
	baseModeDevices = 4

	// baseModeInitialNodes is the size of the cluster the setup test forms.
	// The remaining devices are onboarded but not cluster members.
	baseModeInitialNodes = 3

	// Logical labels this suite gives the two adapters (eth1 and eth0 on the
	// device); ClusterNode.ClusterInterface refers to clusterInterface.
	clusterInterface = "ethernet1"
	mgmtInterface    = "ethernet0"

	// clusterSubnet is the cluster-only network; .1 is the SDN router.
	clusterSubnet = "10.244.244.%d/24"
)

const (
	// kubectlTimeout bounds a single kubectl invocation.
	kubectlTimeout = 2 * time.Minute

	// kubePollInterval is how often the Kubernetes-facing assertions retry.
	// Deliberately unhurried: each poll is an SSH round trip plus a kubectl
	// run inside the kube container.
	kubePollInterval = 15 * time.Second

	// Mirror kubectlx.LonghornNamespace and kubectlx.LonghornDefaultDiskPath:
	// the path EVE hands Longhorn as its default replica store.
	longhornNamespace = "longhorn-system"
	longhornDiskPath  = "/persist/vault/volumes"

	// Mirrors appliedRegistrationYamlName in kube-init/components/
	// registration.go: the AddOn k3s wraps the staged manifest in.
	registrationAddon          = "persist-registration"
	registrationAddonNamespace = "kube-system"
)

// baseModeDevName is the evetest name of the i-th device (0-based). It must
// match the EveDeviceName SeparateClusterPortNodes gives that device's ports.
func baseModeDevName(i int) string {
	return fmt.Sprintf("edge-dev%d", i+1)
}

// baseModeClusterNode describes the i-th device as a cluster node; the first
// bootstraps the cluster and the rest join it.
func baseModeClusterNode(i int) evetest.ClusterNode {
	return evetest.ClusterNode{
		DevName:          baseModeDevName(i),
		ClusterIP:        evetest.IPAddressWithPrefix(fmt.Sprintf(clusterSubnet, i+2)),
		ClusterInterface: clusterInterface,
		BootstrapNode:    i == 0,
	}
}

// baseModeRequirements builds the environment every test shares: all
// baseModeDevices devices, identically specified, plus their network model.
//
// One helper rather than a copy per test because the specifications must match
// across tests or the harness refuses to reuse the VMs; only the reuse policy
// differs, and that is not compared. Call after DefineTestParameters.
func baseModeRequirements(
	reusePolicy evetest.ExistingEdgeDeviceReusePolicy) []evetest.Requirement {
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()
	reqs := make([]evetest.Requirement, 0, baseModeDevices+1)
	for i := 0; i < baseModeDevices; i++ {
		reqs = append(reqs, evetest.RequireEdgeDevice{
			Name:           baseModeDevName(i),
			WithTPM:        withTPM,
			WithHypervisor: evetest.HypervisorKubevirt,
			// Defaults to ext4, for the reason tests/cluster documents: EVE-k
			// formation is fsync-heavy and ZFS's synchronous ZIL commit can
			// crash-loop the apiserver during the etcd transition.
			WithFilesystem:    filesystem,
			DeviceReusePolicy: reusePolicy,
		})
	}
	reqs = append(reqs, evetest.RequireNetworkModel{
		NetworkModel: netmodels.SeparateClusterPortNodes(baseModeDevices),
	})
	return reqs
}

// baseModeClusterState is what the setup test hands to the tests after it.
// Keeping the configuration itself is the point: a fresh EdgeClusterConfig
// would mint a new cluster UUID and join token, breaking the cluster rather
// than extending it.
type baseModeClusterState struct {
	config  *evetest.EdgeClusterConfig
	cluster *evetest.EdgeCluster
	// members are the current cluster members, in node order; devices outside
	// it are onboarded but not in the cluster.
	members []string
}

// baseModeCluster carries the cluster across the suite: the setup test builds
// it, the later tests build on it.
var baseModeCluster *baseModeClusterState

// requireBaseModeCluster returns the cluster the setup test built. Both
// failures are named here rather than left to surface as a half-hour timeout:
// no state means the test was run outside the suite, and state that no longer
// matches the devices means the harness rebuilt the VMs between tests.
func requireBaseModeCluster(t *evetest.T) *baseModeClusterState {
	if baseModeCluster == nil {
		t.Fatalf("No cluster was set up: %s builds on the cluster that "+
			"TestBaseModeClusterSetup forms, so it only runs as part of "+
			"TestBaseModeClusterSuite", t.Name())
	}
	wantID := baseModeCluster.config.ClusterID.String()
	for _, devName := range baseModeCluster.members {
		if info := evetest.GetEdgeDevice(devName).GetClusterInfo(); info != nil {
			if info.GetClusterId() == wantID {
				return baseModeCluster
			}
		}
	}
	t.Fatalf("None of the cluster members %v still reports cluster %s; the "+
		"devices were most likely recreated between tests, leaving the saved "+
		"cluster configuration describing a cluster that no longer exists",
		baseModeCluster.members, wantID)
	return nil // unreachable
}

// readyClusterInfoNodes returns the Ready nodes a ZInfoKubeCluster message
// reports -- the EVE API's view, as opposed to readyKubeNodes'.
func readyClusterInfoNodes(info *eveinfo.ZInfoKubeCluster) []string {
	const nodeReadyCond = eveinfo.KubeNodeConditionType_KUBE_NODE_CONDITION_TYPE_READY
	var ready []string
	for _, node := range info.GetNodes() {
		for _, cond := range node.GetConditions() {
			if cond.GetType() == nodeReadyCond && cond.GetSet() {
				ready = append(ready, node.GetName())
				break
			}
		}
	}
	return ready
}

// kubeNodeList is the minimal shape needed from `kubectl get nodes -o json`.
type kubeNodeList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}

// longhornNodeList is the minimal shape needed from
// `kubectl get nodes.longhorn.io -o json`. Disk keys are Longhorn-generated,
// so only the paths matter.
type longhornNodeList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Disks map[string]struct {
				Path string `json:"path"`
			} `json:"disks"`
		} `json:"spec"`
	} `json:"items"`
}

// kubectlGetJSON runs a `kubectl get ... -o json` and unmarshals the result.
func kubectlGetJSON(dev *evetest.EdgeDevice, args string, out any) error {
	stdout, err := dev.RunKubectl("get "+args+" -o json", kubectlTimeout)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(stdout), out); err != nil {
		return fmt.Errorf("failed to parse `kubectl get %s -o json` output: %w",
			args, err)
	}
	return nil
}

// readyKubeNodes returns the sorted names of the Ready Kubernetes nodes, as
// seen from dev. Registered-but-not-Ready nodes are left out, so a caller
// comparing sets waits for the cluster to settle.
func readyKubeNodes(dev *evetest.EdgeDevice) ([]string, error) {
	var list kubeNodeList
	if err := kubectlGetJSON(dev, "nodes", &list); err != nil {
		return nil, err
	}
	var ready []string
	for _, item := range list.Items {
		for _, cond := range item.Status.Conditions {
			if cond.Type == "Ready" && cond.Status == "True" {
				ready = append(ready, item.Metadata.Name)
				break
			}
		}
	}
	sort.Strings(ready)
	return ready, nil
}

// longhornNodeDisks returns the disk paths configured on every Longhorn node,
// keyed by node name.
func longhornNodeDisks(dev *evetest.EdgeDevice) (map[string][]string, error) {
	var list longhornNodeList
	err := kubectlGetJSON(dev, "nodes.longhorn.io -n "+longhornNamespace, &list)
	if err != nil {
		return nil, err
	}
	disks := make(map[string][]string, len(list.Items))
	for _, item := range list.Items {
		paths := make([]string, 0, len(item.Spec.Disks))
		for _, disk := range item.Spec.Disks {
			paths = append(paths, disk.Path)
		}
		sort.Strings(paths)
		disks[item.Metadata.Name] = paths
	}
	return disks, nil
}

// clusterInfoReadyNodes returns the Ready nodes some member reports for
// clusterID, or nil when none is. Only the kube-stats leader publishes cluster
// info and the others unpublish it, so the members are asked collectively.
func clusterInfoReadyNodes(members []string, clusterID string) []string {
	for _, devName := range members {
		info := evetest.GetEdgeDevice(devName).GetClusterInfo()
		if info == nil || info.GetClusterId() != clusterID {
			continue
		}
		return readyClusterInfoNodes(info)
	}
	return nil
}

// expectClusterInfoNodes waits until a member reports exactly the expected
// nodes Ready for clusterID. Polled, not watched: info is sent only when its
// content changes, so a watch opened here can wait for a message that never
// comes.
func expectClusterInfoNodes(t *WithT, members []string, clusterID string,
	expected []string, timeout time.Duration) {
	t.Eventually(func() []string {
		return clusterInfoReadyNodes(members, clusterID)
	}, timeout, kubePollInterval).Should(ConsistOf(expected),
		"the EVE API should report exactly %v ready in cluster %s",
		expected, clusterID)
}

// expectReadyKubeNodes waits until exactly the expected set of nodes reports
// Ready in Kubernetes, as seen from dev.
func expectReadyKubeNodes(t *WithT, dev *evetest.EdgeDevice,
	expected []string, timeout time.Duration) {
	want := append([]string(nil), expected...)
	sort.Strings(want)
	t.Eventually(func() ([]string, error) {
		return readyKubeNodes(dev)
	}, timeout, kubePollInterval).Should(Equal(want),
		"Kubernetes should report exactly the nodes %v as Ready", want)
}

// baseModeRegistrationManifest is the manifest the controller hands the
// cluster. A real one carries a registration agent; this one carries a single
// ConfigMap, because what is under test is the delivery path -- encrypted with
// the join token, decrypted by zedkube onto /persist, staged by kube-init,
// applied by k3s -- and not the contents. A ConfigMap is the smallest object
// that proves the path ran and carried the right bytes.
const baseModeRegistrationManifest = `apiVersion: v1
kind: ConfigMap
metadata:
  name: evetest-registration
  namespace: default
data:
  registered: "true"
`

const (
	registrationConfigMap          = "evetest-registration"
	registrationConfigMapNamespace = "default"
	registrationConfigMapKey       = "registered"
	registrationConfigMapValue     = "true"
)

// expectRegistrationApplied waits until Kubernetes shows the registration
// manifest applied. Both halves are checked because they fail differently: a
// missing AddOn points at the delivery path (never decrypted, never staged),
// a missing ConfigMap at a manifest that was applied but rejected.
func expectRegistrationApplied(t *WithT, dev *evetest.EdgeDevice, timeout time.Duration) {
	var addon struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	t.Eventually(func() error {
		return kubectlGetJSON(dev,
			"addon "+registrationAddon+" -n "+registrationAddonNamespace, &addon)
	}, timeout, kubePollInterval).Should(Succeed(),
		"k3s should apply the staged registration manifest as AddOn %q",
		registrationAddon)

	var configMap struct {
		Data map[string]string `json:"data"`
	}
	t.Eventually(func() (string, error) {
		err := kubectlGetJSON(dev, "configmap "+registrationConfigMap+
			" -n "+registrationConfigMapNamespace, &configMap)
		if err != nil {
			return "", err
		}
		return configMap.Data[registrationConfigMapKey], nil
	}, timeout, kubePollInterval).Should(Equal(registrationConfigMapValue),
		"the registration manifest should have created ConfigMap %q with %s=%q",
		registrationConfigMap, registrationConfigMapKey, registrationConfigMapValue)
}
