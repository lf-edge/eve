// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"golang.org/x/crypto/ssh"
)

// Namespace, NI names and app identities used throughout this test. Kept as
// constants because the same values are threaded through manifests (as
// strings), the Multus networks annotation, and the CoreDNS FQDNs
// zedkube/kubeappdns.go derives from them -- getting one out of sync with
// another is a likely source of test bugs.
const (
	// nativeTestNamespace is where the directly-deployed (non-EVE-managed)
	// resources in this test are created, kept separate from EVE's own
	// eve-kube-app namespace -- same convention as mgmtproxy_test.go's
	// mgmtProxyTestNamespace.
	nativeTestNamespace = "default"

	localNIDisplayName  = "local-ni"
	switchNIDisplayName = "switch-ni"

	// appImageName is used for every workload in this test -- the native
	// Pod, the native ReplicaSet, and the EVE-API app -- so "the same app
	// image deployed over EVE API" (the test's last phase) is literal.
	// It bundles sshd (root/testpassword), curl, dig/getent and iproute2,
	// everything the assertions below need.
	appImageName = "lfedge/evetest-ubuntu-ctr"
	appImageTag  = "1.2"
	appSSHUser   = "root"
	appSSHPass   = "testpassword"

	nativeBarePodName    = "native-bare-pod"
	nativeReplicaSetName = "native-replica-app"
	eveAppName           = "eve-app"

	// barePodLocalPort / replicaSetLocalPort are the external (host) ports
	// the local-ni port-mapping ACLs expose the workloads' sshd on,
	// distinct so both workloads can coexist.
	barePodLocalPort    = 8022
	replicaSetLocalPort = 8122

	// replicaSetStaticIP is requested via the "ips" networks-annotation
	// field on the ReplicaSet's local-ni attachment. zedrouter's
	// lookupOrAllocateIPv4ForVIF (pkg/pillar/cmd/zedrouter/ipam.go) rejects
	// a static AppIPAddr that falls inside the NI's own DHCP range (dynamic
	// allocation picks addresses by pure offset within that range with no
	// collision check against static addresses, so the two pools must be disjoint),
	// so this must be inside local-ni's subnet but outside its DHCP range
	// (10.11.12.100-10.11.12.254, see the NI config below).
	replicaSetStaticIP = "10.11.12.50"

	// kubeServiceClusterIP is k3s's default Service CIDR (10.43.0.0/16);
	// the "kubernetes" Service in the default namespace always gets its
	// first address. Used as a fixed, DNS-independent target for
	// "reach a Kubernetes service" checks.
	kubeServiceClusterIP = "10.43.0.1"
	// kubeServiceCIDR is the explicit route zedkube/eve-bridge adds on
	// eth0 for a pod whose default route points elsewhere (see
	// pkg/kube/eve-bridge/eve-bridge.go's clusterSvcIPRange).
	kubeServiceCIDR = "10.43.0.0/16"
)

// nativeNetSelection mirrors the subset of Multus's NetworkSelectionElement
// (k8s.v1.cni.cncf.io/networks, JSON-array form) this test exercises. Built
// locally rather than importing the real type so this test file has no
// dependency on the NAD client library -- it only ever marshals these to
// JSON for a pod annotation, never unmarshals or inspects them.
type nativeNetSelection struct {
	Name         string              `json:"name"`
	Namespace    string              `json:"namespace,omitempty"`
	Interface    string              `json:"interface,omitempty"`
	MAC          string              `json:"mac,omitempty"`
	IPs          []string            `json:"ips,omitempty"`
	DefaultRoute []string            `json:"default-route,omitempty"`
	PortMappings []nativePortMapping `json:"portMappings,omitempty"`
}

// nativePortMapping mirrors Multus's PortMapEntry.
type nativePortMapping struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
}

// niNADRef returns the "<namespace>/<name>" NAD reference a directly-deployed
// workload in any namespace uses to attach to niDisplayName, matching
// pkg/pillar/cmd/zedkube/ninad.go's niNADName (a "ni-" prefix on the
// sanitized display name) and the fact that all per-NI NADs live in the
// single eve-kube-app namespace.
func niNADRef(niDisplayName string) (namespace, name string) {
	return "eve-kube-app", "ni-" + niDisplayName
}

// networksAnnotationJSON marshals sels into the JSON-array form of the
// k8s.v1.cni.cncf.io/networks annotation.
func networksAnnotationJSON(t *WithT, sels []nativeNetSelection) string {
	raw, err := json.Marshal(sels)
	t.Expect(err).ToNot(HaveOccurred(), "marshal networks annotation")
	return string(raw)
}

// TestNativeKubeAppNetworking verifies that Kubernetes workloads deployed
// directly into eve-k's k3s cluster (bypassing the EVE API entirely, as a
// Rancher-style helm chart or raw yaml would) can attach to EVE Network
// Instances via the same Multus "k8s.v1.cni.cncf.io/networks" annotation
// controller-managed apps already use, and interoperate with an
// EVE-API-deployed app on the same Network Instances (connectivity, DNS).
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port (eth0), SDN DNS,
//     http-server.test endpoint, controller reachable.
//
// Device configuration
// --------------------
//   - clusterDeviceRequirements (top of this file): WithHypervisor=Kubevirt,
//     DeviceReusePolicy=ResetDeviceConfig, so the "edge-dev" device from
//     TestSingleNodeCluster (same requirements and network model) is reused
//     instead of recreated.
//   - A single-node EdgeNodeClusterConfig (CLUSTER_TYPE_REPLICATED_STORAGE)
//     with EnableNativeK8SOrchestration=true -- this is the opt-in gate
//     pkg/pillar/cmd/zedkube/ninad.go checks before provisioning any per-NI
//     NAD at all, so without it none of this feature activates. A real
//     multi-node EdgeClusterConfig is used (not a bare EdgeDeviceConfig)
//     purely to get a valid, encrypted EdgeNodeCluster proto built for a
//     single node -- there is no second node and no real cluster-interface
//     traffic. This is also the reused device's first exposure to an
//     EdgeNodeClusterConfig, since TestSingleNodeCluster never sets one.
//   - local-ni (Local NI): 10.11.12.0/24, gateway .1, DHCP range .2-.254.
//   - switch-ni (Switch NI): no subnet of its own -- a pure L2 bridge
//     extension of ethernet0, so an attached pod gets a DHCP lease from the
//     same SDN DHCP server eth0 itself uses (172.20.20.0/24).
//
// Every directly-deployed workload below requests explicit Multus
// "interface" names ("localni", "switchni") in its networks annotation so
// shell assertions target stable interface names instead of guessing
// Multus's default net1/net2 numbering.
//
// Phases
// ------
//  1. setup-done -> cluster-is-ready: bring up the single eve-k node with
//     native orchestration enabled; configure local-ni and switch-ni.
//  2. bare-pod-is-deployed: a bare Pod (nativeBarePodName) attaches to both
//     NIs -- a static mac on switch-ni, a portMappings entry on local-ni.
//     Assertions: the port-mapping is reachable (SSH to the device's eth0
//     IP on barePodLocalPort), the primary default route is still eth0
//     (no default-route requested), the switch-ni MAC matches the
//     annotation exactly, a Kubernetes service (the "kubernetes" ClusterIP)
//     is reachable over the (default) primary interface, and the pod has
//     an IPv4 address on both NIs.
//  3. replicaset-is-deployed: a bare ReplicaSet (replicas: 1,
//     nativeReplicaSetName) attaches to both NIs -- a static "ips" request
//     plus a "default-route" request plus a portMappings entry, all on
//     local-ni; switch-ni is a plain attachment. Assertions: the
//     port-mapping is reachable (replicaSetLocalPort), the default route
//     is now local-ni (not eth0, per the default-route request), eth0
//     still carries explicit routes to the Kubernetes service CIDR and the
//     node's own IP (so the control plane stays reachable despite not
//     being the default route) -- verified both by inspecting `ip route`
//     and by actually reaching the "kubernetes" ClusterIP over eth0 -- an
//     outbound request to the SDN's http-server.test succeeds via local-ni
//     (the new default route), and the requested static IP
//     (replicaSetStaticIP) is actually assigned on local-ni, with switch-ni
//     also holding its own (DHCP) address.
//  4. eve-app-is-deployed: the identical image+tag is deployed through the
//     EVE API as a NOHYPER container app (eveAppName) with adapters on
//     both NIs (NOHYPER specifically so it also gets the pod default
//     network -- a KubeVirt VM-mode app would not).
//  5. cross-app connectivity and DNS, in both directions between the
//     ReplicaSet pod and the EVE-API app's pod: ICMP reachability over the
//     primary pod network (eth0/k3s pod CIDR), over local-ni and over
//     switch-ni; DNS resolution of each other's zedkube/kubeappdns.go
//     CoreDNS record (<app>.<namespace>.local-ni.internal) to the correct
//     local-ni IP.
//  6. scale-cycled: the ReplicaSet is scaled 1->0->1 (a bare ReplicaSet, so
//     this is not a "rollout" and never changes its name); the new pod's
//     MAC on both local-ni and switch-ni must match what was recorded
//     before scaling down, proving the derived identity (and therefore the
//     MAC) survived the recreate.
//
// Test parameters
// ---------------
//   - TPM (bool) and Filesystem, both standard cluster-test parameters.
//
// Suite placement
// ---------------
//   - TestNodeClusterSuite, right after TestSingleNodeCluster: its device
//     requirements and network model match exactly, so the framework
//     reuses TestSingleNodeCluster's device instead of creating a new one.
func TestNativeKubeAppNetworking(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()
	log := evetest.Logger()

	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	devName := "edge-dev"
	requiredDevice := clusterDeviceRequirements(devName, withTPM, filesystem, false)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCP,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	evetest.Checkpoint("setup-done")

	// A single-node "cluster" purely to get a valid EdgeNodeCluster proto
	// with EnableNativeK8SOrchestration set -- see NewEdgeClusterConfig.
	clusterCfg := evetest.NewEdgeClusterConfig(
		eveconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE,
		true, // enableNativeK8SOrchestration
		evetest.ClusterNode{
			DevName:          devName,
			ClusterIP:        evetest.IPAddressWithPrefix("10.244.244.2/24"),
			ClusterInterface: "ethernet0",
			BootstrapNode:    true,
		},
	)
	mgmtNet := clusterCfg.AddNetwork(
		evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
	clusterCfg.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   mgmtNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	devConfig := clusterCfg.GetDeviceConfig(devName)

	device := evetest.GetEdgeDevice(devName)
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	timeout := 20 * time.Minute
	log.Infof("Waiting for the single-node eve-k cluster to become ready")
	device.WaitForClusterNodeIsReady(timeout)
	evetest.Checkpoint("cluster-is-ready")

	localNIUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: localNIDisplayName,
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		// .2-.99 is left out of the DHCP range so replicaSetStaticIP (.50)
		// can be statically assigned there -- see its own doc comment.
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.100"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:       evetest.IPAddress("10.11.12.1"),
		EnableFlowlog: true,
		MTU:           1500,
		ClusterWide:   true,
	})
	switchNIUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: switchNIDisplayName,
		Port:        "ethernet0",
		MTU:         1500,
		ClusterWide: true,
	})
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("nis-configured")

	shortTimeout := 30 * time.Second
	// A native pod's first CNI ADD on a freshly-created per-NI NAD can take a
	// few minutes: it waits on the stats-leader's NAD creation, zedkube's
	// own reconcile tick, and (observed) the external "dhcp" CNI IPAM
	// daemon's /run/cni/dhcp.sock not being up yet on a cold cluster,
	// causing several retried attempts before the kubelet's own backoff
	// lets one through -- observed up to ~3.5 minutes on its own. The image
	// pull then stacks on top of that (observed total up to ~5m50s), so the
	// budget needs comfortable headroom above either individually.
	podReadyTimeout := 10 * time.Minute
	deviceIP := firstIPv4(t, device.GetDeviceIPAddress("ethernet0"), "device ethernet0")

	// --- Phase 1: bare Pod, attached to both NIs ---
	//
	// mac is requested on switch-ni; a port-map (-> sshd) is requested on
	// local-ni. Neither selection requests default-route, so eth0 must
	// remain the default route.
	const barePodSwitchMAC = "02:00:00:00:01:01"
	localNINamespace, localNIName := niNADRef(localNIDisplayName)
	switchNINamespace, switchNIName := niNADRef(switchNIDisplayName)
	barePodAnnotation := networksAnnotationJSON(t, []nativeNetSelection{
		{
			Name:      localNIName,
			Namespace: localNINamespace,
			Interface: "localni",
			PortMappings: []nativePortMapping{
				{HostPort: barePodLocalPort, ContainerPort: 22, Protocol: "tcp"},
			},
		},
		{
			Name:      switchNIName,
			Namespace: switchNINamespace,
			Interface: "switchni",
			MAC:       barePodSwitchMAC,
		},
	})
	barePodManifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  annotations:
    k8s.v1.cni.cncf.io/networks: '%s'
spec:
  containers:
  - name: %s
    image: %s:%s
`, nativeBarePodName, nativeTestNamespace, barePodAnnotation, nativeBarePodName,
		appImageName, appImageTag)
	log.Infof("Deploying the bare Pod %s/%s directly via kubectl",
		nativeTestNamespace, nativeBarePodName)
	applyManifest(t, device, barePodManifest, shortTimeout)
	waitForPodReady(t, device, nativeTestNamespace, nativeBarePodName, podReadyTimeout)
	evetest.Checkpoint("bare-pod-is-deployed")

	log.Infof("Testing bare pod's local-ni port mapping (SSH)")
	t.Eventually(func() string {
		out, _ := sshRun(net.JoinHostPort(deviceIP.String(),
			fmt.Sprintf("%d", barePodLocalPort)), "hostname", shortTimeout)
		return strings.TrimSpace(out)
	}, 2*time.Minute, 5*time.Second).Should(Equal(nativeBarePodName),
		"bare pod must be reachable over its local-ni port mapping")

	bareRunner := kubectlExecRunner(device, nativeTestNamespace, nativeBarePodName, shortTimeout)
	defaultRoute := mustRun(t, bareRunner, "ip route show default")
	t.Expect(defaultRoute).To(ContainSubstring("dev eth0"),
		"bare pod (no default-route requested) must keep eth0 as its default route")

	switchMAC := mustRun(t, bareRunner, "cat /sys/class/net/switchni/address")
	t.Expect(strings.TrimSpace(switchMAC)).To(Equal(barePodSwitchMAC),
		"switch-ni interface must carry the MAC requested in the networks annotation")

	svcCode := mustRun(t, bareRunner, curlStatusCmd(kubeServiceClusterIP))
	t.Expect(svcCode).ToNot(Equal("000"),
		"the Kubernetes service ClusterIP must be reachable over the default "+
			"(primary) interface, got curl status %q", svcCode)

	localNIAddr := mustRun(t, bareRunner, "ip -4 -o addr show dev localni")
	bareLocalNIIP := firstIPInCIDR(t, localNIAddr, "10.11.12.0/24")
	switchNIAddr := mustRun(t, bareRunner, "ip -4 -o addr show dev switchni")
	bareSwitchNIIP := firstIPInCIDR(t, switchNIAddr, "172.20.20.0/24")
	log.Infof("Bare pod: local-ni IP=%s, switch-ni IP=%s", bareLocalNIIP, bareSwitchNIIP)

	// --- Phase 2: bare ReplicaSet (replicas: 1), attached to both NIs ---
	//
	// ips + default-route + a port-map are all requested on local-ni;
	// switch-ni is a plain attachment.
	replicaSetAnnotation := networksAnnotationJSON(t, []nativeNetSelection{
		{
			Name:         localNIName,
			Namespace:    localNINamespace,
			Interface:    "localni",
			IPs:          []string{replicaSetStaticIP + "/24"},
			DefaultRoute: []string{"10.11.12.1"},
			PortMappings: []nativePortMapping{
				{HostPort: replicaSetLocalPort, ContainerPort: 22, Protocol: "tcp"},
			},
		},
		{
			Name:      switchNIName,
			Namespace: switchNINamespace,
			Interface: "switchni",
		},
	})
	const replicaSetLabel = "app=" + nativeReplicaSetName
	replicaSetManifest := fmt.Sprintf(`apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %s
  template:
    metadata:
      labels:
        app: %s
      annotations:
        k8s.v1.cni.cncf.io/networks: '%s'
    spec:
      containers:
      - name: %s
        image: %s:%s
`, nativeReplicaSetName, nativeTestNamespace, nativeReplicaSetName, nativeReplicaSetName,
		replicaSetAnnotation, nativeReplicaSetName, appImageName, appImageTag)
	log.Infof("Deploying the bare ReplicaSet %s/%s directly via kubectl",
		nativeTestNamespace, nativeReplicaSetName)
	applyManifest(t, device, replicaSetManifest, shortTimeout)

	rsPod := discoverPodByLabel(t, device, nativeTestNamespace, replicaSetLabel, podReadyTimeout)
	waitForPodReady(t, device, nativeTestNamespace, rsPod, podReadyTimeout)
	evetest.Checkpoint("replicaset-is-deployed")

	log.Infof("Testing ReplicaSet pod's local-ni port mapping (SSH)")
	t.Eventually(func() string {
		out, _ := sshRun(net.JoinHostPort(deviceIP.String(),
			fmt.Sprintf("%d", replicaSetLocalPort)), "hostname", shortTimeout)
		return strings.TrimSpace(out)
	}, 2*time.Minute, 5*time.Second).Should(Equal(rsPod),
		"ReplicaSet pod must be reachable over its local-ni port mapping")

	rsRunner := kubectlExecRunner(device, nativeTestNamespace, rsPod, shortTimeout)
	rsDefaultRoute := mustRun(t, rsRunner, "ip route show default")
	t.Expect(rsDefaultRoute).To(ContainSubstring("dev localni"),
		"ReplicaSet pod (default-route requested on local-ni) must default-route via local-ni")

	// The k3s node's own InternalIP is whatever address kube-init picked for
	// node registration -- on this single-NIC device with both a DHCP
	// management address and a static cluster-interface address on
	// ethernet0, that is the cluster-interface one, not necessarily
	// deviceIP (the externally-reachable address used for the SSH/port-map
	// checks above). Queried directly rather than assumed.
	nodeIP := nodeInternalIP(t, device, devName, shortTimeout)
	eth0Routes := mustRun(t, rsRunner, "ip route show dev eth0")
	t.Expect(eth0Routes).To(ContainSubstring(kubeServiceCIDR),
		"eth0 must carry an explicit route to the Kubernetes service CIDR")
	t.Expect(eth0Routes).To(ContainSubstring(nodeIP),
		"eth0 must carry an explicit route to the node's own IP (%s)", nodeIP)

	rsSvcCode := mustRun(t, rsRunner, curlStatusCmd(kubeServiceClusterIP))
	t.Expect(rsSvcCode).ToNot(Equal("000"),
		"the Kubernetes service ClusterIP must still be reachable over eth0 despite "+
			"eth0 not being the default route, got curl status %q", rsSvcCode)

	// "http-server.test" only resolves via the Network Instance's own DNS
	// server (its gateway, here local-ni's 10.11.12.1) -- that is a separate
	// DNS universe from the pod's default /etc/resolv.conf, which points at
	// k3s's cluster-wide CoreDNS and has no path to EVE's per-NI DNS
	// infrastructure. So resolve explicitly against local-ni's gateway
	// first, then curl the resulting IP directly (with the original
	// hostname in the Host header, matching what curling the name directly
	// would have sent).
	helloworld := mustRun(t, rsRunner,
		`ip=$(dig +short @10.11.12.1 http-server.test) && `+
			`curl -sS --max-time 5 -H "Host: http-server.test" http://$ip/helloworld`)
	t.Expect(helloworld).To(ContainSubstring("Hello world!"),
		"outbound traffic to a host outside the explicit eth0 routes must follow the "+
			"default route (local-ni)")

	rsLocalNIAddr := mustRun(t, rsRunner, "ip -4 -o addr show dev localni")
	t.Expect(rsLocalNIAddr).To(ContainSubstring("inet "+replicaSetStaticIP+"/"),
		"the requested static IP must be assigned on local-ni")
	rsSwitchNIAddr := mustRun(t, rsRunner, "ip -4 -o addr show dev switchni")
	rsSwitchNIIP := firstIPInCIDR(t, rsSwitchNIAddr, "172.20.20.0/24")
	log.Infof("ReplicaSet pod switch-ni IP=%s", rsSwitchNIIP)

	// --- Phase 3: the identical image deployed through the EVE API ---
	//
	// NOHYPER so the app also gets the pod's own default network (eth0) --
	// a KubeVirt VM-mode app would not (see pkg/pillar/hypervisor/kubevirt.go).
	allowAll := []evetest.ACLAllowRule{
		{Protocol: evetest.NetworkProtocolAny, RemoteSubnet: evetest.IPSubnet("0.0.0.0/0")},
	}
	eveAppUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName:        eveAppName,
		Activate:           true,
		VirtualizationMode: eveconfig.VmMode_NOHYPER,
		Image: evetest.DockerContainer{
			ImageName: appImageName,
			Tag:       appImageTag,
		},
		CPUs:        1,
		MemoryBytes: 500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: localNIUUID,
				ACLAllowRules:       allowAll,
			},
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif1",
				NetworkInstanceUUID: switchNIUUID,
				ACLAllowRules:       allowAll,
			},
		},
	})
	device.ApplyConfig(devConfig, true, true)
	log.Infof("Submitted config with EVE-API app UUID=%v", eveAppUUID)
	evetest.Checkpoint("eve-app-config-is-submitted")

	timeoutExcludingDownload := 10 * time.Minute
	log.Infof("Waiting for the EVE-API app %s to report Running", eveAppName)
	device.WaitUntilAppIsRunning(eveAppUUID, timeoutExcludingDownload)
	evetest.Checkpoint("eve-app-is-deployed")

	evePod := discoverPod(t, device, "eve-kube-app", appImageName, shortTimeout)
	eveRunner := kubectlExecRunner(device, "eve-kube-app", evePod, shortTimeout)

	// --- Phase 4: cross-app connectivity and DNS, both directions ---
	rsEthIP := podIP(t, device, nativeTestNamespace, rsPod, shortTimeout)
	eveEthIP := podIP(t, device, "eve-kube-app", evePod, shortTimeout)
	log.Infof("ReplicaSet pod primary IP=%s, EVE app pod primary IP=%s", rsEthIP, eveEthIP)

	eveAddrs := mustRun(t, eveRunner, "ip -4 -o addr show")
	eveLocalNIIP := firstIPInCIDR(t, eveAddrs, "10.11.12.0/24")
	eveSwitchNIIP := firstIPInCIDR(t, eveAddrs, "172.20.20.0/24")
	log.Infof("EVE app pod: local-ni IP=%s, switch-ni IP=%s", eveLocalNIIP, eveSwitchNIIP)

	log.Infof("Testing pod-to-pod connectivity over the primary (eth0) network")
	t.Expect(mustRun(t, rsRunner, pingCmd(eveEthIP))).To(ContainSubstring(" 0% packet loss"))
	t.Expect(mustRun(t, eveRunner, pingCmd(rsEthIP))).To(ContainSubstring(" 0% packet loss"))

	log.Infof("Testing pod-to-pod connectivity over local-ni")
	t.Expect(mustRun(t, rsRunner, pingCmd(eveLocalNIIP))).To(ContainSubstring(" 0% packet loss"))
	t.Expect(mustRun(t, eveRunner, pingCmd(replicaSetStaticIP))).To(ContainSubstring(" 0% packet loss"))

	log.Infof("Testing pod-to-pod connectivity over switch-ni")
	t.Expect(mustRun(t, rsRunner, pingCmd(eveSwitchNIIP))).To(ContainSubstring(" 0% packet loss"))
	t.Expect(mustRun(t, eveRunner, pingCmd(rsSwitchNIIP))).To(ContainSubstring(" 0% packet loss"))

	// DNS records zedkube/kubeappdns.go derives: <app>.<namespace>.<ni>.internal.
	rsLocalNIFQDN := fmt.Sprintf("%s.%s.%s.internal",
		nativeReplicaSetName, nativeTestNamespace, localNIDisplayName)
	eveLocalNIFQDN := fmt.Sprintf("%s.eve-kube-app.%s.internal", eveAppName, localNIDisplayName)

	log.Infof("Testing DNS resolution: EVE app -> native ReplicaSet pod (%s)", rsLocalNIFQDN)
	t.Eventually(func() string {
		return mustRunTolerant(eveRunner, "getent hosts "+rsLocalNIFQDN)
	}, 2*time.Minute, 5*time.Second).Should(ContainSubstring(replicaSetStaticIP),
		"EVE app must resolve the native ReplicaSet's local-ni DNS record to its "+
			"requested static IP")

	log.Infof("Testing DNS resolution: native ReplicaSet pod -> EVE app (%s)", eveLocalNIFQDN)
	t.Eventually(func() string {
		return mustRunTolerant(rsRunner, "getent hosts "+eveLocalNIFQDN)
	}, 2*time.Minute, 5*time.Second).Should(ContainSubstring(eveLocalNIIP),
		"native ReplicaSet pod must resolve the EVE app's local-ni DNS record to its "+
			"local-ni IP")

	// --- Phase 5: scale 1 -> 0 -> 1, MAC must survive the recreate ---
	//
	// A bare ReplicaSet never changes name on scaling (unlike a Deployment
	// rollout, which would create a new ReplicaSet with a new
	// pod-template-hash) -- see pkg/pillar/cmd/zedkube/kubeappnetwork.go's
	// "Keep the immediate controller name as the network identity" comment.
	// The derived appUUID is hash(namespace+ownerName), so it is identical
	// before and after; the MAC (and, best-effort, the IP) must be too.
	localMACBefore := strings.TrimSpace(mustRun(t, rsRunner, "cat /sys/class/net/localni/address"))
	switchMACBefore := strings.TrimSpace(mustRun(t, rsRunner, "cat /sys/class/net/switchni/address"))
	log.Infof("Before scale-cycle: local-ni MAC=%s switch-ni MAC=%s",
		localMACBefore, switchMACBefore)

	scaleReplicaSet(t, device, nativeTestNamespace, nativeReplicaSetName, 0, shortTimeout)
	log.Infof("Waiting for the ReplicaSet's pod to be removed after scaling to 0")
	t.Eventually(func() int {
		return countPodsByLabel(device, nativeTestNamespace, replicaSetLabel, shortTimeout)
	}, 2*time.Minute, 5*time.Second).Should(Equal(0),
		"scaling to 0 must remove the ReplicaSet's pod")
	evetest.Checkpoint("replicaset-scaled-to-zero")

	scaleReplicaSet(t, device, nativeTestNamespace, nativeReplicaSetName, 1, shortTimeout)
	newRSPod := discoverPodByLabel(t, device, nativeTestNamespace, replicaSetLabel, podReadyTimeout)
	waitForPodReady(t, device, nativeTestNamespace, newRSPod, podReadyTimeout)
	evetest.Checkpoint("replicaset-scaled-back-to-one")

	newRSRunner := kubectlExecRunner(device, nativeTestNamespace, newRSPod, shortTimeout)
	localMACAfter := strings.TrimSpace(
		mustRun(t, newRSRunner, "cat /sys/class/net/localni/address"))
	switchMACAfter := strings.TrimSpace(
		mustRun(t, newRSRunner, "cat /sys/class/net/switchni/address"))
	log.Infof("After scale-cycle: local-ni MAC=%s switch-ni MAC=%s", localMACAfter, switchMACAfter)

	t.Expect(localMACAfter).To(Equal(localMACBefore),
		"local-ni MAC must be identical after a bare ReplicaSet scale-to-zero-and-back")
	t.Expect(switchMACAfter).To(Equal(switchMACBefore),
		"switch-ni MAC must be identical after a bare ReplicaSet scale-to-zero-and-back")

	// --- Cleanup: undeploy everything this test created ---
	//
	// ResetDeviceConfig (this test's own reuse policy, and the one every
	// following TestNodeClusterSuite member that might reuse this device
	// also uses) only clears EVE-managed app config; it has no visibility
	// into the native Pod and ReplicaSet, which were applied directly via
	// kubectl, so those are undeployed explicitly here -- otherwise they
	// would still be running when the next test reuses this device.
	_, _, _ = device.RunShellScript(
		fmt.Sprintf("eve exec kube kubectl delete pod %s -n %s --wait=false",
			nativeBarePodName, nativeTestNamespace),
		shortTimeout, 0)
	_, _, _ = device.RunShellScript(
		fmt.Sprintf("eve exec kube kubectl delete replicaset %s -n %s --wait=false",
			nativeReplicaSetName, nativeTestNamespace),
		shortTimeout, 0)
	devConfig.DeleteApplication(eveAppUUID)
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("apps-undeployed")
}

// firstIPv4 returns the first IPv4 address in ips, failing the test with a
// descriptive message (naming what ips was supposed to be) if there is none.
func firstIPv4(t *WithT, ips []net.IP, what string) net.IP {
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
	}
	t.Expect(false).To(BeTrue(), "no IPv4 address found for %s (addresses: %v)", what, ips)
	return nil
}

// firstIPInCIDR scans the output of `ip -4 -o addr show` (one "inet
// X.X.X.X/N ..." token per interface line) and returns the first address
// that falls inside cidr. Used to find a pod's address on a given Network
// Instance without needing to know which interface name Multus assigned it
// (only this test's own native workloads request explicit interface names;
// an EVE-API app's adapters get Multus's default net1/net2 naming).
func firstIPInCIDR(t *WithT, ipAddrOutput, cidr string) string {
	_, ipNet, err := net.ParseCIDR(cidr)
	t.Expect(err).ToNot(HaveOccurred(), "parse CIDR %q", cidr)
	for _, field := range strings.Fields(ipAddrOutput) {
		if !strings.HasPrefix(field, "inet") && !strings.Contains(field, ".") {
			continue
		}
		ipStr, _, found := strings.Cut(field, "/")
		if !found {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip != nil && ipNet.Contains(ip) {
			return ipStr
		}
	}
	t.Expect(false).To(BeTrue(),
		"no IPv4 address found within %s, `ip -4 -o addr show` output was: %s",
		cidr, ipAddrOutput)
	return ""
}

// curlStatusCmd returns a shell command that reports only the HTTP status
// code curl got from ip (or "000" if none), tolerant of a self-signed/absent
// TLS certificate -- used to confirm reachability, not content.
func curlStatusCmd(ip string) string {
	return fmt.Sprintf(
		"curl -sk -o /dev/null -m 5 -w '%%{http_code}' https://%s/", ip)
}

// pingCmd returns a shell command for a single, short-timeout ping, used to
// confirm reachability over a specific interface (the destination IP alone
// determines the route taken).
func pingCmd(ip string) string {
	return fmt.Sprintf("ping -c 1 -W 2 %s", ip)
}

// mustRun runs script inside a pod via runner (see kubectlExecRunner) and
// fails the test immediately on error.
func mustRun(t *WithT, runner func(string) (string, string, error), script string) string {
	out, _, err := runner(script)
	t.Expect(err).ToNot(HaveOccurred(), "exec %q", script)
	return out
}

// mustRunTolerant is mustRun for callers that retry inside Eventually and
// need a transient failure (e.g. DNS not yet propagated) to read as a
// non-matching value rather than aborting the test.
func mustRunTolerant(runner func(string) (string, string, error), script string) string {
	out, _, err := runner(script)
	if err != nil {
		return ""
	}
	return out
}

// waitForPodReady blocks until pod in namespace reports Ready.
func waitForPodReady(t *WithT, device *evetest.EdgeDevice, namespace, pod string,
	timeout time.Duration) {

	evetest.Logger().Infof("Waiting (up to %s) for pod %s/%s to become Ready",
		timeout, namespace, pod)
	script := fmt.Sprintf(
		"eve exec kube kubectl wait --for=condition=Ready pod/%s -n %s --timeout=%ds",
		pod, namespace, int(timeout.Seconds()))
	_, _, err := device.RunShellScript(script, timeout+30*time.Second, 0)
	t.Expect(err).ToNot(HaveOccurred(), "wait for pod %s/%s to become Ready", namespace, pod)
}

// discoverPodByLabel finds the one pod in namespace matching label
// ("key=value") and returns its name, retrying until the scheduler has
// placed it (a bare apply can race ahead of pod creation).
func discoverPodByLabel(t *WithT, device *evetest.EdgeDevice, namespace, label string,
	timeout time.Duration) (podName string) {

	evetest.Logger().Infof("Waiting (up to %s) for a pod matching label %q in namespace %s "+
		"to be scheduled", timeout, label, namespace)
	script := fmt.Sprintf(
		"eve exec kube kubectl get pods -n %s -l %s -o jsonpath='{.items[0].metadata.name}'",
		namespace, label)
	deadline := time.Now().Add(timeout)
	for {
		out, _, err := device.RunShellScript(script, 30*time.Second, 0)
		name := strings.TrimSpace(out)
		if err == nil && name != "" {
			return name
		}
		if time.Now().After(deadline) {
			t.Expect(err).ToNot(HaveOccurred(),
				"discover pod matching label %q in namespace %s (last output: %q)",
				label, namespace, out)
			t.Expect(name).ToNot(BeEmpty(),
				"discover pod matching label %q in namespace %s: none found", label, namespace)
		}
		time.Sleep(3 * time.Second)
	}
}

// countPodsByLabel returns the number of pods in namespace matching label,
// or -1 on error (so a caller polling inside Eventually never confuses a
// transient kubectl failure with "0 pods").
func countPodsByLabel(device *evetest.EdgeDevice, namespace, label string,
	timeout time.Duration) int {

	script := fmt.Sprintf(
		"eve exec kube kubectl get pods -n %s -l %s --no-headers 2>/dev/null | "+
			"grep -c . || true", namespace, label)
	out, _, err := device.RunShellScript(script, timeout, 0)
	if err != nil {
		return -1
	}
	out = strings.TrimSpace(out)
	count := 0
	if out != "" {
		if _, err := fmt.Sscanf(out, "%d", &count); err != nil {
			return -1
		}
	}
	return count
}

// scaleReplicaSet sets spec.replicas on name in namespace.
func scaleReplicaSet(t *WithT, device *evetest.EdgeDevice, namespace, name string,
	replicas int, timeout time.Duration) {

	evetest.Logger().Infof("Scaling ReplicaSet %s/%s to %d replica(s)", namespace, name, replicas)
	script := fmt.Sprintf("eve exec kube kubectl scale replicaset %s -n %s --replicas=%d",
		name, namespace, replicas)
	_, _, err := device.RunShellScript(script, timeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "scale ReplicaSet %s/%s to %d", namespace, name, replicas)
}

// podIP returns a pod's primary (pod-network) IP address.
func podIP(t *WithT, device *evetest.EdgeDevice, namespace, pod string,
	timeout time.Duration) string {

	script := fmt.Sprintf(
		"eve exec kube kubectl get pod %s -n %s -o jsonpath='{.status.podIP}'", pod, namespace)
	out, _, err := device.RunShellScript(script, timeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "read pod IP for %s/%s", namespace, pod)
	ip := strings.TrimSpace(out)
	t.Expect(ip).ToNot(BeEmpty(), "pod %s/%s has no reported pod IP", namespace, pod)
	return ip
}

// nodeInternalIP returns the k3s Node object's reported InternalIP (the k3s
// node name equals the EVE device name).
func nodeInternalIP(t *WithT, device *evetest.EdgeDevice, nodeName string,
	timeout time.Duration) string {

	script := fmt.Sprintf(
		`eve exec kube kubectl get node %s -o `+
			`jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'`, nodeName)
	out, _, err := device.RunShellScript(script, timeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "read node %s InternalIP", nodeName)
	ip := strings.TrimSpace(out)
	t.Expect(ip).ToNot(BeEmpty(), "node %s has no reported InternalIP", nodeName)
	return ip
}

// sshRun opens a plain SSH connection (no tunnel -- the evetest harness
// process has direct network reachability to the SDN, the same precondition
// EdgeDevice.RunShellScriptInsideApp relies on) to addr and runs script,
// authenticating as appSSHUser/appSSHPass (the credentials baked into
// every image this test uses). Used instead of
// EdgeDevice.RunShellScriptInsideApp because that method resolves its
// target address from an EVE AppInstanceConfig, which a directly-deployed
// (non-EVE-managed) workload does not have.
func sshRun(addr, script string, timeout time.Duration) (stdout string, err error) {
	config := &ssh.ClientConfig{
		User:            appSSHUser,
		Auth:            []ssh.AuthMethod{ssh.Password(appSSHPass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return "", fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	defer func() { _ = client.Close() }()
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh new session to %s: %w", addr, err)
	}
	defer func() { _ = session.Close() }()
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	if err := session.Run(script); err != nil {
		return stdoutBuf.String(), fmt.Errorf("ssh run %q on %s: %w", script, addr, err)
	}
	return stdoutBuf.String(), nil
}
