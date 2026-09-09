// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"encoding/json"
	"fmt"
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
)

// numNodesParamKey and numNodesParam let the test form a cluster of any
// size instead of always a single node. mgmtproxy's cni0 proxy-auth
// token/TLS cert are generated differently depending on this: standalone
// (no cluster at all), they're randomly generated per node the first time
// mgmtproxy runs; clustered, they're deterministically derived from the
// cluster's shared k3s join token instead, since PatchCDIProxyConfig
// patches a single cluster-wide CDI CR that every node's importer pods
// read from (see the "Clustered nodes" section of
// pkg/pillar/cmd/mgmtproxy/README.md). NUM_NODES lets this test exercise
// both code paths: with NUM_NODES==1 the device gets a bare
// EdgeDeviceConfig with no Cluster field at all (exactly like
// TestSingleNodeCluster), the standalone/random case; with NUM_NODES>1 a
// real EdgeClusterConfig is built, the clustered/deterministic case. A
// single-node EdgeClusterConfig would NOT exercise the standalone case --
// zedagent would still confirm it as a *clustered* (Valid) config, which is
// exactly what NUM_NODES==1 must avoid. Its default of 3 is also
// deliberately shaped to match TestThreeNodesCluster's device requirements
// and network model, so evetest reuses its already-provisioned devices
// instead of creating new ones -- a secondary benefit, not the reason this
// parameter exists.
const numNodesParamKey = "NUM_NODES"

var numNodesParam = evetest.TestParameterDefinition{
	Key:          numNodesParamKey,
	DefaultValue: 3,
	Description: evetest.TestParameterDescription{
		Summary: "Number of edge nodes to form the cluster from",
		Default: "3",
	},
}

// TestMgmtProxy verifies mgmtproxy (pkg/pillar/cmd/mgmtproxy): both its
// ordinary job (cost-aware CONNECT proxying for kube containerd's and CDI's
// image pulls, independent of the host's table-main default route) and its
// cni0 (pod-facing) guardrail -- without it, any pod on the node could use
// the cni0 listener as an open egress proxy laundering traffic through the
// node's management source IP.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort(devNames...) called with one device name
//     per cluster node. It gives each device two ports: "<devName>-eth0"
//     (DHCP, controller + Internet reachable) and "<devName>-eth1" (intended
//     for cluster network, static, 10.244.244.0/24, NO Internet or
//     controller reachability).
//
// Device configuration -- the deliberate table-main poisoning
// -------------------------------------------------------------
//   - ethernet0 (eth0): PhyIoUsageMgmtAndApps, Cost=1, shared across all
//     nodes.
//   - ethernet1 (eth1): PhyIoUsageMgmtAndApps, Cost=0 -- always the poisoned
//     port, but its Gateway/subnet differ by NUM_NODES (see poisonGateway):
//   - NUM_NODES==1: a bare EdgeDeviceConfig with no Cluster field at all,
//     same as TestSingleNodeCluster. ethernet1 gets a single static IP
//     (10.244.244.2) and gateway (10.244.244.1) on 10.244.244.0/24, with
//     nothing else contending for that interface.
//   - NUM_NODES>1: ethernet1 also doubles as the cluster interface
//     (ClusterNode.ClusterInterface), and kube-init assigns each node's
//     ClusterNode.ClusterIP (10.244.244.x) onto it directly, independent
//     of EVE's own network config. NIM still needs an address of its own
//     on ethernet1 for a Gateway route to be valid (a static port with no
//     address at all is rejected as invalid config), so it gets one from
//     an entirely different subnet, 10.244.245.0/24, gateway 10.244.245.1
//     -- separate from the cluster's own 10.244.244.0/24 by construction,
//     rather than merely a different address within it.
//
// Both ports are mgmt-capable, but ethernet1 -- the LOWER-cost one -- has no
// real Internet route. EVE assigns route metrics by ascending
// Cost (rebuildRouteMetricMap), so the kernel's table-main default route
// ends up via ethernet1's (non-functional) gateway: exactly the
// "table main still points at the dead/wrong gateway" scenario
// pkg/pillar/cmd/mgmtproxy/README.md describes as mgmtproxy's reason for
// existing. mgmtproxy's own dialer is unaffected -- it iterates mgmt ports
// by ascending cost with fallback on failure, so it tries ethernet1 first,
// fails, and succeeds via ethernet0 -- proving its independence from
// table-main. This holds regardless of NUM_NODES; the table-main-poisoning
// check itself is made against the first node (devices[0]) only, but the
// /healthz assertions that follow are summed across every node (see
// sumMgmtProxyHealthz) since not every step's pod is pinned to a specific
// one.
//
// Three steps, three different things exercised
// ----------------------------------------------
//  1. A plain, unprivileged pod applied directly to k3s (`kubectl apply`),
//     bypassing EVE's app-instance pipeline entirely, using testAppImageName
//     directly -- a genuinely public image never pulled onto this device
//     before, so kube containerd must actually fetch it live, through
//     mgmtproxy's loopback listener, cleanly independent of pillar's own
//     downloader (which is what stages the image for step 3 instead).
//     There is no way today to attach such a pod to an EVE network
//     instance, so it lands on the plain cni0 pod network with an
//     ordinary, unprivileged default route already in place -- no extra
//     route needs to be added and no elevated privilege is required to
//     reach the cni0 listener, so this is checked against the guardrail
//     too: the strictly-worse case the guardrail exists for.
//  2. A standalone CDI DataVolume, also applied directly (no VM needs to
//     actually exist for CDI to create an importer pod and attempt the
//     fetch). Its source.http.url points at a real Alpine cloud image
//     re-served by evetest's own embedded HTTPS image server (the same
//     server + pinned image metadata tests/cluster/vmapp_test.go uses),
//     trusted via a certConfigMap built from the harness's own CA
//     (evetest.GetCACertPEM). This is CDI's importer pod -- a plain
//     container CDI's own operator creates -- fetching an external image
//     via the *legitimate* cni0 consumer mgmtproxy exists to serve,
//     proxied through the CDI CR's importProxy config
//     (pkg/kube/kube-init/mgmtproxy/cni0.go:PatchCDIProxyConfig).
//  3. The identical image, deployed through the EVE API as a native
//     (NOHYPER) container. A kubevirt-VM-mode app gets no interface
//     bridged onto cni0 in the guest at all -- domainmgr only wires up
//     the app's own NI-attached interfaces, never the pod's default
//     network -- so NOHYPER is used here so the app has any path to cni0
//     in the first place. EVE-K unconditionally deploys NOHYPER container
//     apps with securityContext.privileged=true
//     (pkg/pillar/hypervisor/kubevirt.go), which is what makes the one
//     extra `ip route add 169.254.100.1/32` possible and the proxy
//     potentially exploitable from inside the app. Because the app is
//     privileged, this guardrail carries an asterisk: a genuinely
//     malicious privileged app already has much more direct
//     host-compromise avenues (raw block device access, capability set)
//     than this proxy ever exposed -- mgmtproxy's fix is still real
//     defense-in-depth against the easy, low-skill path, not a hard
//     boundary against a fully malicious privileged workload. This app's
//     own image is always ImagePullPolicy:Never/pre-staged by pillar's
//     own downloader before the pod spec is even created, so no new pull
//     through mgmtproxy is expected from this step -- unlike steps 1 and
//     2, this one is purely a guardrail check.
//
// Phases
// ------
//  1. setup-done -> initial-config-applied: apply the initial configuration
//     (mgmt+cluster ports, no app yet) -- a bare EdgeDeviceConfig with
//     NUM_NODES==1, otherwise an EdgeClusterConfig applied to every node.
//  2. cluster-is-ready: device.WaitForClusterNodeIsReady (NUM_NODES==1) or
//     EdgeCluster.WaitUntilNodesAreReady (NUM_NODES>1); confirm the
//     table-main-poisoning (default route via ethernet1's gateway) on the
//     first node, then capture the first /healthz snapshot, summed across
//     every node (mgmtproxy already active from system-component image
//     pulls during cluster bring-up).
//  3. step1-is-deployed: the raw container pod is Running; /healthz
//     requests and eth0 successes must have increased (a real containerd
//     pull just happened); confirm the cni0 guardrail from inside it.
//  4. step2-is-deployed: the DataVolume reports Succeeded; /healthz
//     requests and eth0 successes must have increased again (CDI's
//     importer just fetched the image through mgmtproxy).
//  5. step3-is-deployed: the EVE-API app is running; /healthz counters must
//     not have decreased (no new pull expected); confirm the cni0
//     guardrail from inside it too.
//
// Test parameters
// ---------------
//   - TPM (bool) and Filesystem, both standard cluster-test parameters.
//   - NUM_NODES (int, default 3): number of edge nodes forming the cluster.
//     See numNodesParam's own doc comment for why this exists (exercising
//     mgmtproxy's standalone vs. clustered secret-derivation code paths).
//     The table-main-poisoning check runs against the first node only;
//     /healthz assertions are summed across every node, since only step 1's
//     pod (and, best-effort, step 3's app) are pinned to the first node --
//     step 2's CDI importer pod is not (see its own comment).
//
// Suite placement
// ---------------
//   - TestNodeClusterSuite (Kubevirt-only, like the other cluster tests),
//     after TestThreeNodesCluster: with the default NUM_NODES=3 its device
//     requirements and network model exactly match TestThreeNodesCluster's,
//     so evetest reuses the same already-provisioned devices instead of
//     creating new ones.
func TestMgmtProxy(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()
	log := evetest.Logger()

	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
		numNodesParam,
	)
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()
	numNodes := evetest.GetTestParameter[int](numNodesParamKey)
	t.Expect(numNodes).To(BeNumerically(">=", 1), "NUM_NODES must be at least 1")

	devNames := make([]string, numNodes)
	requirements := make([]evetest.Requirement, 0, numNodes+1)
	for i := 0; i < numNodes; i++ {
		devNames[i] = fmt.Sprintf("edge-dev%d", i+1)
		requirements = append(requirements,
			clusterDeviceRequirements(devNames[i], withTPM, filesystem, false))
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SeparateClusterPort(devNames...),
	}
	requirements = append(requirements, requiredNetModel)
	evetest.Setup(requirements...)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial configuration: mgmt-and-app-network on
	// eth0 (Cost=1, real Internet) and cluster-network on eth1 (Cost=0, no
	// Internet) -- both mgmt-capable, so the lower-cost (eth1) port wins
	// table-main's default route despite having nowhere useful to send
	// traffic. With NUM_NODES==1 this is a bare EdgeDeviceConfig with no
	// Cluster field at all -- see numNodesParam's doc comment for why that
	// matters. With NUM_NODES>1 a real EdgeClusterConfig is built instead,
	// with one static IP per node on ethernet1 (which also doubles as the
	// cluster interface).
	//
	// devConfig/clusterConfig and device/cluster are mutually exclusive:
	// exactly one pair is set below, matching NUM_NODES==1 vs NUM_NODES>1.
	// Both are kept in scope for step 3's app deployment further down.
	var (
		devConfig     *evetest.EdgeDeviceConfig
		clusterConfig *evetest.EdgeClusterConfig
		cluster       *evetest.EdgeCluster
	)
	configProps := types.NewConfigItemValueMap()
	// network.download.max.cost defaults to 0, which would exclude
	// ethernet0 (Cost=1) from mgmtproxy's dial candidates entirely --
	// leaving only ethernet1 (deliberately broken), so nothing could ever
	// be pulled at all. Raise it to ethernet0's cost so mgmtproxy can
	// actually fall back to it.
	configProps.SetGlobalValueInt(types.DownloadMaxPortCost, 1)
	mgmtAndApps := evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps

	devices := make([]*evetest.EdgeDevice, numNodes)
	timeout := 20 * time.Minute
	// poisonGateway is the Gateway the table-main check below expects to
	// see, which differs by branch: with NUM_NODES==1 it's on the same
	// subnet as ethernet1's only address; with NUM_NODES>1 it's on the
	// separate subnet reserved for NIM's own address (see the comment on
	// poisonNet below).
	var poisonGateway string
	if numNodes == 1 {
		devConfig = evetest.NewEdgeDeviceConfig(devNames[0])
		mgmtNet := devConfig.AddNetwork(
			evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
		devConfig.AddNetworkAdapter(
			evetest.NetworkAdapterConfig{
				LogicalLabel:  "ethernet0",
				PhysicalLabel: "eth0",
				InterfaceName: "eth0",
				NetworkUUID:   mgmtNet,
				Usage:         mgmtAndApps,
				Cost:          1,
			})
		clusterNet := devConfig.AddNetwork(
			evetest.StaticNetworkConfig{
				NetworkType: evecommon.NetworkType_V4Only,
				Subnet:      evetest.IPSubnet("10.244.244.0/24"),
				Gateway:     evetest.IPAddress("10.244.244.1"),
			})
		devConfig.AddNetworkAdapter(
			evetest.NetworkAdapterConfig{
				LogicalLabel:  "ethernet1",
				PhysicalLabel: "eth1",
				InterfaceName: "eth1",
				NetworkUUID:   clusterNet,
				Usage:         mgmtAndApps,
				Cost:          0,
				StaticIP:      evetest.IPAddress("10.244.244.2"),
			})
		devConfig.SetConfigProperties(configProps)
		poisonGateway = "10.244.244.1"

		device := evetest.GetEdgeDevice(devNames[0])
		device.ApplyConfig(devConfig, true, true)
		evetest.Checkpoint("initial-config-applied")
		device.WaitForClusterNodeIsReady(timeout)
		devices[0] = device
	} else {
		nodes := make([]evetest.ClusterNode, numNodes)
		for i := range nodes {
			clusterIP := evetest.IPAddressWithPrefix(
				fmt.Sprintf("10.244.244.%d/24", i+2))
			nodes[i] = evetest.ClusterNode{
				DevName:          devNames[i],
				ClusterIP:        clusterIP,
				ClusterInterface: "ethernet1",
				BootstrapNode:    i == 0,
			}
		}
		clusterConfig = evetest.NewEdgeClusterConfig(
			eveconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE, nodes...)

		mgmtNet := clusterConfig.AddNetwork(
			evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
		clusterConfig.AddNetworkAdapter(
			evetest.NetworkAdapterConfig{
				LogicalLabel:  "ethernet0",
				PhysicalLabel: "eth0",
				InterfaceName: "eth0",
				NetworkUUID:   mgmtNet,
				Usage:         mgmtAndApps,
				Cost:          1,
			})
		// ethernet1 is the cluster interface: kube-init assigns each node's
		// ClusterNode.ClusterIP (10.244.244.x, below) onto it directly,
		// independent of EVE's own network config. NIM still needs an address
		// of its own on ethernet1 for the poisoned Gateway route below to be
		// valid -- a static port with no address at all is rejected as
		// invalid config (parseSystemAdapterConfig) -- so give it one from an
		// entirely different subnet, guaranteeing it can never collide with
		// whatever ClusterIP kube-init assigns (a same-subnet offset address
		// would also work, but a separate subnet rules out collisions by
		// construction rather than by choosing numbers carefully).
		poisonNet := clusterConfig.AddNetwork(
			evetest.StaticNetworkConfig{
				NetworkType: evecommon.NetworkType_V4Only,
				Subnet:      evetest.IPSubnet("10.244.245.0/24"),
				Gateway:     evetest.IPAddress("10.244.245.1"),
			})
		// Unlike ethernet0, this can't be added via
		// EdgeClusterConfig.AddNetworkAdapter (which applies one identical
		// config to every device) since each node needs its own IP.
		for i := range nodes {
			nimIP := evetest.IPAddress(fmt.Sprintf("10.244.245.%d", i+2))
			clusterConfig.GetDeviceConfig(devNames[i]).AddNetworkAdapter(
				evetest.NetworkAdapterConfig{
					LogicalLabel:  "ethernet1",
					PhysicalLabel: "eth1",
					InterfaceName: "eth1",
					NetworkUUID:   poisonNet,
					Usage:         mgmtAndApps,
					Cost:          0,
					StaticIP:      nimIP,
				})
		}
		clusterConfig.SetConfigProperties(configProps)
		poisonGateway = "10.244.245.1"

		cluster = evetest.NewEdgeCluster("mgmtproxy-test-cluster")
		cluster.ApplyConfig(clusterConfig, true, true)
		evetest.Checkpoint("initial-config-applied")
		cluster.WaitUntilNodesAreReady(timeout)
		for i, name := range devNames {
			devices[i] = evetest.GetEdgeDevice(name)
		}
	}
	// The route check, manifest submission, and cleanup below only need one
	// device to talk to the (cluster-wide, when NUM_NODES>1) k3s API server
	// through; the first node is as good as any.
	device := devices[0]

	// Confirm the table-main poisoning actually took effect before relying
	// on it for the rest of the test. `ip route show default` lists every
	// default-route candidate (both ethernet0's and ethernet1's coexist,
	// distinguished only by metric), so it can't tell us which one the
	// kernel actually picks; `ip route get` resolves a real destination and
	// reports only the route actually selected for it.
	shortTimeout := 30 * time.Second
	defaultRoute, _, err := device.RunShellScript("ip route get 1.1.1.1", shortTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "read the route actually used for outbound traffic")
	t.Expect(defaultRoute).To(ContainSubstring(poisonGateway),
		"outbound traffic must be routed via ethernet1's gateway (%s), "+
			"got: %s", poisonGateway, defaultRoute)
	t.Expect(defaultRoute).ToNot(ContainSubstring("172.20.20.1"),
		"outbound traffic must NOT be routed via ethernet0's gateway, got: %s", defaultRoute)
	log.Infof("Confirmed table-main is poisoned: outbound traffic resolves via "+
		"ethernet1: %s", strings.TrimSpace(defaultRoute))

	// Baseline /healthz, summed across every node: mgmtproxy should already
	// be alive on each one and have served real traffic from
	// system-component image pulls during cluster bring-up (coredns,
	// kube-multus, virt-*, cdi-*, longhorn-*, ...) -- none of that is
	// app-specific, it's an inherent part of any fresh eve-k cluster
	// forming. Summed (rather than read from a single node) because steps 1
	// and 3's pods, and step 2's CDI importer pod, are not all pinned to a
	// specific node (see their own comments below) -- the k8s scheduler is
	// free to place them on any node when NUM_NODES > 1, so only a
	// cluster-wide total is guaranteed to reflect a given step's traffic.
	// cni0Listening depends on kube-init's own steady-state tick assigning
	// the cni0 anchor IP (SetupCNI0ProxyIP), which only runs once kube-init
	// reaches its RUNNING state -- it does not run during StateDeploying,
	// while KubeVirt/CDI/Longhorn are still installing. WaitUntilNodesAreReady
	// only waits for each k3s node's Ready condition plus storage (Longhorn)
	// health, a narrower condition that can be satisfied while KubeVirt
	// (observed as the slowest of the three to report its CR Deployed) is
	// still deploying, so the test can resume before kube-init has finished
	// the full sequence and reached RUNNING on every node. Poll generously
	// rather than asserting immediately.
	log.Infof("Waiting for mgmtproxy to become ready with cni0 listening "+
		"and having served requests on all %d node(s)", numNodes)
	var baseline types.MgmtProxyHealthz
	t.Eventually(func() bool {
		sum, ok := sumMgmtProxyHealthz(devices, shortTimeout)
		if !ok || !sum.Ready || !sum.CNI0Listening || sum.Requests == 0 {
			return false
		}
		baseline = sum
		return true
	}, 5*time.Minute, 5*time.Second).Should(BeTrue(),
		"every node's mgmtproxy should become ready with cni0 listening and "+
			"having served requests")
	t.Expect(baseline.SuccessByPort).To(HaveKeyWithValue("eth0", BeNumerically(">", 0)),
		"successful traffic must have gone out via eth0 (the only port with real "+
			"Internet), despite eth1 being cost-preferred")
	log.Infof("Baseline /healthz (summed): requests=%d successByPort=%v failureByPort=%v",
		baseline.Requests, baseline.SuccessByPort, baseline.FailureByPort)
	evetest.Checkpoint("cluster-is-ready")

	// mgmtProxyTestNamespace is where the raw (non-EVE-managed) resources in
	// this test are created, kept separate from EVE's own eve-kube-app
	// namespace so they're never mistaken for EVE-reconciled resources.
	const mgmtProxyTestNamespace = "default"

	const (
		testAppImageName = "milan4zededa/evetest-ubuntu-ctr"
		testAppImageTag  = "1.2"
	)

	// --- Step 1: raw, unprivileged container pod, genuinely uncached image ---
	//
	// testAppImageName has never been pulled onto this device before, so
	// containerd must fetch it live -- through mgmtproxy's loopback
	// listener -- independent of pillar's own downloader (which is what
	// stages step 3's image instead, without ever touching mgmtproxy). Pinned
	// via nodeName to the first node (the k3s node name is the EVE device
	// name, see edgecluster.go's own use of dev.devName as the node name) so
	// the pull is guaranteed to hit the same node the /healthz assertions
	// read from, regardless of NUM_NODES.
	const step1Pod = "mgmtproxy-test-container"
	step1Manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  nodeName: %s
  containers:
  - name: %s
    image: %s:%s
`, step1Pod, mgmtProxyTestNamespace, devNames[0], step1Pod, testAppImageName, testAppImageTag)
	applyManifest(t, device, step1Manifest, shortTimeout)

	waitScript := fmt.Sprintf(
		"eve exec kube kubectl wait --for=condition=Ready pod/%s -n %s --timeout=180s",
		step1Pod, mgmtProxyTestNamespace)
	log.Infof("Waiting for the raw container pod %s/%s to become Ready",
		mgmtProxyTestNamespace, step1Pod)
	_, _, err = device.RunShellScript(waitScript, 3*time.Minute, 0)
	t.Expect(err).ToNot(HaveOccurred(), "wait for the raw container pod to become Ready")
	log.Infof("Raw container pod %s/%s is Ready", mgmtProxyTestNamespace, step1Pod)
	evetest.Checkpoint("step1-is-deployed")

	afterStep1 := mustSumMgmtProxyHealthz(t, devices, shortTimeout)
	t.Expect(afterStep1.Requests).To(BeNumerically(">", baseline.Requests),
		"mgmtproxy should have served the raw container pod's image pull")
	t.Expect(afterStep1.SuccessByPort["eth0"]).To(
		BeNumerically(">", baseline.SuccessByPort["eth0"]),
		"the container pull must have gone out via eth0")
	log.Infof("After step 1, /healthz (summed): requests=%d (baseline was %d)",
		afterStep1.Requests, baseline.Requests)

	step1Runner := kubectlExecRunner(device, mgmtProxyTestNamespace, step1Pod, shortTimeout)
	checkMgmtProxyGuardrail(t, step1Runner,
		"step 1 (kubectl apply, unprivileged, default route only)")

	// --- Step 2: standalone CDI DataVolume, importer pod fetches an image ---
	//
	// No VM needs to actually exist for CDI to create an importer pod and
	// attempt the fetch -- a DataVolume object alone is enough. The image
	// is the same pinned Alpine cloud image tests/cluster/vmapp_test.go
	// uses, re-served by evetest's own embedded HTTPS image server and
	// trusted via a certConfigMap built from the harness's own CA, so the
	// fetch needs no real Internet reachability of its own -- just
	// mgmtproxy routing it correctly despite table-main being poisoned.
	// Unlike step 1's plain Pod, CDI's importer pod isn't pinned to the
	// first node -- there's no well-known, low-risk equivalent of nodeName
	// for a DataVolume -- so with NUM_NODES > 1 the scheduler is free to
	// place it on any node; the assertions below rely on every node's
	// mgmtproxy behaving identically (the whole point of deriving its
	// secrets cluster-wide), not on this one landing on devices[0].
	image := vmAppAlpineImages["amd64"]
	imgName := evetest.FetchAndServeImageFile(
		"https://dl-cdn.alpinelinux.org"+image.relativePath,
		"mgmtproxy-test-alpine.qcow2", image.sha256)
	caCertPEM := evetest.GetCACertPEM()

	const cdiCAConfigMap = "mgmtproxy-test-ca"
	const cdiDataVolume = "mgmtproxy-test-dv"
	step2Manifest := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: %s
  namespace: %s
data:
  cacert: |
%s
---
apiVersion: cdi.kubevirt.io/v1beta1
kind: DataVolume
metadata:
  name: %s
  namespace: %s
spec:
  source:
    http:
      url: "https://%s/%s"
      certConfigMap: %s
  pvc:
    # The cluster has two default StorageClasses: "longhorn" (Immediate
    # binding) and "local-path" (WaitForFirstConsumer). Left unset, the PVC
    # lands on whichever one the apiserver's admission controller picks --
    # if that's local-path, the PVC never binds and CDI's importer never
    # even starts, since nothing ever consumes it (a standalone DataVolume,
    # unlike a VM's PVC, has no such consumer). Pin explicitly.
    storageClassName: longhorn
    accessModes:
      - ReadWriteOnce
    resources:
      requests:
        storage: 300Mi
`, cdiCAConfigMap, mgmtProxyTestNamespace, indentBlock(string(caCertPEM), "    "),
		cdiDataVolume, mgmtProxyTestNamespace,
		evetest.GetImageServerIPv4(), imgName, cdiCAConfigMap)
	applyManifest(t, device, step2Manifest, shortTimeout)

	dvWaitScript := fmt.Sprintf(
		"eve exec kube kubectl wait --for=jsonpath='{.status.phase}'=Succeeded "+
			"datavolume/%s -n %s --timeout=300s", cdiDataVolume, mgmtProxyTestNamespace)
	log.Infof("Waiting for DataVolume %s/%s to report Succeeded",
		mgmtProxyTestNamespace, cdiDataVolume)
	_, _, err = device.RunShellScript(dvWaitScript, 6*time.Minute, 0)
	t.Expect(err).ToNot(HaveOccurred(), "wait for the DataVolume import to succeed")
	log.Infof("DataVolume %s/%s import Succeeded", mgmtProxyTestNamespace, cdiDataVolume)
	evetest.Checkpoint("step2-is-deployed")

	afterStep2 := mustSumMgmtProxyHealthz(t, devices, shortTimeout)
	t.Expect(afterStep2.Requests).To(BeNumerically(">", afterStep1.Requests),
		"mgmtproxy should have served CDI importer's image fetch")
	t.Expect(afterStep2.SuccessByPort["eth0"]).To(
		BeNumerically(">", afterStep1.SuccessByPort["eth0"]),
		"CDI's importer fetch must have gone out via eth0")
	log.Infof("After step 2, /healthz (summed): requests=%d (was %d after step 1)",
		afterStep2.Requests, afterStep1.Requests)

	// --- Step 3: EVE-API path, NOHYPER container ---
	//
	// The container app's own network instance is air-gapped (no uplink
	// Port at all), so its only possible path to anything outside its own
	// subnet is the host's cni0 mgmtproxy listener, if any. With
	// NUM_NODES>1 it's pinned to the first node via DesignatedNodeName
	// (PREFERRED, not REQUIRED, matching TestThreeNodesCluster's own use of
	// this mechanism) purely so a human reading a failure knows which
	// device to inspect -- not a correctness requirement, since the
	// /healthz assertions below are summed across every node and the
	// guardrail check runs through kubectl exec, which reaches whichever
	// node actually hosts the pod.
	niConfig := evetest.LocalNetworkInstanceConfig{
		DisplayName: "air-gap-ni",
		// No Port: an air-gapped NI, bridged to no physical interface at
		// all. The app has no network path out except through the host's
		// cni0 mgmtproxy listener, if any.
		Subnet: evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:       evetest.IPAddress("10.11.12.1"),
		EnableFlowlog: false,
		MTU:           1500,
		ForwardLLDP:   false,
	}
	appConfig := evetest.ApplicationInstanceConfig{
		DisplayName:        "mgmtproxy-test-app",
		Activate:           true,
		VirtualizationMode: eveconfig.VmMode_NOHYPER,
		Image: evetest.DockerContainer{
			ImageName: testAppImageName,
			Tag:       testAppImageTag,
		},
		CPUs:        1,
		MemoryBytes: 500 * evetest.MiB,
	}
	if numNodes == 1 {
		niUUID := devConfig.AddNetworkInstance(niConfig)
		appConfig.NetworkAdapters = []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
			},
		}
		step3UUID := devConfig.AddApplication(appConfig)
		device.ApplyConfig(devConfig, true, true)
		log.Infof("Submitted config with step 3 (EVE API) UUID=%v", step3UUID)
		evetest.Checkpoint("step3-config-is-submitted")
		device.WaitUntilAppIsRunning(step3UUID, 10*time.Minute)
	} else {
		niUUID := clusterConfig.AddNetworkInstance(niConfig)
		appConfig.NetworkAdapters = []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
			},
		}
		step3UUID := clusterConfig.AddApplication(evetest.ClusterApplicationInstanceConfig{
			ApplicationInstanceConfig: appConfig,
			DesignatedNodeName:        devNames[0],
			Affinity:                  eveconfig.AffinityType_AFFINITY_TYPE_PREFERRED,
		})
		cluster.ApplyConfig(clusterConfig, true, true)
		log.Infof("Submitted config with step 3 (EVE API) UUID=%v", step3UUID)
		evetest.Checkpoint("step3-config-is-submitted")
		cluster.WaitUntilAppIsRunning(step3UUID, 10*time.Minute)
	}
	evetest.Checkpoint("step3-is-deployed")

	// The NI is air-gapped, so there is no port-forwarding path for SSH.
	// Discover the app's pod name and reach it via kubectl exec instead.
	step3Pod := discoverPod(t, device, "eve-kube-app", "evetest-ubuntu-ctr", shortTimeout)
	step3Runner := kubectlExecRunner(device, "eve-kube-app", step3Pod, shortTimeout)

	afterStep3 := mustSumMgmtProxyHealthz(t, devices, shortTimeout)
	t.Expect(afterStep3.Requests).To(BeNumerically(">=", afterStep2.Requests),
		"mgmtproxy request count must never go down")
	log.Infof("After step 3, /healthz (summed): requests=%d (was %d after step 2; "+
		"a container app's own OCI image is always ImagePullPolicy:Never/"+
		"pre-staged by pillar's downloader, so no new pull through mgmtproxy "+
		"is expected from this step)",
		afterStep3.Requests, afterStep2.Requests)

	// Step 3 is privileged (every NOHYPER container app is), so it can add
	// the route needed to reach the cni0 listener.
	_, _, err = step3Runner("ip route add 169.254.100.1/32 dev eth0")
	t.Expect(err).ToNot(HaveOccurred(),
		"step 3: ip route add (should succeed, app is privileged)")
	checkMgmtProxyGuardrail(t, step3Runner, "step 3 (EVE API, privileged, NOHYPER)")

	_, _, _ = device.RunShellScript(
		fmt.Sprintf("eve exec kube kubectl delete pod %s -n %s --wait=false",
			step1Pod, mgmtProxyTestNamespace),
		shortTimeout, 0)
	_, _, _ = device.RunShellScript(
		fmt.Sprintf("eve exec kube kubectl delete datavolume %s -n %s --wait=false",
			cdiDataVolume, mgmtProxyTestNamespace),
		shortTimeout, 0)
	_, _, _ = device.RunShellScript(
		fmt.Sprintf("eve exec kube kubectl delete configmap %s -n %s --wait=false",
			cdiCAConfigMap, mgmtProxyTestNamespace),
		shortTimeout, 0)
}

// applyManifest kubectl-applies a YAML manifest (single- or multi-document,
// "---"-separated) via `eve exec kube kubectl apply -f -`.
func applyManifest(t *WithT, device *evetest.EdgeDevice, manifest string,
	timeout time.Duration) {

	script := fmt.Sprintf("eve exec kube kubectl apply -f - <<'EOF'\n%s\nEOF", manifest)
	_, _, err := device.RunShellScript(script, timeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "kubectl apply manifest:\n%s", manifest)
}

// indentBlock prefixes every line of s with indent, for embedding
// multi-line content (a PEM certificate) as a YAML literal block scalar.
func indentBlock(s, indent string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = indent + line
	}
	return strings.Join(lines, "\n")
}

// discoverPod finds the one pod in namespace whose image reference contains
// imageSubstring and returns its pod name. Used to locate an EVE-managed
// app's pod (there is no port-forwarding path into an air-gapped app, so
// kubectl exec is the only way in) without hardcoding the randomized
// pod-name suffix Kubernetes assigns.
func discoverPod(t *WithT, device *evetest.EdgeDevice, namespace, imageSubstring string,
	timeout time.Duration) (podName string) {

	out, _, err := device.RunShellScript(
		fmt.Sprintf("eve exec kube kubectl get pods -n %s -o "+
			`jsonpath='{range .items[*]}{.metadata.name}{" "}`+
			`{.spec.containers[0].image}{"\n"}{end}' `+
			"| grep %s | head -n1", namespace, imageSubstring),
		timeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "discover pod matching %q in namespace %s",
		imageSubstring, namespace)
	fields := strings.Fields(strings.TrimSpace(out))
	t.Expect(fields).To(HaveLen(2), "expected '<pod-name> <image-ref>' matching %q, got: %q",
		imageSubstring, out)
	return fields[0]
}

// kubectlExecRunner returns a function that runs a shell script inside pod
// (in namespace) via `eve exec kube kubectl exec`, for use with
// checkMgmtProxyGuardrail.
func kubectlExecRunner(device *evetest.EdgeDevice, namespace, pod string,
	timeout time.Duration) func(script string) (string, string, error) {

	return func(script string) (string, string, error) {
		wrapped := fmt.Sprintf("eve exec kube kubectl exec -n %s %s -- sh -c %s",
			namespace, pod, shellQuote(script))
		return device.RunShellScript(wrapped, timeout, 0)
	}
}

// sumMgmtProxyHealthz reads /healthz from every device and returns the
// per-field sums (Ready and CNI0Listening are ANDed instead). Used instead
// of reading a single device because, with more than one cluster node, the
// k8s scheduler is free to place a given step's pod on any node -- only a
// cluster-wide total is guaranteed to reflect that step's traffic. ok is
// false if reading any device failed, so callers can use this directly
// inside a t.Eventually.
func sumMgmtProxyHealthz(devices []*evetest.EdgeDevice,
	timeout time.Duration) (sum types.MgmtProxyHealthz, ok bool) {

	sum.SuccessByPort = map[string]uint64{}
	sum.FailureByPort = map[string]uint64{}
	sum.Ready = true
	sum.CNI0Listening = true
	for _, d := range devices {
		h, err := tryReadMgmtProxyHealthz(d, timeout)
		if err != nil {
			return sum, false
		}
		sum.Ready = sum.Ready && h.Ready
		sum.CNI0Listening = sum.CNI0Listening && h.CNI0Listening
		sum.Requests += h.Requests
		for port, n := range h.SuccessByPort {
			sum.SuccessByPort[port] += n
		}
		for port, n := range h.FailureByPort {
			sum.FailureByPort[port] += n
		}
	}
	return sum, true
}

// mustSumMgmtProxyHealthz is sumMgmtProxyHealthz for callers that want to
// fail the test on the spot rather than tolerate a transient read failure.
func mustSumMgmtProxyHealthz(t *WithT, devices []*evetest.EdgeDevice,
	timeout time.Duration) types.MgmtProxyHealthz {

	sum, ok := sumMgmtProxyHealthz(devices, timeout)
	t.Expect(ok).To(BeTrue(), "read /healthz from every cluster node")
	return sum
}

// tryReadMgmtProxyHealthz is the error-returning core of
// sumMgmtProxyHealthz, for callers (Eventually polling loops) that need to
// tolerate a transient failure rather than fail the test on the spot.
func tryReadMgmtProxyHealthz(device *evetest.EdgeDevice,
	timeout time.Duration) (types.MgmtProxyHealthz, error) {

	var h types.MgmtProxyHealthz
	stdout, _, err := device.RunShellScript(
		"curl -s http://127.0.0.1:5443/healthz", timeout, 0)
	if err != nil {
		return h, fmt.Errorf("curl mgmtproxy's loopback /healthz: %w", err)
	}
	if err := json.Unmarshal([]byte(stdout), &h); err != nil {
		return h, fmt.Errorf("unmarshal /healthz JSON (raw: %s): %w", stdout, err)
	}
	return h, nil
}

// checkMgmtProxyGuardrail exercises the cni0 (pod-facing) listener's
// guardrail from inside an already-reachable pod (run), asserting:
//   - Plain HTTP (no TLS at all) never reaches proxy logic -- the listener
//     is TLS-only, so a bare HTTP request is rejected at the record layer
//     before any HTTP semantics are exchanged. This is the exact vector
//     this guardrail exists for: before TLS, a CONNECT's
//     Proxy-Authorization token was interceptable by ARP-spoofing the
//     shared cni0 bridge. (A plain GET specifically gets a clean 400 --
//     Go's crypto/tls recognizes a misdirected plaintext HTTP request line
//     and replies with a "Client sent an HTTP request to an HTTPS server"
//     400 before closing, rather than just dropping the connection;
//     CONNECT isn't one of the request lines it recognizes, so that one
//     fails at the raw record layer instead -- verified against a real Go
//     TLS listener, not assumed.)
//   - Over TLS (skipping certificate validation -- this pod, unlike a real
//     CDI importer, was never given the CA, same as an attacker probing the
//     real listener directly rather than MITMing a real importer):
//     /healthz is not served there at all (404) -- it's loopback-only.
//   - A CONNECT to a real, otherwise-legitimate target (the mgmt-and-app
//     network's http-server.test, reachable only via the real mgmt
//     interface, never via the app's own network) is rejected with 407
//     (Proxy Authentication Required) -- the pod has no way to obtain the
//     vault-persisted proxy-auth token, regardless of whether the target
//     itself would otherwise be an allowed destination.
func checkMgmtProxyGuardrail(t *WithT, run func(script string) (string, string, error),
	label string) {
	out, _, err := run(
		"curl -s -o /dev/null -m 5 -w '%{http_code}' http://169.254.100.1:5443/healthz")
	t.Expect(err).ToNot(HaveOccurred(), "%s: plain HTTP to cni0 /healthz", label)
	t.Expect(out).To(Equal("400"),
		"%s: plain HTTP to cni0 /healthz must get crypto/tls's misdirected-request "+
			"400, not real proxy logic, got %s", label, out)

	// "000" is curl's -w convention for "no HTTP response was received at
	// all" -- CONNECT isn't a request line Go's TLS layer recognizes as
	// plaintext HTTP, so this one fails at the raw record layer, with no
	// status line to report at all (see the doc comment above).
	out, _, err = run("curl -s -m 5 --proxytunnel -x http://169.254.100.1:5443 " +
		"-o /dev/null -w '%{http_code}' http://http-server.test/helloworld")
	t.Expect(err).To(HaveOccurred(),
		"%s: plain HTTP CONNECT via cni0 must fail (listener is TLS-only)", label)
	t.Expect(out).To(Equal("000"),
		"%s: plain HTTP CONNECT via cni0 must get no HTTP response, got %s", label, out)

	out, _, err = run(
		"curl -sk -o /dev/null -m 5 -w '%{http_code}' https://169.254.100.1:5443/healthz")
	t.Expect(err).ToNot(HaveOccurred(), "%s: curl cni0 /healthz", label)
	t.Expect(out).To(Equal("404"),
		"%s: cni0 /healthz must not be served (want 404), got %s", label, out)

	// curl --proxytunnel treats any non-2xx CONNECT response as a hard
	// failure (exit 56, CURLE_RECV_ERROR) and reports -w '%{http_code}' as
	// "000" in that case, so the rejection is read from the CONNECT
	// response's status line (still written via -D -) instead; curl's own
	// exit code is deliberately ignored here.
	out, _, err = run("curl -sk --proxy-insecure -m 5 --proxytunnel " +
		"-x https://169.254.100.1:5443 -D - -o /dev/null http://http-server.test/helloworld")
	t.Expect(out).To(ContainSubstring("407 Proxy Authentication Required"),
		"%s: cni0 CONNECT must require proxy auth (want 407), got (err=%v): %s",
		label, err, out)
}

// shellQuote wraps s in single quotes for embedding as one argument inside
// an outer double-quoted `sh -c "..."` invocation, escaping any single
// quote already in s. Only needed because this test threads a script
// through both `eve exec kube kubectl exec` and an inner `sh -c`.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
