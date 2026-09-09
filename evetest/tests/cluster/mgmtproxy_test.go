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

// TestMgmtProxy verifies mgmtproxy (pkg/pillar/cmd/mgmtproxy): both its
// ordinary job (cost-aware CONNECT proxying for kube containerd's and CDI's
// image pulls, independent of the host's table-main default route) and its
// cni0 (pod-facing) guardrail -- without it, any pod on the node could use
// the cni0 listener as an open egress proxy laundering traffic through the
// node's management source IP.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort(devName) called with a single device
//     name. It gives two ports: "<devName>-eth0" (DHCP, controller + Internet
//     reachable) and "<devName>-eth1" (intended for cluster network, static,
//     10.244.244.0/24, NO Internet or controller reachability).
//
// Device configuration -- the deliberate table-main poisoning
// -------------------------------------------------------------
//   - ethernet0 (eth0): PhyIoUsageMgmtAndApps, Cost=1.
//   - ethernet1 (eth1): PhyIoUsageMgmtAndApps, Cost=0,
//     static IP 10.244.244.5/24 via gateway 10.244.244.1.
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
// table-main.
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
//  1. setup-done -> initial-config-applied: apply the device config
//     (mgmt+cluster ports, no app yet).
//  2. cluster-is-ready: WaitForClusterNodeIsReady; capture the
//     table-main-poisoning baseline (default route via ethernet1's gateway)
//     and the first /healthz snapshot (mgmtproxy already active from
//     system-component image pulls during cluster bring-up).
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
// Suite placement
// ---------------
//   - TestNodeClusterSuite (Kubevirt-only, like the other cluster tests).
func TestMgmtProxy(test *testing.T) {
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
		NetworkModel: netmodels.SeparateClusterPort(devName),
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial device configuration: mgmt-and-app-network
	// on eth0 (Cost=1, real Internet) and cluster-network on eth1 (Cost=0,
	// no Internet) -- both mgmt-capable, so the lower-cost (eth1) port wins
	// table-main's default route despite having nowhere useful to send
	// traffic.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	mgmtNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   mgmtNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
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
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			Cost:          0,
			StaticIP:      evetest.IPAddress("10.244.244.5"),
		})
	// network.download.max.cost defaults to 0, which would exclude
	// ethernet0 (Cost=1) from mgmtproxy's dial candidates entirely --
	// leaving only ethernet1 (deliberately broken), so nothing could ever
	// be pulled at all. Raise it to ethernet0's cost so mgmtproxy can
	// actually fall back to it.
	configProps := types.NewConfigItemValueMap()
	configProps.SetGlobalValueInt(types.DownloadMaxPortCost, 1)
	devConfig.SetConfigProperties(configProps)
	device := evetest.GetEdgeDevice(devName)
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	timeout := 20 * time.Minute
	device.WaitForClusterNodeIsReady(timeout)

	// Confirm the table-main poisoning actually took effect before relying
	// on it for the rest of the test. `ip route show default` lists every
	// default-route candidate (both ethernet0's and ethernet1's coexist,
	// distinguished only by metric), so it can't tell us which one the
	// kernel actually picks; `ip route get` resolves a real destination and
	// reports only the route actually selected for it.
	shortTimeout := 30 * time.Second
	defaultRoute, _, err := device.RunShellScript("ip route get 1.1.1.1", shortTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "read the route actually used for outbound traffic")
	t.Expect(defaultRoute).To(ContainSubstring("10.244.244.1"),
		"outbound traffic must be routed via ethernet1's gateway (10.244.244.1), "+
			"got: %s", defaultRoute)
	t.Expect(defaultRoute).ToNot(ContainSubstring("172.20.20.1"),
		"outbound traffic must NOT be routed via ethernet0's gateway, got: %s", defaultRoute)
	log.Infof("Confirmed table-main is poisoned: outbound traffic resolves via "+
		"ethernet1: %s", strings.TrimSpace(defaultRoute))

	// Baseline /healthz: mgmtproxy should already be alive and have served
	// real traffic from system-component image pulls during cluster
	// bring-up (coredns, kube-multus, virt-*, cdi-*, longhorn-*, ...) --
	// none of that is app-specific, it's an inherent part of any fresh
	// eve-k cluster forming. cni0Listening depends on kube-init's own
	// steady-state tick assigning the cni0 anchor IP (SetupCNI0ProxyIP),
	// which only runs once kube-init reaches its RUNNING state -- it does
	// not run during StateDeploying, while KubeVirt/CDI/Longhorn are still
	// installing. WaitForClusterNodeIsReady only waits for the k3s node's
	// Ready condition plus storage (Longhorn) health, a narrower condition
	// that can be satisfied while KubeVirt (observed as the slowest of the
	// three to report its CR Deployed) is still deploying, so the test can
	// resume before kube-init has finished the full sequence and reached
	// RUNNING. Poll generously rather than asserting immediately.
	log.Infof("Waiting for mgmtproxy to become ready with cni0 listening " +
		"and having served requests")
	var baseline types.MgmtProxyHealthz
	t.Eventually(func() bool {
		h, err := tryReadMgmtProxyHealthz(device, shortTimeout)
		if err != nil {
			return false
		}
		baseline = h
		return h.Ready && h.CNI0Listening && h.Requests > 0
	}, 5*time.Minute, 5*time.Second).Should(BeTrue(),
		"mgmtproxy should become ready with cni0 listening and having served requests")
	t.Expect(baseline.SuccessByPort).To(HaveKeyWithValue("eth0", BeNumerically(">", 0)),
		"successful traffic must have gone out via eth0 (the only port with real "+
			"Internet), despite eth1 being cost-preferred")
	log.Infof("Baseline /healthz: requests=%d successByPort=%v failureByPort=%v",
		baseline.Requests, baseline.SuccessByPort, baseline.FailureByPort)
	evetest.Checkpoint("cluster-is-ready")

	// mgmtProxyTestNamespace is where the raw (non-EVE-managed) resources in
	// this test are created, kept separate from EVE's own eve-kube-app
	// namespace so they're never mistaken for EVE-reconciled resources.
	const mgmtProxyTestNamespace = "default"

	const (
		testAppImageName = "lfedge/evetest-ubuntu-ctr"
		testAppImageTag  = "1.1"
	)

	// --- Step 1: raw, unprivileged container pod, genuinely uncached image ---
	//
	// testAppImageName has never been pulled onto this device before, so
	// containerd must fetch it live -- through mgmtproxy's loopback
	// listener -- independent of pillar's own downloader (which is what
	// stages step 3's image instead, without ever touching mgmtproxy).
	const step1Pod = "mgmtproxy-test-container"
	step1Manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  containers:
  - name: %s
    image: %s:%s
`, step1Pod, mgmtProxyTestNamespace, step1Pod, testAppImageName, testAppImageTag)
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

	afterStep1 := readMgmtProxyHealthz(t, device, shortTimeout)
	t.Expect(afterStep1.Requests).To(BeNumerically(">", baseline.Requests),
		"mgmtproxy should have served the raw container pod's image pull")
	t.Expect(afterStep1.SuccessByPort["eth0"]).To(
		BeNumerically(">", baseline.SuccessByPort["eth0"]),
		"the container pull must have gone out via eth0")
	log.Infof("After step 1, /healthz: requests=%d (baseline was %d)",
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

	afterStep2 := readMgmtProxyHealthz(t, device, shortTimeout)
	t.Expect(afterStep2.Requests).To(BeNumerically(">", afterStep1.Requests),
		"mgmtproxy should have served CDI importer's image fetch")
	t.Expect(afterStep2.SuccessByPort["eth0"]).To(
		BeNumerically(">", afterStep1.SuccessByPort["eth0"]),
		"CDI's importer fetch must have gone out via eth0")
	log.Infof("After step 2, /healthz: requests=%d (was %d after step 1)",
		afterStep2.Requests, afterStep1.Requests)

	// --- Step 3: EVE-API path, NOHYPER container ---
	//
	// The container app's own network instance is air-gapped (no uplink
	// Port at all), so its only possible path to anything outside its own
	// subnet is the host's cni0 mgmtproxy listener, if any.
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
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
	})
	step3UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName:        "mgmtproxy-test-app",
		Activate:           true,
		VirtualizationMode: eveconfig.VmMode_NOHYPER,
		Image: evetest.DockerContainer{
			ImageName: testAppImageName,
			Tag:       testAppImageTag,
		},
		CPUs:        1,
		MemoryBytes: 500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
			},
		},
	})
	device.ApplyConfig(devConfig, true, true)
	log.Infof("Submitted config with step 3 (EVE API) UUID=%v", step3UUID)
	evetest.Checkpoint("step3-config-is-submitted")

	device.WaitUntilAppIsRunning(step3UUID, 10*time.Minute)
	evetest.Checkpoint("step3-is-deployed")

	// The NI is air-gapped, so there is no port-forwarding path for SSH.
	// Discover the app's pod name and reach it via kubectl exec instead.
	step3Pod := discoverPod(t, device, "eve-kube-app", "evetest-ubuntu-ctr", shortTimeout)
	step3Runner := kubectlExecRunner(device, "eve-kube-app", step3Pod, shortTimeout)

	afterStep3 := readMgmtProxyHealthz(t, device, shortTimeout)
	t.Expect(afterStep3.Requests).To(BeNumerically(">=", afterStep2.Requests),
		"mgmtproxy request count must never go down")
	log.Infof("After step 3, /healthz: requests=%d (was %d after step 2; "+
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

// readMgmtProxyHealthz reads and parses mgmtproxy's loopback (host-only)
// /healthz endpoint. Unlike the cni0 one, this listener is not subject to
// the guardrail under test, so a plain host-side shell script (no
// `eve exec kube`) is enough to reach it -- pillar runs with net: host.
func readMgmtProxyHealthz(t *WithT, device *evetest.EdgeDevice,
	timeout time.Duration) types.MgmtProxyHealthz {

	h, err := tryReadMgmtProxyHealthz(device, timeout)
	t.Expect(err).ToNot(HaveOccurred())
	return h
}

// tryReadMgmtProxyHealthz is the error-returning core of
// readMgmtProxyHealthz, for callers (Eventually polling loops) that need to
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
