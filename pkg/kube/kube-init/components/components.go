// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package components deploys Kubernetes workloads after k3s is
// running: Multus CNI, KubeVirt, CDI, Longhorn, descheduler, debug-
// user RBAC, and storage-class manifests.
//
// Every installation function is idempotent — a marker file under
// /var/lib/ is touched on success and checked on subsequent calls so
// a component is never re-installed across kube-init restarts.
package components

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/deploy"
	"github.com/lf-edge/eve/pkg/kube/kube-init/edgenodeinfo"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/prereqs"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	"github.com/lf-edge/eve/pkg/kube/kube-init/versions"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

const longhornInformerResync = 10 * time.Minute

// GVK/GVR handles used by components/* patch operations.
var (
	kubevirtGVK = schema.GroupVersionKind{Group: "kubevirt.io", Version: "v1", Kind: "KubeVirt"}
	cdiGVK      = schema.GroupVersionKind{Group: "cdi.kubevirt.io", Version: "v1beta1", Kind: "CDI"}
)

// Component manifest paths, baked into the container image at build
// time.
const (
	debugRoleBinding  = "/etc/debuguser-role-binding.yaml"
	kubevirtOperator  = "/etc/kubevirt-operator.yaml"
	kubevirtFeatures  = "/etc/kubevirt-features.yaml"
	longhornCfg       = "/etc/lh-cfg-" + versions.Longhorn + ".yaml"
	deschedulerRBAC   = "/etc/descheduler_rbac.yaml"
	deschedulerPolicy = "/etc/descheduler-policy-configmap.yaml"

	storageClassesYaml = "storage-classes.yaml"

	// manifestsSrc holds yaml templates shipped with kube-init.
	// manifestsDst is the k3s server's auto-deploy manifests dir.
	manifestsSrc = "/etc/k3s-manifests/"
	manifestsDst = "/var/lib/rancher/k3s/server/manifests/"

	certGenBin = "/usr/bin/cert-gen"

	caCertPath = "/var/lib/rancher/k3s/server/tls/client-ca.crt"
	caKeyPath  = "/var/lib/rancher/k3s/server/tls/client-ca.key"

	kubevirtCRURL = "https://github.com/kubevirt/kubevirt/releases/download/" +
		versions.KubeVirt + "/kubevirt-cr.yaml"
	cdiVersion = versions.CDI

	// longhornWaitTimeout is a NO-PROGRESS window, not a wall clock:
	// the component sets Progress, so the budget restarts whenever
	// containerd reports more bytes pulled. The ceiling bounds the
	// total for a component that reports progress but never
	// converges. Longhorn is ~280 MB across three images, which on a
	// slow link legitimately exceeds the window while advancing.
	longhornWaitTimeout = 10 * time.Minute
	// Sized above a cold pull of the instance-manager image (442 MB) plus
	// the resource reaching running, measured at ~42 min on the slowest
	// topology under load. The previous 40 min expired three minutes short
	// of convergence. Matches the e2e suite's own budget for this gate.
	longhornReadyCeiling = 90 * time.Minute

	nvidiaVendorDir = "/opt/vendor/nvidia"

	// Multus readiness identity. The DaemonSet's pods write
	// 00-multus.conf into k3s's CNI dir; because 00- sorts first that
	// file is the node's primary CNI config, so components that create
	// pods must not run until it is in place.
	multusNamespace     = "kube-system"
	multusDaemonSet     = "kube-multus-ds"
	multusReadyTimeout  = 5 * time.Minute
	eveKubeAppNamespace = "eve-kube-app"

	// KubeVirt readiness identities.
	kubevirtOperatorDeployment    = "virt-operator"
	kubevirtCRName                = "kubevirt"
	kubevirtOperatorWaitTimeout   = 5 * time.Minute
	kubevirtCRDeployedWaitTimeout = 10 * time.Minute
	kubevirtCRReadyCeiling        = 40 * time.Minute

	// CDI readiness identities.
	cdiOperatorDeployment    = "cdi-operator"
	cdiCRName                = "cdi"
	cdiOperatorWaitTimeout   = 5 * time.Minute
	cdiCRDeployedWaitTimeout = 10 * time.Minute
	cdiOperatorReadyCeiling  = 20 * time.Minute
	cdiCRReadyCeiling        = 30 * time.Minute
)

// Multus + DHCP-daemon + debug-user paths. Exported because the
// monitor package re-reads/re-creates these files in its
// running-state health check loop.
const (
	MultusYAMLSrc    = "/etc/multus-daemonset.yaml"
	MultusYAMLDst    = "/etc/multus-daemonset-new.yaml"
	MultusLinkSource = "/var/lib/cni/bin/multus"
	MultusLinkTarget = "/var/lib/rancher/k3s/data/current/bin/multus"

	DHCPBinary = "/opt/cni/bin/dhcp"
	DHCPSocket = "/run/cni/dhcp.sock"

	K3sUserYaml = "/var/lib/rancher/k3s/user.yaml"
	RunUserYaml = "/run/.kube/k3s/user.yaml"
)

// NodeAddress carries the host's IPv4 + cluster prefix as a single
// pair so callers can't accidentally swap the two strings at a call
// site.
type NodeAddress struct {
	// IP is the host's IPv4 address (no CIDR suffix).
	IP string
	// Prefix is the CIDR suffix kube-init writes into the Multus
	// daemonset template — always "/32" today.
	Prefix string
}

// DeployAll orchestrates component deployment.
//
// Dependency rationale:
//   - `longhorn` needs `manifests` because its PVC controller reads
//     storage-classes.yaml out of the k3s auto-deploy dir before its
//     first reconcile, otherwise it races an empty StorageClass list.
//     A filesystem fact, so a PolicyDeps rather than a signal.
//   - `multus` needs the eve-kube-app namespace: the rendered manifest
//     puts a NetworkAttachmentDefinition in it.
//   - every pod-creating component needs MultusCNIReady. Multus writes
//     00-multus.conf, and because 00- sorts first that is the node's
//     primary CNI config — starting kubevirt, cdi or longhorn while it
//     is still landing races pod creation against the CNI delegate
//     changing underneath.
//
// debug-rbac and descheduler depend on nothing and run immediately.
//
// kubevirt + cdi + longhorn are BestEffort: their phase=Deployed
// (or DaemonSet-ready) wait can take minutes on a fresh boot, and
// the FSM's steady-state ticks reconcile any apply failure.
// BestEffort prevents them from blocking the rest of the deploy
// and the transition to RUNNING. BestEffortWaitReadyTimeout is
// set per-node so each operator's convergence budget (10 min) is
// respected; without it the deploy package's 30-second default
// would fire prematurely.
//
// MaxParallel bounds concurrent Apply work so a first boot does not put
// every operator install and manifest parse on the node at once. Ready
// waits run outside that bound — see runOne. The count comes from the
// live kube cpuset rather than runtime.NumCPU, which caches the mask at
// process start and so would not see the first-boot widening.
//
// AllComponentsInitialized / NodeLabelsInitialized are deliberately
// NOT written here — the caller writes them only after the post-deploy
// SaveVarLib succeeds, so "marker present" implies a complete /var/lib
// snapshot too. A failed snapshot fails the deploy and is retried
// rather than being logged past, because that snapshot is the only
// rollback point for a later cluster→single conversion.
func DeployAll(
	ctx, retryCtx context.Context, bus *deploy.Bus,
	deviceName string, installKubevirt bool,
) error {
	log.Printf("starting component deployment (device=%s, kubevirt=%v)",
		deviceName, installKubevirt)

	// Resolve node IP up front so the Multus closure captures concrete
	// values; a network misconfig fails fast before any kubectl runs.
	addr, err := resolveNodeAddress()
	if err != nil {
		return fmt.Errorf("resolve node IP: %w", err)
	}

	g := buildDeployGraph(deviceName, addr, installKubevirt)
	// Daemon-scoped so a re-entered deploy sees signals earlier passes
	// already established, and the control socket can report them.
	g.Bus = bus
	// Wire the daemon-scoped ctx for BestEffort background retries.
	// Retries survive Run's return (its ctx is workCtx, per-invocation)
	// so a slow component keeps reconciling in the background; they
	// die on daemon shutdown when retryCtx is cancelled.
	g.RetryCtx = retryCtx
	// Lets the daemon tell 'Run returned' from 'nothing is still working'.
	g.Retries = retryTracker
	if err := g.Run(ctx); err != nil {
		return err
	}
	log.Printf("all components initialized")
	return nil
}

// applyConcurrency caps concurrent Apply work at the CPUs the kube
// cgroup may currently use. The floor of two keeps a single-CPU device
// from serialising completely, since an Apply interleaves parsing with
// API round-trips rather than spinning.
func applyConcurrency() int {
	n := prereqs.KubeCPUCount()
	if n <= 0 {
		// No cpuset to read (cgroup v2, or an unconfined host).
		n = runtime.NumCPU()
	}
	return max(2, n)
}

// ensureEveKubeAppNamespace creates the namespace that hosts EVE app
// instance workloads if it is not already present. Idempotent.
// multus-daemonset.yaml puts a NetworkAttachmentDefinition in it, so
// the multus component gates on the signal this emits.
func ensureEveKubeAppNamespace(ctx context.Context) error {
	nsClient := kubeclient.Default().Clientset.CoreV1().Namespaces()
	if _, err := nsClient.Get(ctx, eveKubeAppNamespace, metav1.GetOptions{}); err == nil {
		return nil
	}
	nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: eveKubeAppNamespace}}
	if _, err := nsClient.Create(ctx, nsObj, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("create namespace: %w", err)
	}
	log.Printf("created namespace eve-kube-app")
	return nil
}

// GraphEdges returns the resolved dependency edges of the deploy
// graph without running it. installKubevirt mirrors the DeployAll
// flag so the reported graph matches what a live boot would execute.
//
// The graph is built with placeholder deviceName + NodeAddress —
// those affect the Apply closures, not the edges, so the placeholders
// are safe. If the plan itself is malformed (a coding bug), the
// underlying error is surfaced.
func GraphEdges(installKubevirt bool) ([]deploy.Edge, error) {
	g := buildDeployGraph("<sctl>", NodeAddress{IP: "0.0.0.0", Prefix: "/32"}, installKubevirt)
	return g.Edges()
}

// buildDeployGraph constructs the deploy.Graph used by DeployAll.
// Extracted so the wiring (PolicyDeps edges + conditional inclusion
// of kubevirt/cdi) can be unit-tested without invoking installers.
//
// Components declare no Manifests today — every install runs via
// the imperative Apply / Ready step-func pair inherited from the
// previous Node-based graph. Task #12 will migrate each InstallX
// to declarative Manifests so the runner's structural rules can
// derive edges automatically; until then, ordering rides on
// PolicyDeps.
func buildDeployGraph(deviceName string, addr NodeAddress, installKubevirt bool) deploy.Graph {
	g := deploy.Graph{
		MaxParallel: applyConcurrency(),
		// Operator breakpoint per component, so /persist/k3s/wait_longhorn
		// holds the graph just before Longhorn applies. Covers the shell's
		// kubevirt/cdi/longhorn/descheduler wait points and every other
		// component for free, since the names are the graph's own.
		BeforeApply: state.WaitForItem,
		Components: []deploy.Component{
			{
				// The namespace hosts EVE app workloads and holds the
				// NetworkAttachmentDefinition in the multus manifest.
				Name:  "namespace",
				Apply: ensureEveKubeAppNamespace,
				Emits: []deploy.Signal{deploy.EveKubeAppNamespaceExists},
			},
			{
				Name:     "multus",
				Requires: []deploy.Signal{deploy.EveKubeAppNamespaceExists},
				Apply:    func(c context.Context) error { return ApplyMultusCNI(c, addr) },
				Ready: func(c context.Context) error {
					return kubectlx.WaitDaemonSetReady(c, kubeclient.Default(),
						multusNamespace, multusDaemonSet, multusReadyTimeout)
				},
				Emits: []deploy.Signal{deploy.MultusCNIReady},
			},
			{
				Name:  "debug-rbac",
				Apply: ConfigClusterRoles,
			},
			{
				Name:  "manifests",
				Apply: func(_ context.Context) error { return CopyManifests() },
			},
			{
				// Longhorn needs storage-classes.yaml in the auto-deploy
				// dir before its config is applied (real dep).
				//
				// BestEffort with the full 10-min ready timeout — Apply
				// still runs synchronously and writes
				// state.LonghornInitialized, but Ready is downgraded
				// so the rest of the deploy (and the FSM's transition
				// to RUNNING) doesn't block on Longhorn's CR
				// convergence. runHealthWorker's
				// LonghornPostInstallConfig gates its work on
				// Longhorn_is_ready, so steady-state ticks reconcile
				// any apply that hasn't converged yet.
				Name:         "longhorn",
				PolicyDeps:   []string{"manifests"},
				Requires:     []deploy.Signal{deploy.MultusCNIReady},
				Apply:        func(c context.Context) error { return InstallLonghorn(c, deviceName) },
				Ready:        WaitLonghornReady,
				Emits:        []deploy.Signal{deploy.LonghornReady},
				BestEffort:   true,
				ReadyTimeout: longhornWaitTimeout,
				Progress:     longhornProgress,
				ReadyCeiling: longhornReadyCeiling,
			},
			{
				Name:  "descheduler",
				Apply: InstallDescheduler,
			},
		},
	}
	if installKubevirt {
		g.Components = append(g.Components,
			deploy.Component{
				Name:         "kubevirt",
				Requires:     []deploy.Signal{deploy.MultusCNIReady},
				Apply:        InstallKubeVirt,
				Ready:        WaitKubeVirtReady,
				BestEffort:   true,
				ReadyTimeout: kubevirtCRDeployedWaitTimeout,
				Progress:     componentProgress(kubectlx.KubeVirtNamespace),
				ReadyCeiling: kubevirtCRReadyCeiling,
			},
			deploy.Component{
				Name:         "cdi-operator",
				Requires:     []deploy.Signal{deploy.MultusCNIReady},
				Apply:        InstallCDIOperator,
				Ready:        WaitCDIOperatorReady,
				Emits:        []deploy.Signal{deploy.CDIOperatorReady},
				BestEffort:   true,
				ReadyTimeout: cdiOperatorWaitTimeout,
				Progress:     componentProgress(kubectlx.CDINamespace),
				ReadyCeiling: cdiOperatorReadyCeiling,
			},
			deploy.Component{
				// MultusCNIReady comes transitively via cdi-operator.
				Name:         "cdi",
				Requires:     []deploy.Signal{deploy.CDIOperatorReady},
				Apply:        InstallCDICR,
				Ready:        WaitCDIReady,
				Emits:        []deploy.Signal{deploy.CDIReady},
				BestEffort:   true,
				ReadyTimeout: cdiCRDeployedWaitTimeout,
				Progress:     componentProgress(kubectlx.CDINamespace),
				ReadyCeiling: cdiCRReadyCeiling,
			},
		)
	}
	return g
}

// ---------------------------------------------------------------------------
// Multus CNI
// ---------------------------------------------------------------------------

// ApplyMultusCNI renders the Multus DaemonSet template with the
// node's IP prefix, applies the manifest, and symlinks the multus
// binary into k3s.
//
// PRECONDITION: the eve-kube-app namespace must already exist —
// the rendered manifest contains a NetworkAttachmentDefinition
// inside it. DeployAll's prelude creates the namespace before any
// graph node runs; cluster-mode transitions reuse the namespace
// from the prior first-boot DeployAll (k3s state lives in
// /persist and survives reboots).
//
// The initialization marker is written ONLY after every step
// (including the symlink) succeeds; a partial install must remain
// detectable so the next FSM tick re-runs the function.
func ApplyMultusCNI(ctx context.Context, addr NodeAddress) error {
	marked, err := state.IsMarked(state.MultusInitialized)
	if err != nil {
		return fmt.Errorf("check multus marker: %w", err)
	}
	if marked {
		log.Printf("multus already initialized, skipping")
		return nil
	}

	ipPrefix := addr.IP + addr.Prefix
	tmpl, err := os.ReadFile(MultusYAMLSrc)
	if err != nil {
		return fmt.Errorf("read multus template %s: %w", MultusYAMLSrc, err)
	}
	rendered := strings.ReplaceAll(string(tmpl), "IPAddressReplaceMe", ipPrefix)
	if err := os.WriteFile(MultusYAMLDst, []byte(rendered), 0644); err != nil {
		return fmt.Errorf("write rendered multus yaml %s: %w", MultusYAMLDst, err)
	}
	log.Printf("rendered multus daemonset with IP prefix %s", ipPrefix)

	if err := kubectlApply(ctx, MultusYAMLDst); err != nil {
		return fmt.Errorf("apply multus daemonset: %w", err)
	}
	log.Printf("multus daemonset applied")

	if err := linkMultusIntoK3s(); err != nil {
		return fmt.Errorf("link multus into k3s: %w", err)
	}

	if err := state.Mark(state.MultusInitialized); err != nil {
		return fmt.Errorf("mark multus initialized: %w", err)
	}
	log.Printf("multus initialization complete")
	return nil
}

// ---------------------------------------------------------------------------
// DHCP daemon (CNI)
// ---------------------------------------------------------------------------

// StartDHCPDaemon launches the CNI DHCP daemon in the background
// if not already running. Idempotent.
//
// The reaper goroutine LOGS the exit error rather than discarding
// it: a daemon that dies seconds after Start (bad CNI config,
// missing /var/lib/cni) needs to surface in the daemon log or it
// becomes an undebuggable silent failure.
func StartDHCPDaemon() error {
	if isDHCPRunning() {
		log.Printf("DHCP daemon already running")
		return nil
	}
	if _, err := os.Stat(DHCPSocket); err == nil {
		log.Printf("removing stale DHCP socket %s", DHCPSocket)
		if err := os.Remove(DHCPSocket); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale DHCP socket: %w", err)
		}
	}
	cmd := exec.Command(DHCPBinary, "daemon")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start DHCP daemon: %w", err)
	}
	pid := cmd.Process.Pid
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("DHCP daemon (pid %d) exited: %v", pid, err)
		}
	}()
	log.Printf("DHCP daemon started (pid %d)", pid)
	return nil
}

// ---------------------------------------------------------------------------
// Debug-user RBAC
// ---------------------------------------------------------------------------

// ConfigClusterRoles generates TLS certs for the debug user,
// builds a kubeconfig, and applies the RoleBinding. Idempotent via
// state.DebugUserInitialized marker.
func ConfigClusterRoles(ctx context.Context) error {
	marked, err := state.IsMarked(state.DebugUserInitialized)
	if err != nil {
		return fmt.Errorf("check debug-user marker: %w", err)
	}
	if marked {
		log.Printf("debug user already initialized, skipping")
		return nil
	}

	removeGlob("/tmp/k3s-debuguser*.pem")

	certGenArgs := []string{
		"-l", "315360000",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"-o", "k3s-debuguser",
		"--output-dir", "/tmp",
		"--cert-cn", "debugging-user",
		"--cert-o", "rbac",
	}
	out, err := runCommand(certGenBin, certGenArgs...)
	if err != nil {
		return fmt.Errorf("cert-gen failed: %w (output: %s)", err, out)
	}
	log.Printf("debug user certificates generated")

	keyPath, err := findGlob("/tmp/k3s-debuguser*.key.pem")
	if err != nil {
		return fmt.Errorf("find debug user key: %w", err)
	}
	crtPath, err := findGlob("/tmp/k3s-debuguser*.cert.pem")
	if err != nil {
		return fmt.Errorf("find debug user cert: %w", err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	crtData, err := os.ReadFile(crtPath)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}

	adminCfg, err := os.ReadFile(state.K3sKubeconfig)
	if err != nil {
		return fmt.Errorf("read admin kubeconfig: %w", err)
	}
	userCfg := string(adminCfg)
	userCfg = replaceField(userCfg, "client-certificate-data:",
		base64.StdEncoding.EncodeToString(crtData))
	userCfg = replaceField(userCfg, "client-key-data:",
		base64.StdEncoding.EncodeToString(keyData))

	if err := os.WriteFile(K3sUserYaml, []byte(userCfg), 0600); err != nil {
		return fmt.Errorf("write user yaml: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(RunUserYaml), 0755); err != nil {
		return fmt.Errorf("mkdir for run user yaml: %w", err)
	}
	if err := copyFile(K3sUserYaml, RunUserYaml); err != nil {
		return fmt.Errorf("copy user yaml to run: %w", err)
	}

	if err := kubectlApply(ctx, debugRoleBinding); err != nil {
		return fmt.Errorf("apply debug role binding: %w", err)
	}

	if err := state.Mark(state.DebugUserInitialized); err != nil {
		return fmt.Errorf("mark debug-user initialized: %w", err)
	}
	log.Printf("debug user RBAC configured")
	return nil
}

// ---------------------------------------------------------------------------
// KubeVirt
// ---------------------------------------------------------------------------

// InstallKubeVirt applies the patched KubeVirt operator, waits for
// virt-operator to roll out, then applies the upstream CR. The post-
// CR readiness gate lives in WaitKubeVirtReady (deploy-graph WaitReady).
//
// Sequence:
//
//	apply operator → WaitDeploymentReady(virt-operator)
//	  → apply CR → patch replicas → apply feature gates
//
// The phase=Deployed wait is intentionally NOT in this function:
// it routinely takes 5+ minutes on a fresh node and would block
// peers in the deploy graph. The graph's WaitReady step (which runs
// concurrently with downstream nodes) is where that wait belongs.
func InstallKubeVirt(ctx context.Context) error {
	marked, err := state.IsMarked(state.KubevirtInitialized)
	if err != nil {
		return fmt.Errorf("check kubevirt marker: %w", err)
	}
	if marked {
		log.Printf("kubevirt already initialized, skipping")
		return nil
	}

	kc := kubeclient.Default()
	log.Printf("installing KubeVirt operator")
	if err := kubectlx.ApplyFile(ctx, kc, kubevirtOperator, kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("apply kubevirt operator: %w", err)
	}

	// Wait for virt-operator before applying the CR — the operator
	// owns the KubeVirt CRD admission webhook; applying the CR
	// before the operator is Ready races both.
	if err := kubectlx.WaitDeploymentReady(ctx, kc, kubectlx.KubeVirtNamespace,
		kubevirtOperatorDeployment, kubevirtOperatorWaitTimeout); err != nil {
		return fmt.Errorf("wait virt-operator ready: %w", err)
	}

	log.Printf("applying KubeVirt CR")
	if err := kubectlx.ApplyURL(ctx, kc, kubevirtCRURL, kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("apply kubevirt CR: %w", err)
	}

	// Replica patch is best-effort — the CR controller may still be
	// starting; the next steady-state tick will reconcile.
	if err := kubeVirtConfigReplicas(ctx, 3); err != nil {
		log.Printf("warning: KubeVirt replica count patch: %v", err)
	}

	log.Printf("applying KubeVirt feature gates")
	if err := kubectlx.ApplyFile(ctx, kc, kubevirtFeatures, kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("apply kubevirt features: %w", err)
	}

	if err := state.Mark(state.KubevirtInitialized); err != nil {
		return fmt.Errorf("mark kubevirt initialized: %w", err)
	}
	log.Printf("KubeVirt installation complete")
	return nil
}

// WaitKubeVirtReady blocks until the KubeVirt CR reports
// status.phase=Deployed.
func WaitKubeVirtReady(ctx context.Context) error {
	return kubectlx.WaitForCondition(ctx, kubeclient.Default(),
		kubevirtGVK, kubectlx.KubeVirtNamespace, kubevirtCRName,
		"{.status.phase}", "Deployed",
		kubectlx.WaitFromContext)
}

// kubeVirtConfigReplicas patches virt-operator Deployment replicas
// and KubeVirt CR infra.replicas in one shot.
//
// Uses server-side apply with a dedicated field manager
// ("kube-init-replicas") so subsequent SSAs of the operator
// manifest under FM="kube-init" don't race for ownership of
// .spec.replicas — the two managers own disjoint fields cleanly,
// and both use Force via kubectlx's default so field-manager
// hand-off is transparent. Merge patches don't work here: they
// create an Update-op ownership record that SSA sees as a foreign
// owner and rejects with a conflict on retry.
func kubeVirtConfigReplicas(ctx context.Context, replicas int) error {
	log.Printf("setting virt-operator and KubeVirt infra replicas to %d", replicas)
	kc := kubeclient.Default()

	deployApply := fmt.Sprintf(
		`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"virt-operator","namespace":%q},"spec":{"replicas":%d}}`,
		kubectlx.KubeVirtNamespace, replicas)
	force := true
	if _, err := kc.Clientset.AppsV1().Deployments(kubectlx.KubeVirtNamespace).
		Patch(ctx, "virt-operator", types.ApplyPatchType,
			[]byte(deployApply),
			metav1.PatchOptions{FieldManager: "kube-init-replicas", Force: &force},
		); err != nil {
		return fmt.Errorf("patch virt-operator deployment: %w", err)
	}

	crApply := fmt.Sprintf(
		`{"apiVersion":"kubevirt.io/v1","kind":"KubeVirt","metadata":{"name":"kubevirt","namespace":%q},"spec":{"infra":{"replicas":%d}}}`,
		kubectlx.KubeVirtNamespace, replicas)
	if _, err := kc.Dynamic.Resource(kubectlx.KubeVirtGVR).Namespace(kubectlx.KubeVirtNamespace).
		Patch(ctx, "kubevirt", types.ApplyPatchType, []byte(crApply),
			metav1.PatchOptions{FieldManager: "kube-init-replicas", Force: &force},
		); err != nil {
		return fmt.Errorf("patch KubeVirt CR infra.replicas: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// CDI
// ---------------------------------------------------------------------------

// cdiReleaseURL builds the URL of a manifest in the pinned CDI release.
func cdiReleaseURL(manifest string) string {
	return fmt.Sprintf(
		"https://github.com/kubevirt/containerized-data-importer/releases/download/%s/%s",
		cdiVersion, manifest)
}

// InstallCDIOperator applies the CDI operator manifest.
//
// The operator and its CR are separate graph components rather than one
// installer with a blocking wait between them. The operator serves the
// CR's admission webhook, so the ordering is real — but expressing it as
// a signal edge means a slow operator image pull retries only the
// operator stage. Folded together, the retry re-applied the operator
// manifest and re-waited the full operator budget on every attempt, and
// a wait that timed out skipped the CR entirely, leaving CDI installed
// but never reconciling.
func InstallCDIOperator(ctx context.Context) error {
	log.Printf("installing CDI operator %s", cdiVersion)
	if err := kubectlx.ApplyURL(ctx, kubeclient.Default(),
		cdiReleaseURL("cdi-operator.yaml"), kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("apply CDI operator: %w", err)
	}
	return nil
}

// WaitCDIOperatorReady blocks until cdi-operator is Available.
func WaitCDIOperatorReady(ctx context.Context) error {
	return kubectlx.WaitDeploymentReady(ctx, kubeclient.Default(),
		kubectlx.CDINamespace, cdiOperatorDeployment, kubectlx.WaitFromContext)
}

// InstallCDICR applies the CDI CR. Gated on CDIOperatorReady, so the
// admission webhook is normally serving by the time this runs; ApplyURL's
// own backoff covers the case where the operator was only reported ready
// moments earlier.
func InstallCDICR(ctx context.Context) error {
	log.Printf("applying CDI CR")
	if err := kubectlx.ApplyURL(ctx, kubeclient.Default(),
		cdiReleaseURL("cdi-cr.yaml"), kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("apply CDI CR: %w", err)
	}
	return nil
}

// WaitCDIReady blocks until the CDI CR reports phase=Deployed.
func WaitCDIReady(ctx context.Context) error {
	return kubectlx.WaitForCondition(ctx, kubeclient.Default(),
		cdiGVK, "", cdiCRName,
		"{.status.phase}", "Deployed",
		kubectlx.WaitFromContext)
}

// ---------------------------------------------------------------------------
// Storage manifests
// ---------------------------------------------------------------------------

// CopyManifests stages storage-classes.yaml (and optionally the
// NVIDIA device-plugin manifest) into the k3s auto-deploy dir.
// EnsureStorageClasses owns the MkdirAll of manifestsDst.
func CopyManifests() error {
	if err := EnsureStorageClasses(); err != nil {
		return fmt.Errorf("copy storage-classes.yaml: %w", err)
	}
	return copyOptionalNvidiaManifest()
}

// EnsureStorageClasses copies storage-classes.yaml from manifestsSrc
// into the auto-deploy dir when missing. Idempotent.
func EnsureStorageClasses() error {
	dst := filepath.Join(manifestsDst, storageClassesYaml)
	if _, err := os.Stat(dst); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", dst, err)
	}
	if err := os.MkdirAll(manifestsDst, 0755); err != nil {
		return fmt.Errorf("mkdir manifests dst: %w", err)
	}
	src := filepath.Join(manifestsSrc, storageClassesYaml)
	if err := copyFile(src, dst); err != nil {
		return fmt.Errorf("copy %s: %w", storageClassesYaml, err)
	}
	log.Printf("ensured %s in %s", storageClassesYaml, manifestsDst)
	return nil
}

// copyOptionalNvidiaManifest stages the NVIDIA device-plugin
// manifest into the auto-deploy dir on hardware that exposes
// /opt/vendor/nvidia. ENOENT on either the vendor dir or the
// manifest is a no-op (no NVIDIA hardware / minimal build). A
// copy failure on hardware that does have the vendor dir IS
// surfaced — silent failure means GPUs are invisible to k8s
// and the misconfiguration is undiagnosable from the daemon log.
func copyOptionalNvidiaManifest() error {
	if _, err := os.Stat(nvidiaVendorDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", nvidiaVendorDir, err)
	}
	nvSrc := filepath.Join(manifestsSrc, "nvidia-device-plugin-18.0.yml")
	nvDst := filepath.Join(manifestsDst, "nvidia-device-plugin-18.0.yml")
	if _, err := os.Stat(nvSrc); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", nvSrc, err)
	}
	if err := copyFile(nvSrc, nvDst); err != nil {
		return fmt.Errorf("copy NVIDIA manifest: %w", err)
	}
	log.Printf("copied NVIDIA device plugin manifest")
	return nil
}

// ---------------------------------------------------------------------------
// Longhorn
// ---------------------------------------------------------------------------

// InstallLonghorn labels the node for Longhorn disk discovery and
// applies the Longhorn config YAML.
func InstallLonghorn(ctx context.Context, deviceName string) error {
	marked, err := state.IsMarked(state.LonghornInitialized)
	if err != nil {
		return fmt.Errorf("check longhorn marker: %w", err)
	}
	if marked {
		log.Printf("longhorn already initialized, skipping")
		return nil
	}

	log.Printf("installing Longhorn")
	longhornPreflightCheck()
	applyLonghornDiskConfig(ctx, deviceName)

	cfgData, err := os.ReadFile(longhornCfg)
	if err != nil {
		return fmt.Errorf("read longhorn config: %w", err)
	}
	cfgStr := string(cfgData)
	if !strings.Contains(cfgStr, "create-default-disk-labeled-nodes: true") {
		cfgStr = strings.Replace(cfgStr,
			"  default-setting.yaml: |-",
			"  default-setting.yaml: |-\n    create-default-disk-labeled-nodes: true",
			1)
		if err := os.WriteFile(longhornCfg, []byte(cfgStr), 0644); err != nil {
			return fmt.Errorf("patch longhorn config: %w", err)
		}
	}

	if err := kubectlApply(ctx, longhornCfg); err != nil {
		return fmt.Errorf("apply longhorn config: %w", err)
	}

	if err := state.Mark(state.LonghornInitialized); err != nil {
		return fmt.Errorf("mark longhorn initialized: %w", err)
	}
	log.Printf("Longhorn installation complete")
	return nil
}

// WaitLonghornReady blocks until the longhorn-manager and longhorn-csi-plugin
// DaemonSets are Available and the Node CR for this host exists. Uses per-call
// filtered informer factories scoped to the wait ctx; times out after
// longhornWaitTimeout.
func WaitLonghornReady(ctx context.Context) error {
	log.Printf("waiting for Longhorn readiness (deadline from caller)")

	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	kc := kubeclient.Default()

	dsFactory := informers.NewSharedInformerFactoryWithOptions(kc.Clientset,
		longhornInformerResync, informers.WithNamespace(kubectlx.LonghornNamespace))
	dynFactory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(kc.Dynamic,
		longhornInformerResync, kubectlx.LonghornNamespace, nil)

	dsInformer := dsFactory.Apps().V1().DaemonSets().Informer()
	longhornNodesInformer := dynFactory.ForResource(kubectlx.LonghornNodesGVR).Informer()
	longhornIMInformer := dynFactory.ForResource(kubectlx.LonghornInstanceManagersGVR).Informer()

	ready := make(chan struct{}, 1)
	signalReady := func() {
		select {
		case ready <- struct{}{}:
		default:
		}
	}
	check := func() {
		if longhornDaemonSetsReady(waitCtx) && longhornNodeExists(waitCtx) &&
			longhornInstanceManagerRunning(waitCtx) {
			signalReady()
		}
	}
	if _, err := dsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { check() },
		UpdateFunc: func(_, _ any) { check() },
	}); err != nil {
		return fmt.Errorf("add daemonset event handler: %w", err)
	}
	if _, err := longhornNodesInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { check() },
		UpdateFunc: func(_, _ any) { check() },
	}); err != nil {
		return fmt.Errorf("add longhorn node event handler: %w", err)
	}
	// Without this the instance-manager could be the last condition to
	// hold and nothing would notice until the informers' 10-minute
	// resync, since the wait blocks on events rather than polling.
	if _, err := longhornIMInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { check() },
		UpdateFunc: func(_, _ any) { check() },
	}); err != nil {
		return fmt.Errorf("add longhorn instancemanager event handler: %w", err)
	}

	dsFactory.Start(waitCtx.Done())
	dynFactory.Start(waitCtx.Done())

	if !cache.WaitForCacheSync(waitCtx.Done(),
		dsInformer.HasSynced, longhornNodesInformer.HasSynced,
		longhornIMInformer.HasSynced) {
		return fmt.Errorf("longhorn informers failed to sync: %w", waitCtx.Err())
	}

	// Kick off with a synchronous check — the informer caches may
	// already show a Ready state (steady-state re-entry), and we'd
	// otherwise block waiting for the next event that never comes.
	check()

	select {
	case <-ready:
		log.Printf("Longhorn is ready")
		return nil
	case <-waitCtx.Done():
		// The caller owns the deadline, so it labels the outcome —
		// stalled, ceiling, or its own cancellation.
		return fmt.Errorf("waiting for Longhorn readiness: %w", waitCtx.Err())
	}
}

// ---------------------------------------------------------------------------
// Descheduler
// ---------------------------------------------------------------------------

// InstallDescheduler applies the descheduler RBAC and policy
// ConfigMap.
func InstallDescheduler(ctx context.Context) error {
	log.Printf("installing descheduler")
	if err := kubectlApply(ctx, deschedulerRBAC); err != nil {
		return fmt.Errorf("apply descheduler RBAC: %w", err)
	}
	if err := kubectlApply(ctx, deschedulerPolicy); err != nil {
		return fmt.Errorf("apply descheduler policy: %w", err)
	}
	log.Printf("descheduler installation complete")
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// kubectlApply applies a manifest file via client-go server-side
// apply. The retry-on-NoKindMatchError inside kubectlx.ApplyFile
// handles the CRD-then-CR race that manifests like multus-daemonset.yaml
// hit (the CRD + a CR of that kind in one file — the first pass
// creates the CRD, the second sees it).
func kubectlApply(ctx context.Context, yamlFile string) error {
	return kubectlx.ApplyFile(ctx, kubeclient.Default(), yamlFile, kubectlx.ApplyOptions{})
}

// copyFile copies src to dst, preserving the source's mode bits.
// Creates the destination's parent directories as needed.
func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("mkdir for %s: %w", dst, err)
	}
	if err := os.WriteFile(dst, data, info.Mode().Perm()); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return nil
}

// linkMultusIntoK3s symlinks the host multus binary into the k3s
// data dir. No-op when the link already exists; errors are returned
// (not logged-and-swallowed) so ApplyMultusCNI does not mark the
// install complete on a half-finished setup.
func linkMultusIntoK3s() error {
	switch _, err := os.Lstat(MultusLinkTarget); {
	case err == nil:
		return nil // already exists
	case errors.Is(err, os.ErrNotExist):
		// fall through to create
	default:
		return fmt.Errorf("lstat %s: %w", MultusLinkTarget, err)
	}
	if err := os.MkdirAll(filepath.Dir(MultusLinkTarget), 0755); err != nil {
		return fmt.Errorf("mkdir for multus link: %w", err)
	}
	if err := os.Symlink(MultusLinkSource, MultusLinkTarget); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w",
			MultusLinkTarget, MultusLinkSource, err)
	}
	log.Printf("symlinked multus into k3s: %s -> %s",
		MultusLinkTarget, MultusLinkSource)
	return nil
}

// isDHCPRunning scans /proc for the CNI DHCP daemon. argv[0]'s
// basename must equal "dhcp" — substring matching on "dhcp" +
// "daemon" false-positives on dhcpcd/--daemon and other unrelated
// processes.
func isDHCPRunning() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", name, "cmdline"))
		if err != nil {
			continue
		}
		// argv tokens are NUL-separated; the first token is argv[0].
		argv0 := string(cmdline)
		if i := strings.IndexByte(argv0, 0); i >= 0 {
			argv0 = argv0[:i]
		}
		if filepath.Base(argv0) != "dhcp" {
			continue
		}
		// Second arg should be "daemon" — confirm we have the CNI
		// daemon mode, not a one-shot invocation.
		rest := string(cmdline)
		if strings.Contains(rest, "\x00daemon\x00") ||
			strings.HasSuffix(rest, "\x00daemon") {
			return true
		}
	}
	return false
}

func runCommand(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func removeGlob(pattern string) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	for _, m := range matches {
		if err := os.Remove(m); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("warning: remove %s: %v", m, err)
		}
	}
}

// findGlob returns the first match for pattern (alphabetical order
// — sufficient for uniquely-named cert files).
func findGlob(pattern string) (string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no files matching %s", pattern)
	}
	return matches[0], nil
}

// replaceField rewrites the value after fieldPrefix on each
// matching line with newValue, preserving the line's leading
// indent. Used to substitute base64 cert/key data into the admin
// kubeconfig template.
//
// Replaces EVERY line whose trimmed content starts with
// fieldPrefix — callers that need single-line replacement should
// pre-trim or use a more specific anchor.
func replaceField(content, fieldPrefix, newValue string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, fieldPrefix) {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines[i] = indent + fieldPrefix + " " + newValue
	}
	return strings.Join(lines, "\n")
}

// resolveNodeAddress returns the host's IPv4 + cluster prefix by
// reading the default-route interface from `ip route show default`
// and the first IPv4 address from `ip -o -4 addr show dev <iface>`.
//
// In cluster mode the multus manifest is rendered later from the
// EdgeNodeClusterStatus, not from the local default route — so
// this function returns the zero NodeAddress when the rendered
// manifest already exists, signalling the caller that nothing else
// needs to be done.
func resolveNodeAddress() (NodeAddress, error) {
	if marked, mErr := state.IsMarked(state.EdgeNodeClusterMode); mErr != nil {
		return NodeAddress{}, fmt.Errorf("check cluster-mode marker: %w", mErr)
	} else if marked {
		if _, statErr := os.Stat(MultusYAMLDst); statErr == nil {
			return NodeAddress{}, nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return NodeAddress{}, fmt.Errorf("stat %s: %w", MultusYAMLDst, statErr)
		}
	}
	_, ip, err := DefaultInterfaceIPv4()
	if err != nil {
		return NodeAddress{}, err
	}
	return NodeAddress{IP: ip, Prefix: "/32"}, nil
}

// DefaultInterfaceIPv4 returns the name and first IPv4 address of the
// interface carrying the system's default IPv4 route.
//
// Scoped to the main table and resolved lowest-metric-first, which is
// what `ip route show default` reports. EVE also installs a per-port
// default route in a numbered table (see `ip rule`), and a device with
// several uplinks has one default route per uplink — without both the
// table filter and the metric ordering this picks an arbitrary uplink
// and the node IP ends up belonging to the wrong interface.
func DefaultInterfaceIPv4() (iface, ipv4 string, err error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return "", "", fmt.Errorf("list ipv4 routes: %w", err)
	}
	best := pickDefaultRoute(routes)
	if best < 0 {
		return "", "", errors.New("no default IPv4 route in the main table")
	}
	defaultLink, err := netlink.LinkByIndex(routes[best].LinkIndex)
	if err != nil {
		return "", "", fmt.Errorf("lookup default route link %d: %w",
			routes[best].LinkIndex, err)
	}
	name := defaultLink.Attrs().Name
	addrs, err := netlink.AddrList(defaultLink, netlink.FAMILY_V4)
	if err != nil {
		return "", "", fmt.Errorf("list addrs on %s: %w", name, err)
	}
	for _, a := range addrs {
		if a.IP != nil {
			return name, a.IP.String(), nil
		}
	}
	return "", "", fmt.Errorf("no IPv4 address on %s", name)
}

// pickDefaultRoute returns the index of the lowest-metric default route,
// or -1 if none of them is one. Lowest metric is the order `ip route`
// lists them, so a multi-uplink device resolves to the same interface a
// reader of `ip route show default` would expect.
func pickDefaultRoute(routes []netlink.Route) int {
	best := -1
	for i := range routes {
		if !isDefaultDst(routes[i].Dst) {
			continue
		}
		if best < 0 || routes[i].Priority < routes[best].Priority {
			best = i
		}
	}
	return best
}

// isDefaultDst reports whether dst matches every destination. The kernel
// reports a default route's destination as nil or as 0.0.0.0/0 depending
// on how it was installed, so both spellings must be accepted.
func isDefaultDst(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, _ := dst.Mask.Size()
	return ones == 0 && dst.IP.IsUnspecified()
}

// applyLonghornDiskConfig labels + annotates the local node for
// Longhorn's default-disk discovery.
func applyLonghornDiskConfig(ctx context.Context, deviceName string) {
	nodeName := state.ToK8sName(deviceName)
	nodes := kubeclient.Default().Clientset.CoreV1().Nodes()
	disks, err := json.Marshal([]map[string]any{
		{"path": kubectlx.LonghornDefaultDiskPath, "allowScheduling": true},
	})
	if err != nil {
		log.Printf("warning: build longhorn disk-config annotation: %v", err)
		return
	}
	patch, err := kubectlx.BuildMergeLabelPatch(
		map[string]string{"node.longhorn.io/create-default-disk": "config"},
		map[string]string{"node.longhorn.io/default-disks-config": string(disks)},
	)
	if err != nil {
		log.Printf("warning: build longhorn disk-config patch: %v", err)
		return
	}
	if _, err := nodes.Patch(ctx, nodeName,
		types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		log.Printf("warning: label/annotate node for longhorn disk: %v", err)
	}
}

// longhornDaemonSetsReady returns true when every DaemonSet in
// longhorn-system has numberReady == desiredNumberScheduled (and
// neither is 0). At least three DaemonSets are expected.
func longhornDaemonSetsReady(ctx context.Context) bool {
	list, err := kubeclient.Default().Clientset.AppsV1().
		DaemonSets(kubectlx.LonghornNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("warning: list longhorn daemonsets: %v", err)
		return false
	}
	if len(list.Items) < 3 {
		return false
	}
	for _, ds := range list.Items {
		if ds.Status.DesiredNumberScheduled == 0 {
			return false
		}
		if ds.Status.NumberReady != ds.Status.DesiredNumberScheduled {
			return false
		}
	}
	return true
}

// longhornNodeExists reports whether the Longhorn Node object for
// this device exists. Side effect: when missing, attempts to
// create it (the manager won't initialise without one); a create
// failure is logged so a steady-state hot loop in WaitLonghornReady
// is debuggable.
// longhornInstanceManagerRunning reports whether this node has an
// instance-manager in the running state.
//
// Longhorn runs a volume's engine and replica processes inside that pod, so
// storage cannot serve a volume until one exists — yet it is owned by an
// InstanceManager CR rather than a DaemonSet, so the daemonset sweep above
// cannot observe it. Leaving it out let readiness be declared while the pod's
// 442 MB image was still downloading, and the snapshot's k3s stop then
// cancelled that pull.
//
// Longhorn creates the CR eagerly during node setup, not on first volume
// request (verified on-device: the CR is running with no volumes present), so
// waiting for it cannot deadlock against a volume that is itself gated on
// storage readiness.
func longhornInstanceManagerRunning(ctx context.Context) bool {
	list, err := kubeclient.Default().Dynamic.
		Resource(kubectlx.LonghornInstanceManagersGVR).
		Namespace(kubectlx.LonghornNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			log.Printf("warning: list longhorn instancemanagers: %v", err)
		}
		return false
	}
	devName := readDeviceK8sName()
	for i := range list.Items {
		nodeID, _, _ := unstructured.NestedString(list.Items[i].Object, "spec", "nodeID")
		if devName != "" && nodeID != devName {
			continue
		}
		state, _, _ := unstructured.NestedString(list.Items[i].Object, "status", "currentState")
		if state == "running" {
			return true
		}
	}
	return false
}

func longhornNodeExists(ctx context.Context) bool {
	devName := readDeviceK8sName()
	if devName == "" {
		return false
	}
	if _, err := kubeclient.Default().Dynamic.Resource(kubectlx.LonghornNodesGVR).
		Namespace(kubectlx.LonghornNamespace).Get(ctx, devName,
		metav1.GetOptions{}); err != nil {
		if !apierrors.IsNotFound(err) {
			// Any non-NotFound error (auth, timeout, dial failure) is
			// NOT "node missing" — attempting Create on repeat monitor
			// ticks just hammers the API with pointless attempts that
			// will hit the same underlying failure.
			log.Printf("warning: get longhorn node %s: %v", devName, err)
			return false
		}
		log.Printf("longhorn node %s not found, attempting to create", devName)
		if cErr := longhornNodeCreate(ctx, devName); cErr != nil {
			log.Printf("warning: create longhorn node %s: %v", devName, cErr)
		}
		return false
	}
	return true
}

// longhornNodeCreate creates a minimal Longhorn Node object so the
// Longhorn manager can initialise.
func longhornNodeCreate(ctx context.Context, name string) error {
	yaml := fmt.Sprintf(`---
apiVersion: longhorn.io/v1beta2
kind: Node
metadata:
  name: %s
  namespace: longhorn-system
spec:
  allowScheduling: true
  evictionRequested: false
  tags: []
`, name)
	if err := kubectlx.Apply(ctx, kubeclient.Default(),
		[]byte(yaml), kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("apply longhorn node %s: %w", name, err)
	}
	return nil
}

// readDeviceK8sName returns the device name in Kubernetes-node-
// name form, sourced from the EdgeNodeInfo subscription cache.
// Returns "" if the subscription has not delivered yet — callers
// treat "" as "not yet available, try again later".
func readDeviceK8sName() string {
	name := edgenodeinfo.DeviceName()
	if name == "" {
		return ""
	}
	return state.ToK8sName(name)
}

// RestartMultusDaemonSet triggers a rolling restart of the Multus
// DaemonSet, the same way `kubectl rollout restart` does: stamp the pod
// template with kubectl.kubernetes.io/restartedAt so the controller
// sees a changed template and recreates its pods.
//
// Needed because the node IP lives in the Multus ConfigMap (the
// "nodeIP" field of the CNI conf) and the DaemonSet's install container
// writes that conf to /etc/cni/net.d once, at pod start. Re-applying
// the manifest updates the ConfigMap but leaves the on-disk conf — and
// the pod's kubeconfig — as they were, so the pods have to come back.
func RestartMultusDaemonSet(ctx context.Context) error {
	patch := buildRestartPatch(time.Now())
	if _, err := kubeclient.Default().Clientset.AppsV1().
		DaemonSets(multusNamespace).Patch(ctx, multusDaemonSet,
		types.MergePatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("restart %s/%s: %w", multusNamespace, multusDaemonSet, err)
	}
	log.Printf("multus daemonset restart requested")
	return nil
}

// restartedAtAnnotation is the annotation `kubectl rollout restart`
// stamps to force a new pod generation.
const restartedAtAnnotation = "kubectl.kubernetes.io/restartedAt"

// buildRestartPatch builds the merge patch that triggers a rolling
// restart. The annotation must land on spec.template.metadata — the pod
// template — not on the workload's own metadata: only a change to the
// template makes the controller recreate pods.
func buildRestartPatch(now time.Time) []byte {
	return fmt.Appendf(nil,
		`{"spec":{"template":{"metadata":{"annotations":{%q:%q}}}}}`,
		restartedAtAnnotation, now.Format(time.RFC3339))
}

// ingestProbeTimeout bounds one containerd progress probe. Short: the
// probe runs on a poll loop and a hung containerd must not stall it.
const ingestProbeTimeout = 10 * time.Second

// retryTracker counts the BestEffort retry loops still converging after
// DeployAll returns, so the daemon can avoid tearing k3s down on top of
// one. Package-level because the graph is rebuilt per deploy pass while
// the retries outlive it.
var retryTracker = &deploy.RetryTracker{}

// AwaitRetriesQuiescent blocks until no component is still retrying in
// the background, at most for budget. A non-nil error means the budget
// expired and work is still outstanding; callers log it and continue —
// a wedged component must never hold up the state machine.
func AwaitRetriesQuiescent(ctx context.Context, budget time.Duration) error {
	return retryTracker.AwaitQuiescent(ctx, budget)
}

// ingestProgress reports containerd's in-flight ingest volume: bytes
// written into content ingests plus how many are open. It advances
// while an image is downloading — but goes quiet the moment a pull
// moves from download to unpack, which is why it is only half the
// signal.
//
// A fresh connection per probe: containerd is itself restarted during
// bring-up, and a cached client would outlive the daemon it dialled.
func ingestProgress(ctx context.Context) (string, error) {
	cc, err := kubectlx.NewContainerd(ctx, state.ContainerdSocket)
	if err != nil {
		return "", err
	}
	defer func() { _ = cc.Close() }()
	bytes, active, err := cc.ActiveIngestBytes(ctx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ingest=%d/%d", bytes, active), nil
}

// podProgress summarises a namespace's pods: how many exist, how many
// containers are ready, and the total restart count. It changes as pods
// are scheduled, as containers come up one by one, and when one
// crash-loops — covering the unpack and post-pull phases that the
// ingest counter cannot see.
func podProgress(ctx context.Context, namespace string) (string, error) {
	pods, err := kubeclient.Default().Clientset.CoreV1().Pods(namespace).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}
	ready, restarts := 0, 0
	for i := range pods.Items {
		for _, cs := range pods.Items[i].Status.ContainerStatuses {
			if cs.Ready {
				ready++
			}
			restarts += int(cs.RestartCount)
		}
	}
	return fmt.Sprintf("pods=%d ready=%d restarts=%d", len(pods.Items), ready, restarts), nil
}

// componentProgress builds the Progress hook for a component whose work
// lands in one namespace. Either source advancing counts as progress:
// downloads show up in the ingest counter, everything after them —
// unpack, scheduling, containers starting, a crash-loop — shows up in
// the pod summary. Reporting only one of them is what made an earlier
// version of this guard read a busy unpack as a stall.
//
// A failing sub-probe degrades to its error text rather than failing the
// whole token, so containerd being briefly unreachable does not erase
// the Kubernetes-side signal.
func componentProgress(namespace string) deploy.ProgressFunc {
	return func(ctx context.Context) (string, error) {
		probeCtx, cancel := context.WithTimeout(ctx, ingestProbeTimeout)
		defer cancel()

		ing, ingErr := ingestProgress(probeCtx)
		if ingErr != nil {
			ing = "ingest=?"
		}
		pods, podErr := podProgress(probeCtx, namespace)
		if podErr != nil {
			pods = "pods=?"
		}
		if ingErr != nil && podErr != nil {
			return "", fmt.Errorf("progress probe %s: containerd: %v; kubernetes: %w",
				namespace, ingErr, podErr)
		}
		return ing + " " + pods, nil
	}
}
