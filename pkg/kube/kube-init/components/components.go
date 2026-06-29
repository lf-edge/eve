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
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/deploy"
	"github.com/lf-edge/eve/pkg/kube/kube-init/edgenodeinfo"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// Component manifest paths, baked into the container image at build
// time.
const (
	debugRoleBinding  = "/etc/debuguser-role-binding.yaml"
	kubevirtOperator  = "/etc/kubevirt-operator.yaml"
	kubevirtFeatures  = "/etc/kubevirt-features.yaml"
	longhornCfg       = "/etc/lh-cfg-v1.9.1.yaml"
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

	kubevirtCRURL = "https://github.com/kubevirt/kubevirt/releases/download/v1.7.3/kubevirt-cr.yaml"
	cdiVersion    = "v1.57.1"

	longhornWaitTimeout = 10 * time.Minute

	nvidiaVendorDir = "/opt/vendor/nvidia"

	// KubeVirt readiness identities.
	kubevirtNamespace             = "kubevirt"
	kubevirtOperatorDeployment    = "virt-operator"
	kubevirtCRName                = "kubevirt"
	kubevirtOperatorWaitTimeout   = 5 * time.Minute
	kubevirtCRDeployedWaitTimeout = 10 * time.Minute

	// CDI readiness identities.
	cdiNamespace             = "cdi"
	cdiOperatorDeployment    = "cdi-operator"
	cdiCRName                = "cdi"
	cdiOperatorWaitTimeout   = 5 * time.Minute
	cdiCRDeployedWaitTimeout = 10 * time.Minute

	// Longhorn install lives in its own namespace; every kubectl
	// call against it passes this via -n.
	longhornNamespace = "longhorn-system"
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
// Dependency rationale: nodes are mutually independent except for
// `longhorn` depending on `manifests` — Longhorn's PVC controller
// needs storage-classes.yaml in the k3s auto-deploy dir before its
// first reconcile, otherwise it races against an empty StorageClass
// list. Everything else can run concurrently.
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
// MaxParallel=0 (unbounded). If we observe API-server pressure on
// real hardware we can cap without touching Deps edges. The k3s
// API server handles a handful of concurrent applies fine;
// kubectlx.ClassifyKubectlErr backs off transient discovery races.
//
// AllComponentsInitialized / NodeLabelsInitialized are deliberately
// NOT written here — the caller writes them after the post-deploy
// SaveVarLib completes so "marker present" unambiguously implies a
// complete /var/lib snapshot too.
func DeployAll(ctx context.Context, deviceName string, installKubevirt bool) error {
	log.Printf("starting component deployment (device=%s, kubevirt=%v)",
		deviceName, installKubevirt)

	// Resolve node IP up front so the Multus closure captures concrete
	// values; a network misconfig fails fast before any kubectl runs.
	addr, err := resolveNodeAddress()
	if err != nil {
		return fmt.Errorf("resolve node IP: %w", err)
	}

	// Pre-create the eve-kube-app namespace BEFORE the graph runs.
	// The shell version got this for free because its components ran
	// sequentially and multus (which creates the namespace as a side
	// effect) happened first. Our parallel DAG runs multus and
	// debug-rbac in the same wave; debug-rbac's RoleBinding targets
	// eve-kube-app and would race-fail with "namespace not found" if
	// multus hadn't created it yet. Hoisting the creation eliminates
	// the race — every graph node can assume the namespace exists.
	if err := ensureEveKubeAppNamespace(); err != nil {
		return fmt.Errorf("ensure eve-kube-app namespace: %w", err)
	}

	g := buildDeployGraph(deviceName, addr, installKubevirt)
	if err := g.Run(ctx); err != nil {
		return err
	}
	log.Printf("all components initialized")
	return nil
}

// ensureEveKubeAppNamespace creates the eve-kube-app namespace if
// it does not already exist. Idempotent. The namespace hosts EVE
// app instance workloads and is referenced by the multus
// NetworkAttachmentDefinition and the debug-user RoleBinding.
func ensureEveKubeAppNamespace() error {
	if _, err := kubectl("get", "namespace", "eve-kube-app"); err == nil {
		return nil
	}
	if _, err := kubectl("create", "namespace", "eve-kube-app"); err != nil {
		return fmt.Errorf("create namespace: %w", err)
	}
	log.Printf("created namespace eve-kube-app")
	return nil
}

// buildDeployGraph constructs the deploy.Graph used by DeployAll.
// Extracted so the wiring (Deps edges + conditional inclusion of
// kubevirt/cdi) can be unit-tested without invoking installers.
func buildDeployGraph(deviceName string, addr NodeAddress, installKubevirt bool) deploy.Graph {
	g := deploy.Graph{
		Nodes: []deploy.Node{
			{
				Name:  "multus",
				Apply: func(c context.Context) error { return ApplyMultusCNI(c, addr) },
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
				// BestEffort with the full 10-min wait timeout — Apply
				// still runs synchronously and writes
				// state.LonghornInitialized, but WaitReady is
				// downgraded so the rest of the deploy (and the
				// FSM's transition to RUNNING) doesn't block on
				// Longhorn's CR convergence. runHealthWorker's
				// LonghornPostInstallConfig gates its work on
				// Longhorn_is_ready, so steady-state ticks
				// reconcile any apply that hasn't converged yet.
				Name:                       "longhorn",
				Deps:                       []string{"manifests"},
				Apply:                      func(c context.Context) error { return InstallLonghorn(c, deviceName) },
				WaitReady:                  WaitLonghornReady,
				BestEffort:                 true,
				BestEffortWaitReadyTimeout: longhornWaitTimeout,
			},
			{
				Name:  "descheduler",
				Apply: InstallDescheduler,
			},
		},
	}
	if installKubevirt {
		g.Nodes = append(g.Nodes,
			deploy.Node{
				Name:                       "kubevirt",
				Apply:                      InstallKubeVirt,
				WaitReady:                  WaitKubeVirtReady,
				BestEffort:                 true,
				BestEffortWaitReadyTimeout: kubevirtCRDeployedWaitTimeout,
			},
			deploy.Node{
				Name:                       "cdi",
				Apply:                      InstallCDI,
				WaitReady:                  WaitCDIReady,
				BestEffort:                 true,
				BestEffortWaitReadyTimeout: cdiCRDeployedWaitTimeout,
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

	log.Printf("installing KubeVirt operator")
	if err := kubectlx.ApplyWithBackoff(ctx, kubevirtOperator, kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("apply kubevirt operator: %w", err)
	}

	// Wait for virt-operator before applying the CR — the operator
	// owns the KubeVirt CRD admission webhook; applying the CR
	// before the operator is Ready races both.
	if err := kubectlx.WaitDeploymentReady(ctx, kubevirtNamespace,
		kubevirtOperatorDeployment, kubevirtOperatorWaitTimeout); err != nil {
		return fmt.Errorf("wait virt-operator ready: %w", err)
	}

	log.Printf("applying KubeVirt CR")
	if err := kubectlx.ApplyWithBackoff(ctx, kubevirtCRURL, kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("apply kubevirt CR: %w", err)
	}

	// Replica patch is best-effort — the CR controller may still be
	// starting; the next steady-state tick will reconcile.
	if err := kubeVirtConfigReplicas(3); err != nil {
		log.Printf("warning: KubeVirt replica count patch: %v", err)
	}

	log.Printf("applying KubeVirt feature gates")
	if err := kubectlx.ApplyWithBackoff(ctx, kubevirtFeatures, kubectlx.ApplyOptions{}); err != nil {
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
	return kubectlx.WaitForCondition(ctx,
		"kubevirt", kubevirtNamespace, kubevirtCRName,
		"{.status.phase}", "Deployed",
		kubevirtCRDeployedWaitTimeout)
}

// kubeVirtConfigReplicas patches virt-operator Deployment replicas
// and KubeVirt CR infra.replicas in one shot.
func kubeVirtConfigReplicas(replicas int) error {
	log.Printf("setting virt-operator and KubeVirt infra replicas to %d", replicas)
	deployPatch := fmt.Sprintf(`{"spec":{"replicas": %d}}`, replicas)
	if _, err := kubectl("patch", "deployment", "virt-operator",
		"-n", kubevirtNamespace, "--patch", deployPatch); err != nil {
		return fmt.Errorf("patch virt-operator deployment: %w", err)
	}
	crPatch := fmt.Sprintf(`{"spec":{"infra":{"replicas": %d}}}`, replicas)
	if _, err := kubectl("patch", "KubeVirt", "kubevirt",
		"-n", kubevirtNamespace, "--type=merge", "--patch", crPatch); err != nil {
		return fmt.Errorf("patch KubeVirt CR infra.replicas: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// CDI
// ---------------------------------------------------------------------------

// InstallCDI applies the CDI operator, waits for the operator
// Deployment to roll out, then applies the CR. The post-CR
// phase=Deployed gate lives in WaitCDIReady.
func InstallCDI(ctx context.Context) error {
	cdiOperatorURL := fmt.Sprintf(
		"https://github.com/kubevirt/containerized-data-importer/releases/download/%s/cdi-operator.yaml",
		cdiVersion)
	cdiCRURL := fmt.Sprintf(
		"https://github.com/kubevirt/containerized-data-importer/releases/download/%s/cdi-cr.yaml",
		cdiVersion)

	log.Printf("installing CDI %s", cdiVersion)
	if err := kubectlx.ApplyWithBackoff(ctx, cdiOperatorURL, kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("apply CDI operator: %w", err)
	}
	if err := kubectlx.WaitDeploymentReady(ctx, cdiNamespace,
		cdiOperatorDeployment, cdiOperatorWaitTimeout); err != nil {
		return fmt.Errorf("wait cdi-operator ready: %w", err)
	}
	if err := kubectlx.ApplyWithBackoff(ctx, cdiCRURL, kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("apply CDI CR: %w", err)
	}
	log.Printf("CDI installation complete")
	return nil
}

// WaitCDIReady blocks until the CDI CR reports phase=Deployed.
func WaitCDIReady(ctx context.Context) error {
	return kubectlx.WaitForCondition(ctx,
		"cdi", "", cdiCRName,
		"{.status.phase}", "Deployed",
		cdiCRDeployedWaitTimeout)
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
	applyLonghornDiskConfig(deviceName)

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

// WaitLonghornReady polls for DaemonSet readiness + Longhorn node
// object existence; times out after longhornWaitTimeout.
func WaitLonghornReady(ctx context.Context) error {
	log.Printf("waiting for Longhorn readiness (timeout %v)", longhornWaitTimeout)
	deadline := time.Now().Add(longhornWaitTimeout)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for Longhorn readiness after %v",
				longhornWaitTimeout)
		}
		if longhornDaemonSetsReady() && longhornNodeExists() {
			log.Printf("Longhorn is ready")
			return nil
		}
		log.Printf("Longhorn not yet ready, rechecking in 10s")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
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

// kubectl is the package-local wrapper around kubectlx.Run.
func kubectl(args ...string) (string, error) {
	return kubectlx.Run(args...)
}

// kubectlApply runs `kubectl apply -f <file>` with the kubectlx
// backoff/classification wrapper. The retry loop is REQUIRED for
// manifests that combine a CRD and a custom resource of that CRD
// in the same file (e.g. multus-daemonset.yaml ships a
// NetworkAttachmentDefinition CRD plus a NAD instance): kubectl's
// API-discovery cache is built at process start, so the first
// apply creates the CRD but errors on the CR with "no matches for
// kind". ApplyWithBackoff classifies that as Transient and retries
// after backoff, by which point the CRD is established.
//
// Defaults (kubectlx.ApplyOptions{}): 10 attempts, 1-30 s backoff,
// 60 s per-attempt timeout. The caller's ctx still bounds the
// total wall-clock.
func kubectlApply(ctx context.Context, yamlFile string) error {
	return kubectlx.ApplyWithBackoff(ctx, yamlFile, kubectlx.ApplyOptions{})
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
	defaultIf, err := readDefaultInterface()
	if err != nil {
		return NodeAddress{}, err
	}
	ip, err := readInterfaceIPv4(defaultIf)
	if err != nil {
		return NodeAddress{}, err
	}
	return NodeAddress{IP: ip, Prefix: "/32"}, nil
}

// readDefaultInterface parses `ip route show default` output and
// returns the device name after the "dev" token.
func readDefaultInterface() (string, error) {
	out, err := runCommand("ip", "route", "show", "default")
	if err != nil {
		return "", fmt.Errorf("discover default interface: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no default route interface found")
}

// readInterfaceIPv4 returns the first IPv4 address (no CIDR suffix)
// reported by `ip -o -4 addr show dev <iface>`.
func readInterfaceIPv4(iface string) (string, error) {
	out, err := runCommand("ip", "-o", "-4", "addr", "show", "dev", iface)
	if err != nil {
		return "", fmt.Errorf("discover node IP: %w", err)
	}
	if ip := parseFirstIPv4(out); ip != "" {
		return ip, nil
	}
	return "", fmt.Errorf("no IP address on interface %s", iface)
}

// parseFirstIPv4 extracts the first `inet <ip>/<mask>` value from
// `ip -o -4 addr show` output and returns the IP without the mask.
// Returns "" if no IPv4 address is present.
func parseFirstIPv4(ipAddrOutput string) string {
	for _, line := range strings.Split(ipAddrOutput, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "inet" && i+1 < len(fields) {
				return strings.SplitN(fields[i+1], "/", 2)[0]
			}
		}
	}
	return ""
}

// applyLonghornDiskConfig labels + annotates the local node for
// Longhorn's default-disk discovery.
func applyLonghornDiskConfig(deviceName string) {
	nodeName := state.ToK8sName(deviceName)
	if _, err := kubectl("label", "node", nodeName,
		"node.longhorn.io/create-default-disk=config", "--overwrite"); err != nil {
		log.Printf("warning: label node for longhorn disk: %v", err)
	}
	if _, err := kubectl("annotate", "node", nodeName,
		`node.longhorn.io/default-disks-config=[ { "path":"/persist/vault/volumes", "allowScheduling":true }]`,
		"--overwrite"); err != nil {
		log.Printf("warning: annotate node for longhorn disk: %v", err)
	}
}

// longhornDaemonSetsReady returns true when every DaemonSet in
// longhorn-system has numberReady == desiredNumberScheduled (and
// neither is 0). At least three DaemonSets are expected.
func longhornDaemonSetsReady() bool {
	out, err := kubectl("get", "daemonsets", "-n", longhornNamespace,
		"-o", `jsonpath={range .items[*]}{.status.numberReady},{.status.desiredNumberScheduled}{"\n"}{end}`)
	if err != nil {
		return false
	}
	return parseLonghornDSReady(out)
}

// parseLonghornDSReady is the pure half of longhornDaemonSetsReady,
// factored out so the parsing logic is testable without a cluster.
func parseLonghornDSReady(jsonpathOutput string) bool {
	lines := strings.Split(strings.TrimSpace(jsonpathOutput), "\n")
	if len(lines) < 3 {
		return false
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 || parts[0] != parts[1] || parts[0] == "0" {
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
func longhornNodeExists() bool {
	devName := readDeviceK8sName()
	if devName == "" {
		return false
	}
	if _, err := kubectl("get", "nodes.longhorn.io", devName,
		"-n", longhornNamespace); err != nil {
		log.Printf("longhorn node %s not found, attempting to create", devName)
		if cErr := longhornNodeCreate(devName); cErr != nil {
			log.Printf("warning: create longhorn node %s: %v", devName, cErr)
		}
		return false
	}
	return true
}

// longhornNodeCreate creates a minimal Longhorn Node object so the
// Longhorn manager can initialise. Returns the kubectl error
// (including the trimmed stderr) on failure.
func longhornNodeCreate(name string) error {
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
	cmd := kubectlx.Cmd("apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yaml)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply longhorn node %s: %w (output: %s)",
			name, err, strings.TrimSpace(string(out)))
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
