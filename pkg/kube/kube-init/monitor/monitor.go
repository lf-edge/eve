// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package monitor implements ongoing tasks that run while
// kube-init is in the RUNNING state: cluster-config watch, user-
// override watch, periodic health checks, log rotation, kubeconfig
// sync, and the VNC proxy lifecycle.
//
// All goroutines are cancellable via context and Monitor.Stop().
package monitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/components"
	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/prereqs"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	"github.com/lf-edge/eve/pkg/kube/kube-init/tiebreaker"
	"github.com/lf-edge/eve/pkg/kube/kube-init/vnc"
)

// Per-loop intervals. Vars so tests can shrink them.
var (
	healthCheckInterval  = 15 * time.Second
	clusterPollInterval  = 15 * time.Second
	overridePollInterval = 15 * time.Second
)

// maxLogSize is the rotation threshold for k3s.log and friends.
// 5 MB is empirical: large enough to capture meaningful context
// across a restart, small enough that rotation is cheap on a
// modest persist partition.
const maxLogSize = 5 * 1024 * 1024

// RestartReason describes why the monitor wants the FSM to bounce
// k3s. Type-aliased to int so the FSM's `chan int` accepts these
// values without conversion. Values are aligned with the
// restartReason constants in the daemon entry point.
type RestartReason = int

const (
	// RestartConfigChange — a user override or cluster config changed.
	RestartConfigChange RestartReason = 3
	// RestartFullRecycle — return the FSM to its CONFIGURE_K3S state.
	RestartFullRecycle RestartReason = 4
	// RestartSingleToCluster — run the single → cluster transition.
	RestartSingleToCluster RestartReason = 5
	// RestartClusterToSingle — run the cluster → single transition.
	RestartClusterToSingle RestartReason = 6
)

// Monitor owns the running-state goroutines.
type Monitor struct {
	deviceName      string
	uuid            string
	eveRelease      string
	installKubevirt bool

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	vncMgr *vnc.Manager
}

// New returns a Monitor configured for this device. The
// installKubevirt flag is set at deploy time and never flips
// without an FSM restart — passing it here avoids re-deriving it
// from state on every tick.
func New(deviceName, uuid, eveRelease string, installKubevirt bool) *Monitor {
	return &Monitor{
		deviceName:      deviceName,
		uuid:            uuid,
		eveRelease:      eveRelease,
		installKubevirt: installKubevirt,
		stopCh:          make(chan struct{}),
	}
}

// Start launches the background monitoring goroutines using an
// internal restart channel that logs (but does not propagate)
// restart signals. Use StartWithRestartCh when the caller wants
// restart signals routed to the FSM.
func (m *Monitor) Start(ctx context.Context) {
	internal := make(chan RestartReason, 1)
	m.startInternal(ctx, internal)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			case reason := <-internal:
				log.Printf("k3s restart signalled by monitor (reason=%d, no external listener)",
					reason)
			}
		}
	}()
}

// StartWithRestartCh launches the monitoring goroutines AND
// forwards restart signals to externalCh. The send is
// non-blocking so a restart already in flight (channel full)
// suppresses the duplicate signal — the FSM picks up the pending
// one when it drains.
func (m *Monitor) StartWithRestartCh(ctx context.Context, externalCh chan<- RestartReason) {
	bridge := make(chan RestartReason, 1)
	m.startInternal(ctx, bridge)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			case reason := <-bridge:
				log.Printf("k3s restart signalled by monitor (reason=%d), forwarding",
					reason)
				select {
				case externalCh <- reason:
				default:
					log.Printf("external restart channel full, restart already pending")
				}
			}
		}
	}()
}

// startInternal wires the core monitoring goroutines.
func (m *Monitor) startInternal(ctx context.Context, restartCh chan<- RestartReason) {
	log.Printf("starting monitor goroutines (device=%s)", m.deviceName)
	m.spawn(ctx, func(c context.Context) { m.monitorClusterConfigLoop(c, restartCh) })
	m.spawn(ctx, func(c context.Context) { m.monitorUserOverridesLoop(c, restartCh) })
	m.spawn(ctx, m.logRotationLoop)
	m.spawn(ctx, m.kubeconfigSyncLoop)

	m.vncMgr = vnc.NewManager()
	m.spawn(ctx, func(c context.Context) { m.vncMgr.Run(c) })
}

// spawn runs fn under a context that cancels when EITHER the
// parent ctx is done OR the monitor is Stop()ed.
func (m *Monitor) spawn(parent context.Context, fn func(context.Context)) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		merged, cancel := m.mergeCtx(parent)
		defer cancel()
		fn(merged)
	}()
}

// Stop closes the stop channel and waits for every spawned
// goroutine to return.
func (m *Monitor) Stop() {
	m.stopOnce.Do(func() {
		log.Printf("stopping monitor")
		close(m.stopCh)
	})
	m.wg.Wait()
	log.Printf("monitor stopped")
}

// mergeCtx returns a context cancelled when either parent or
// m.stopCh fires. The bridging goroutine is tracked under m.wg so
// Stop()+Wait observes a clean drain.
func (m *Monitor) mergeCtx(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		select {
		case <-m.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// ---------------------------------------------------------------------------
// Periodic health checks
// ---------------------------------------------------------------------------

// RunHealthChecks runs the per-tick housekeeping.
//
// Ordering matters: fast restart-critical housekeeping FIRST so a
// slow image-import pass can't delay network-plane recovery. A
// post-restart first tick must not leave the DHCP daemon, multus,
// or CNI plugins missing for ~60s while it re-imports tarballs.
func (m *Monitor) RunHealthChecks(ctx context.Context) {
	// --- 1. Fast restart-critical housekeeping ---
	m.ensureDHCPRunning()
	m.copyCNIPluginsIfNeeded()

	multusMarked, err := state.IsMarked(state.MultusInitialized)
	if err != nil {
		log.Printf("warning: check multus marker: %v", err)
	} else if !multusMarked {
		rendered := true
		if _, err := os.Stat(components.MultusYAMLDst); errors.Is(err, os.ErrNotExist) {
			if err := m.assignMultusNodeIP(); err != nil {
				log.Printf("warning: render multus manifest: %v", err)
				rendered = false
			}
		}
		// Skip applyMultus when render failed: applying a stale
		// or missing manifest would just produce a more confusing
		// kubectl error on top of the render failure.
		if rendered {
			m.applyMultus()
		}
	}
	m.checkForMultusLinkRequest()

	labelsMarked, err := state.IsMarked(state.NodeLabelsInitialized)
	if err != nil {
		log.Printf("warning: check node-labels marker: %v", err)
	} else if !labelsMarked {
		m.reapplyNodeLabels()
	}

	m.ensureDebugUser()
	SyncKubeconfig()

	// --- 2. Potentially slow work ---
	m.reimportImages()

	longhornMarked, err := state.IsMarked(state.LonghornInitialized)
	if err != nil {
		log.Printf("warning: check longhorn marker: %v", err)
	} else if longhornMarked {
		ready, err := components.LonghornIsReady(ctx)
		if err != nil {
			log.Printf("warning: longhorn readiness check: %v", err)
		} else if !ready {
			log.Printf("longhorn not ready this tick; skipping nsmounter overwrite")
		} else {
			components.CheckOverwriteNsmounter(ctx)
		}
	}

	if m.installKubevirt {
		migrated, err := state.IsMarked(state.KubevirtFeatureGatesMigrated)
		if err != nil {
			log.Printf("warning: check kubevirt feature-gate marker: %v", err)
		} else if !migrated {
			if err := components.MigrateKubeVirtFeatureGates(ctx); err != nil {
				log.Printf("warning: kubevirt feature-gate migration: %v", err)
			}
		}
	}

	clusterMode, err := k3s.IsClusterMode()
	if err != nil {
		log.Printf("warning: check cluster-mode marker: %v", err)
	} else if clusterMode {
		if err := tiebreaker.ConfigApply(ctx, m.uuid); err != nil {
			log.Printf("warning: tie-breaker config apply: %v", err)
		}
	}
}

// CheckContainerd verifies the user-containerd socket is still
// present. Image-import operations target this socket via
// ctr/crictl; a missing socket silently fails those calls. Logs
// a warning rather than acting — the supervisor owns recovery.
func (m *Monitor) CheckContainerd() {
	if _, err := os.Stat(state.ContainerdSocket); err != nil {
		log.Printf("WARNING: containerd watchdog: socket %s not present: %v",
			state.ContainerdSocket, err)
	}
}

// ---------------------------------------------------------------------------
// Cluster-config + user-override watchers
// ---------------------------------------------------------------------------

// ClusterConfig polls the EdgeNodeClusterStatus file and
// detects single ↔ cluster transitions. On a detected edge it
// sends a RestartReason on restartCh and continues polling; the
// FSM owns the actual transition runner.
func ClusterConfig(ctx context.Context, restartCh chan<- RestartReason) error {
	log.Printf("cluster config monitor started")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		allInitialized, err := state.IsMarked(state.AllComponentsInitialized)
		if err != nil {
			// Don't proceed: a transient marker-read failure here
			// would otherwise paralyse the cluster-config watcher.
			// Log and retry next tick.
			log.Printf("warning: check all-components marker, retrying next tick: %v",
				err)
			sleepCtx(ctx, clusterPollInterval)
			continue
		}
		if !allInitialized {
			sleepCtx(ctx, clusterPollInterval)
			continue
		}

		_, statErr := os.Stat(k3s.EncStatusFile)
		encExists := statErr == nil
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			log.Printf("warning: stat %s: %v", k3s.EncStatusFile, statErr)
			sleepCtx(ctx, clusterPollInterval)
			continue
		}

		inClusterMode, err := state.IsMarked(state.EdgeNodeClusterMode)
		if err != nil {
			// Don't proceed: a stale marker read could otherwise
			// mis-fire RestartSingleToCluster if encExists is true
			// while the (real) cluster-mode marker is set but
			// unreadable.
			log.Printf("warning: check cluster-mode marker, retrying next tick: %v",
				err)
			sleepCtx(ctx, clusterPollInterval)
			continue
		}

		switch {
		case !encExists && inClusterMode:
			// EdgeNodeClusterStatus withdrawn while we were in
			// cluster mode → controller revoked the cluster.
			// Unmark cluster mode before signalling so subsequent
			// polls don't re-fire the same edge forever — the FSM
			// owns the actual transition, and our marker should
			// reflect "no longer in cluster mode" immediately.
			log.Printf("EdgeNodeClusterStatus missing while in cluster mode — " +
				"signalling cluster→single transition")
			if err := state.Unmark(state.EdgeNodeClusterMode); err != nil {
				log.Printf("warning: unmark cluster mode: %v", err)
			}
			trySend(restartCh, RestartClusterToSingle, "cluster→single")
		case encExists && !inClusterMode:
			// EdgeNodeClusterStatus appeared → joining cluster.
			// Mark cluster mode immediately so we don't re-fire
			// the edge on every poll while the FSM is still
			// running the transition.
			log.Printf("EdgeNodeClusterStatus found, node not in cluster mode — " +
				"signalling single→cluster transition")
			if err := state.Mark(state.EdgeNodeClusterMode); err != nil {
				log.Printf("warning: mark cluster mode: %v", err)
			}
			trySend(restartCh, RestartSingleToCluster, "single→cluster")
		case encExists && inClusterMode:
			// Joining-in-progress retry handled in transition.go.
			CheckClusterTransitionDone(ctx)
		}
		sleepCtx(ctx, clusterPollInterval)
	}
}

// trySend posts reason on ch if the channel has space; otherwise
// logs that a restart is already pending and drops the duplicate.
func trySend(ch chan<- RestartReason, reason RestartReason, label string) {
	select {
	case ch <- reason:
		log.Printf("signalled %s transition", label)
	default:
		log.Printf("restart channel full, %s transition already pending", label)
	}
}

// UserOverrides polls k3s.UserOverrideSrc and signals a
// restart when the file content changes. The actual sync work
// lives in k3s.ApplyUserOverrides; this loop just detects
// "something changed".
func UserOverrides(ctx context.Context, restartCh chan<- RestartReason) {
	log.Printf("user overrides monitor started")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if applyUserOverride() {
			trySend(restartCh, RestartConfigChange, "user-override")
		}
		sleepCtx(ctx, overridePollInterval)
	}
}

// applyUserOverride wraps k3s.ApplyUserOverrides and reports
// whether the on-disk drop-in changed.
func applyUserOverride() bool {
	changed, err := k3s.ApplyUserOverrides()
	if err != nil {
		log.Printf("warning: apply user overrides: %v", err)
		return false
	}
	return changed
}

// ---------------------------------------------------------------------------
// Log rotation
// ---------------------------------------------------------------------------

// RotateLogs rotates each known log file if it exceeds maxLogSize,
// then prunes excess raft logs.
func RotateLogs() {
	for _, name := range []string{
		"k3s.log",
		"multus.log",
		"eve-bridge.log",
		"containerd-user.log",
	} {
		rotateLogFile(name)
	}
	CleanExcessiveK3sLogs()
}

// rotateLogFile rotates path → path.1 → path.2 → path.3 when
// path exceeds maxLogSize. For k3s.log specifically, SIGHUP is
// sent to the k3s server BEFORE truncation so it releases its fd.
func rotateLogFile(name string) {
	path := filepath.Join(prereqs.KubeLogDir, name)
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Size() <= maxLogSize {
		return
	}

	for i := 2; i >= 0; i-- {
		var src string
		if i == 0 {
			src = path
		} else {
			src = fmt.Sprintf("%s.%d", path, i)
		}
		dst := fmt.Sprintf("%s.%d", path, i+1)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if i == 0 {
			// k3s still has the active log open; copy rather
			// than rename so the fd remains valid. Stream via
			// io.Copy so we never allocate the full file
			// content (maxLogSize is 5 MB today but the cap
			// could grow).
			if err := streamCopy(src, dst); err != nil {
				log.Printf("warning: rotate-copy %s → %s: %v", src, dst, err)
			}
		} else if err := os.Rename(src, dst); err != nil {
			log.Printf("warning: rotate %s → %s: %v", src, dst, err)
		}
	}

	if name == "k3s.log" {
		sendSIGHUPToK3s()
	}
	if err := os.Truncate(path, 0); err != nil {
		log.Printf("warning: truncate %s: %v", path, err)
		return
	}
	log.Printf("rotated log file %s (was %d bytes)", name, info.Size())
}

// sendSIGHUPToK3s scans /proc for `k3s server` and signals it so
// it releases the log file before we truncate. Best-effort.
//
// Match is path-agnostic: argv[0] basename == "k3s" AND argv[1] ==
// "server". The earlier hard-coded prefix list (/usr/bin/k3s,
// /var/lib/k3s/bin/k3s) missed e.g. /usr/local/bin/k3s. PID
// recycling between scan and Kill is harmless — a SIGHUP to a
// fresh k3s just rotates again.
func sendSIGHUPToK3s() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isNumeric(entry.Name()) {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		// argv tokens are NUL-separated; argv[0] is the binary
		// path and argv[1] is the subcommand.
		argv := strings.Split(string(cmdline), "\x00")
		if len(argv) < 2 || filepath.Base(argv[0]) != "k3s" || argv[1] != "server" {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if sErr := syscall.Kill(pid, syscall.SIGHUP); sErr != nil {
			log.Printf("warning: SIGHUP to k3s pid %d: %v", pid, sErr)
			continue
		}
		log.Printf("sent SIGHUP to k3s server pid %d before log truncation", pid)
	}
}

// ---------------------------------------------------------------------------
// Kubeconfig sync
// ---------------------------------------------------------------------------

// SyncKubeconfig mirrors state.K3sKubeconfig into k3s.KubeconfigCopy
// when the source has changed. Other components (registration,
// debug-user) consume the copy from /run instead of reaching into
// /etc/rancher.
func SyncKubeconfig() {
	srcData, err := os.ReadFile(state.K3sKubeconfig)
	if err != nil {
		return
	}
	if dstData, _ := os.ReadFile(k3s.KubeconfigCopy); string(dstData) == string(srcData) {
		return
	}
	if err := os.MkdirAll(filepath.Dir(k3s.KubeconfigCopy), 0755); err != nil {
		log.Printf("warning: mkdir for kubeconfig sync: %v", err)
		return
	}
	if err := os.WriteFile(k3s.KubeconfigCopy, srcData, 0600); err != nil {
		log.Printf("warning: kubeconfig sync failed: %v", err)
		return
	}
	log.Printf("synced kubeconfig %s → %s",
		state.K3sKubeconfig, k3s.KubeconfigCopy)
}

// ---------------------------------------------------------------------------
// Internal goroutine wrappers
// ---------------------------------------------------------------------------

func (m *Monitor) monitorClusterConfigLoop(ctx context.Context, restartCh chan<- RestartReason) {
	if err := ClusterConfig(ctx, restartCh); err != nil {
		if ctx.Err() == nil {
			log.Printf("cluster config monitor error: %v", err)
		}
	}
}

func (m *Monitor) monitorUserOverridesLoop(ctx context.Context, restartCh chan<- RestartReason) {
	UserOverrides(ctx, restartCh)
}

func (m *Monitor) logRotationLoop(ctx context.Context) {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			RotateLogs()
		}
	}
}

func (m *Monitor) kubeconfigSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			SyncKubeconfig()
		}
	}
}

// ---------------------------------------------------------------------------
// Per-tick housekeeping helpers
// ---------------------------------------------------------------------------

// reapplyNodeLabels re-stamps the node-uuid label, the longhorn
// disk-config label, and the longhorn default-disks-config
// annotation. Marks NodeLabelsInitialized only after every piece
// has been verified to actually exist on the node.
//
// We verify the annotation separately from the labels because an
// annotation can fail silently (e.g. validating webhook strips it)
// while the kubectl exit code reports success — without an explicit
// annotation check we'd otherwise mark the node as initialized and
// never re-stamp.
//
// Verification matches the node name exactly so a different node
// whose name contains m.deviceName as a substring cannot false-
// positive.
func (m *Monitor) reapplyNodeLabels() {
	if m.uuid == "" {
		// Without a UUID we can't apply or verify the
		// node-uuid label. The labels initialised flag stays
		// unset and the FSM/health tick will retry once uuid
		// is populated.
		log.Printf("reapply node labels: device UUID not yet available, skipping")
		return
	}
	if _, err := kubectlx.Run("label", "node", m.deviceName,
		"node-uuid="+m.uuid, "--overwrite"); err != nil {
		log.Printf("warning: reapply node-uuid label: %v", err)
		return
	}
	if _, err := kubectlx.Run("label", "node", m.deviceName,
		"node.longhorn.io/create-default-disk=config", "--overwrite"); err != nil {
		log.Printf("warning: reapply longhorn disk label: %v", err)
		return
	}
	if _, err := kubectlx.Run("annotate", "node", m.deviceName,
		`node.longhorn.io/default-disks-config=[ { "path":"/persist/vault/volumes", "allowScheduling":true }]`,
		"--overwrite"); err != nil {
		log.Printf("warning: reapply longhorn disk annotation: %v", err)
		return
	}

	// Label verification: tagged `kubectl get nodes` must return
	// our node name.
	out, err := kubectlx.Run("get", "nodes",
		"-l", "node-uuid="+m.uuid+",node.longhorn.io/create-default-disk=config",
		"-o", "jsonpath={.items[*].metadata.name}")
	labelMatched := false
	if err == nil {
		for _, name := range strings.Fields(out) {
			if name == m.deviceName {
				labelMatched = true
				break
			}
		}
	}
	if !labelMatched {
		log.Printf("node labels verification failed for %s", m.deviceName)
		return
	}

	// Annotation verification: the value isn't pre-parsed by
	// kubectl, so a non-empty jsonpath result means the
	// annotation was persisted.
	annot, err := kubectlx.Run("get", "node", m.deviceName,
		"-o", `jsonpath={.metadata.annotations.node\.longhorn\.io/default-disks-config}`)
	if err != nil || strings.TrimSpace(annot) == "" {
		log.Printf("node annotation verification failed for %s (err=%v, value=%q)",
			m.deviceName, err, annot)
		return
	}

	log.Printf("node labels + annotation re-applied successfully")
	if err := state.Mark(state.NodeLabelsInitialized); err != nil {
		log.Printf("warning: mark node-labels initialized: %v", err)
	}
}

// reimportImages re-imports the EVE-authored external-boot-image
// tarball on restart if it is somehow no longer present in
// containerd. Most calls are a no-op (the crictl pre-check finds
// the image already there); the import only fires when the image
// has genuinely gone missing (e.g. after a containerd reset).
//
// RT image re-imports are intentionally not handled in this
// package; they belong with the RT-specific code path.
func (m *Monitor) reimportImages() {
	if !m.installKubevirt {
		return
	}
	m.importImageIfNeeded(
		"/images/external-boot-image.tar",
		"docker.io/lfedge/eve-external-boot-image",
		m.eveRelease,
	)
}

// importImageIfNeeded imports tarPath into the user-containerd
// only when the expected image tag is not already present in the
// kubelet-visible namespace. Consulting containerd directly makes
// this idempotent across restarts without a persistent marker.
func (m *Monitor) importImageIfNeeded(tarPath, imageName, tag string) {
	fullRef := imageName + ":" + tag
	if out, err := kubectlx.CrictlRun("inspecti", fullRef); err == nil && len(out) > 0 {
		return
	}
	if _, err := os.Stat(tarPath); errors.Is(err, os.ErrNotExist) {
		return
	}
	if _, err := kubectlx.CtrRun("images", "import", tarPath); err != nil {
		log.Printf("warning: image import %s failed: %v", tarPath, err)
		return
	}
	log.Printf("imported image from %s", tarPath)
}

// assignMultusNodeIP regenerates the multus DaemonSet template
// with the local node's IP prefix. Used during a recovery tick
// when the rendered manifest is missing.
//
// Returns an error so the caller can skip the apply step when
// rendering failed — applying a missing or stale manifest would
// produce confusing kubectl errors on top of the render failure.
func (m *Monitor) assignMultusNodeIP() error {
	defaultIf, ok := readDefaultInterface()
	if !ok {
		return errors.New("no default route interface")
	}
	ip, ok := readFirstIPv4(defaultIf)
	if !ok {
		return fmt.Errorf("no IPv4 on %s", defaultIf)
	}
	tmpl, err := os.ReadFile(components.MultusYAMLSrc)
	if err != nil {
		return fmt.Errorf("read multus template %s: %w",
			components.MultusYAMLSrc, err)
	}
	rendered := strings.ReplaceAll(string(tmpl),
		"IPAddressReplaceMe", ip+"/32")
	if err := os.WriteFile(components.MultusYAMLDst,
		[]byte(rendered), 0644); err != nil {
		return fmt.Errorf("write rendered multus %s: %w",
			components.MultusYAMLDst, err)
	}
	return nil
}

// readDefaultInterface returns the default-route interface name
// from `ip route show default`. (false, "") on any failure.
func readDefaultInterface() (string, bool) {
	out, err := runCmd("ip", "route", "show", "default")
	if err != nil {
		return "", false
	}
	fields := strings.Fields(strings.TrimSpace(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], true
		}
	}
	return "", false
}

// readFirstIPv4 returns the first IPv4 address on iface from
// `ip -o -4 addr show dev <iface>`. (false, "") on any failure.
func readFirstIPv4(iface string) (string, bool) {
	out, err := runCmd("ip", "-o", "-4", "addr", "show", "dev", iface)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "inet" && i+1 < len(fields) {
				if ip := strings.SplitN(fields[i+1], "/", 2)[0]; ip != "" {
					return ip, true
				}
			}
		}
	}
	return "", false
}

// applyMultus re-applies the rendered multus DaemonSet and
// touches the initialization marker on success.
func (m *Monitor) applyMultus() {
	if _, err := kubectlx.Run("get", "namespace", "eve-kube-app"); err != nil {
		if _, cErr := kubectlx.Run("create", "namespace", "eve-kube-app"); cErr != nil {
			log.Printf("warning: create eve-kube-app namespace: %v", cErr)
			return
		}
	}
	if _, err := kubectlx.Run("apply", "-f", components.MultusYAMLDst); err != nil {
		log.Printf("warning: apply multus: %v", err)
		return
	}
	if err := linkMultusIntoK3s(); err != nil {
		log.Printf("warning: link multus into k3s: %v", err)
		return
	}
	if err := state.Mark(state.MultusInitialized); err != nil {
		log.Printf("warning: mark multus initialized: %v", err)
		return
	}
	log.Printf("multus re-applied and initialized")
}

// checkForMultusLinkRequest honours an out-of-band "retouch the
// multus link" request file written by cluster-mode transitions.
func (m *Monitor) checkForMultusLinkRequest() {
	const requestFile = "/var/lib/request-retouch-multus"
	if _, err := os.Stat(requestFile); err != nil {
		return
	}
	if err := os.Remove(requestFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("warning: remove %s: %v", requestFile, err)
	}
	if err := linkMultusIntoK3s(); err != nil {
		log.Printf("warning: link multus into k3s: %v", err)
	}
}

// ensureDHCPRunning starts the CNI DHCP daemon when it has died
// between ticks. Steady-state recovery for the CNI DHCP daemon.
func (m *Monitor) ensureDHCPRunning() {
	if isDHCPRunning() {
		return
	}
	if _, err := os.Stat(components.DHCPSocket); err == nil {
		if err := os.Remove(components.DHCPSocket); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("warning: remove stale DHCP socket: %v", err)
		}
	}
	cmd := exec.Command(components.DHCPBinary, "daemon")
	if err := cmd.Start(); err != nil {
		log.Printf("warning: start DHCP daemon: %v", err)
		return
	}
	pid := cmd.Process.Pid
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("DHCP daemon (pid %d) exited: %v", pid, err)
		}
	}()
	log.Printf("DHCP daemon started (pid %d)", pid)
}

// copyCNIPluginsIfNeeded recopies CNI plugins into the legacy +
// modern bin dirs when either is empty. The kube container's
// /usr is restored from the read-only image layer on every
// restart, so the bin dirs can disappear unexpectedly.
func (m *Monitor) copyCNIPluginsIfNeeded() {
	if dirExists(prereqs.CNIBinDir) && dirExists(prereqs.OptCNIDir) {
		return
	}
	for _, dir := range []string{prereqs.CNIBinDir, prereqs.OptCNIDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("warning: mkdir %s: %v", dir, err)
			return
		}
	}
	entries, err := os.ReadDir(prereqs.CNISrcDir)
	if err != nil {
		log.Printf("warning: read CNI src %s: %v", prereqs.CNISrcDir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(prereqs.CNISrcDir, e.Name())
		data, err := os.ReadFile(src)
		if err != nil {
			log.Printf("warning: read CNI plugin %s: %v", src, err)
			continue
		}
		for _, dst := range []string{
			filepath.Join(prereqs.CNIBinDir, e.Name()),
			filepath.Join(prereqs.OptCNIDir, e.Name()),
		} {
			if err := os.WriteFile(dst, data, 0755); err != nil {
				log.Printf("warning: copy CNI plugin %s: %v", dst, err)
			}
		}
	}
	if data, err := os.ReadFile("/usr/bin/eve-bridge"); err == nil {
		for _, dst := range []string{
			filepath.Join(prereqs.CNIBinDir, "eve-bridge"),
			filepath.Join(prereqs.OptCNIDir, "eve-bridge"),
		} {
			if err := os.WriteFile(dst, data, 0755); err != nil {
				log.Printf("warning: copy eve-bridge to %s: %v", dst, err)
			}
		}
	}
	log.Printf("CNI plugins copied")
}

// ensureDebugUser keeps the /run copy of the debug user
// kubeconfig in sync with the persistent copy. Steady-state
// mirror only — initial cert generation is the FSM's
// responsibility.
func (m *Monitor) ensureDebugUser() {
	marked, err := state.IsMarked(state.DebugUserInitialized)
	if err != nil {
		log.Printf("warning: check debug-user marker: %v", err)
		return
	}
	if !marked {
		return
	}
	if _, err := os.Stat(components.RunUserYaml); err == nil {
		return
	}
	data, err := os.ReadFile(components.K3sUserYaml)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(components.RunUserYaml), 0755); err != nil {
		log.Printf("warning: mkdir for run user.yaml: %v", err)
		return
	}
	if err := os.WriteFile(components.RunUserYaml, data, 0600); err != nil {
		log.Printf("warning: copy user.yaml to run: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// streamCopy copies src → dst byte-by-byte through a 32 KiB buffer
// without allocating the full source into memory.
func streamCopy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy %s → %s: %w", src, dst, err)
	}
	return nil
}

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// linkMultusIntoK3s creates the multus symlink in the k3s data
// dir when missing. Returns nil when the link is already correct.
// Non-ENOENT errors are surfaced so a half-finished state doesn't
// silently look like a successful no-op.
func linkMultusIntoK3s() error {
	switch _, err := os.Lstat(components.MultusLinkTarget); {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrNotExist):
	default:
		return fmt.Errorf("lstat %s: %w", components.MultusLinkTarget, err)
	}
	if err := os.MkdirAll(filepath.Dir(components.MultusLinkTarget), 0755); err != nil {
		return fmt.Errorf("mkdir for multus link: %w", err)
	}
	if err := os.Symlink(components.MultusLinkSource, components.MultusLinkTarget); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w",
			components.MultusLinkTarget, components.MultusLinkSource, err)
	}
	return nil
}

// isDHCPRunning scans /proc for argv[0]=="dhcp" with "daemon" as
// a subsequent argv token. Tight basename match avoids false
// positives on dhcpcd/--daemon and similar.
func isDHCPRunning() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isNumeric(entry.Name()) {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		argv0 := string(cmdline)
		if i := strings.IndexByte(argv0, 0); i >= 0 {
			argv0 = argv0[:i]
		}
		if filepath.Base(argv0) != "dhcp" {
			continue
		}
		full := string(cmdline)
		if strings.Contains(full, "\x00daemon\x00") ||
			strings.HasSuffix(full, "\x00daemon") {
			return true
		}
	}
	return false
}

func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// sleepCtx is a select-ctx-or-timer helper. Equivalent to a
// time.After plus a ctx.Done in a single call.
func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
