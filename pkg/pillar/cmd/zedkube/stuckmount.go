// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// stuckMountThreshold is how long a pod must sit Pending with an attached
	// but unmounted volume before we treat it as a kubelet mount wedge. Node
	// staging normally completes in seconds, so minutes means wedged.
	stuckMountThreshold = 5 * time.Minute
	// stuckMountMaxRecover caps recovery attempts within one wedge episode;
	// reset once a tick observes no wedged pod. The count lives in memory, so
	// it bounds restarts only within one pillar lifetime: a reboot re-arms the
	// detector and a pod that is Pending for a reason a fresh kubelet cannot
	// fix earns a new episode on every boot.
	stuckMountMaxRecover = 3
	// stuckMountSuppressWindow is the cooldown after a recovery attempt, so the
	// detector cannot thrash a k3s restart faster than kubelet can recover.
	stuckMountSuppressWindow = 15 * time.Minute
	// stuckMountDevPath is where the Longhorn CSI node plugin materializes the
	// block device once the volume is attached to this node.
	stuckMountDevPath = "/dev/longhorn"
	// stuckMountRecoveryMarker is a distinctive, greppable string emitted on
	// every recovery so operators can spot mount-wedge restarts in the logs.
	stuckMountRecoveryMarker = "MOUNT-WEDGE-RECOVERY"
	// procRootDir is where the host PID namespace's process list is mounted.
	procRootDir = "/proc"
	// k3sSupervisorTimeout bounds both the connect and the reply on the
	// supervisor socket. A restart request is answered as soon as it is accepted,
	// not once k3s is back, so this only has to cover the handshake.
	k3sSupervisorTimeout = 10 * time.Second
)

var (
	// stuckMountDryRun gates the recovery action. When true the detector only
	// logs what it would do and takes NO action; when false it restarts k3s to
	// give kubelet a fresh volume manager.
	stuckMountDryRun = false
	// stuckMountK3sStartFlag is the manual-start flag of the cluster-init.sh
	// shell supervisor, which runs k3s on the stable branches. Touching it
	// resets that supervisor's exponential restart backoff so k3s is relaunched
	// promptly after we terminate it. It lives on the /run bind shared with the
	// kube container. Nothing in this tree reads it — here the kube-init daemon
	// supervises k3s — so it matters only where the SIGTERM path below is live.
	stuckMountK3sStartFlag = "/run/kube/k3s-start"
	// k3sSupervisorSocket is the kube-init daemon's control socket, which accepts
	// a "restart" verb. Present only on images where that daemon replaced
	// cluster-init.sh; its absence is what selects the SIGTERM path below.
	k3sSupervisorSocket = "/run/k3s-supervisor.sock"
	// The cluster and host lookups the wedge signature and the recovery action
	// depend on, indirected so tests can drive both without a live cluster and
	// without signaling a real k3s. Overridden only in tests.
	pvcGet                   = kubeapi.PVCGet
	volumeAttachmentAttached = kubeapi.GetVolumeAttachmentAttached
	devicePresent            = longhornDevicePresent
	signalK3s                = signalK3sServer
)

// checkStuckVolumeMount detects the kubelet volume-mount wedge: a pod scheduled
// on this node sits Pending past stuckMountThreshold with no container-level
// error, yet at least one of its Longhorn PVCs is attached to this node
// (VolumeAttachment reports Attached and /dev/longhorn/<pv> exists) — meaning
// attach succeeded but kubelet never issued NodeStage, so the pod never starts.
// Longhorn, CDI and image pull are not at fault; the stall is in kubelet's
// volume manager, and only a fresh kubelet clears it.
//
// Recovery (see recoverKubeletMountWedge) restarts k3s so kubelet comes back
// with a fresh volume manager, rate-limited by stuckMountMaxRecover and
// stuckMountSuppressWindow. Set stuckMountDryRun to disable the action and only
// log.
func (z *zedkube) checkStuckVolumeMount() {
	if z.nodeName == "" {
		return
	}
	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("checkStuckVolumeMount: get clientset: %v", err)
		return
	}
	z.checkStuckVolumeMountWithClient(clientset, time.Now())
}

// checkStuckVolumeMountWithClient is the body of one detector tick: it collects
// the wedged pods this node currently has and, subject to the per-episode
// attempt cap and cooldown, triggers recovery. now is passed in so the episode
// rate limiting is exercisable without a wall clock.
func (z *zedkube) checkStuckVolumeMountWithClient(clientset kubernetes.Interface, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()
	// Restrict the LIST server-side: only Pending pods on this node can exhibit
	// the wedge, and a multi-node cluster's other nodes are none of our business.
	pods, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + z.nodeName +
			",status.phase=" + string(corev1.PodPending),
	})
	if err != nil {
		log.Errorf("checkStuckVolumeMount: list pods: %v", err)
		return
	}

	var wedged []string
	for i := range pods.Items {
		if desc, ok := z.podMountWedge(pods.Items[i], now); ok {
			wedged = append(wedged, desc)
		}
	}

	if len(wedged) == 0 {
		z.stuckMountRecoverCount = 0
		return
	}

	if now.Before(z.stuckMountSuppressUntil) {
		log.Functionf("checkStuckVolumeMount: %d wedged pod(s); recovery in cooldown until %v: %s",
			len(wedged), z.stuckMountSuppressUntil, strings.Join(wedged, "; "))
		return
	}
	if z.stuckMountRecoverCount >= stuckMountMaxRecover {
		log.Errorf("checkStuckVolumeMount: %d wedged pod(s) after %d recovery attempts; giving up until they clear: %s",
			len(wedged), stuckMountMaxRecover, strings.Join(wedged, "; "))
		return
	}

	z.stuckMountRecoverCount++
	z.stuckMountSuppressUntil = now.Add(stuckMountSuppressWindow)
	z.recoverKubeletMountWedge(wedged)
}

// podMountWedge reports whether pod p on this node exhibits the mount wedge and,
// if so, returns a human-readable description. It matches a Pending, non-
// terminating pod aged past stuckMountThreshold that has no container- or
// init-container error (image pull / crashloop are excluded as different
// failures) and at least one Longhorn PVC that is attached to this node yet
// still unmounted.
func (z *zedkube) podMountWedge(p corev1.Pod, now time.Time) (string, bool) {
	if p.Spec.NodeName != z.nodeName {
		return "", false
	}
	if p.Status.Phase != corev1.PodPending || isPodTerminating(p) {
		return "", false
	}
	if podHasContainerError(p) || podHasInitContainerError(p) {
		return "", false
	}
	age := now.Sub(p.CreationTimestamp.Time)
	if age < stuckMountThreshold {
		return "", false
	}
	for _, vol := range p.Spec.Volumes {
		if vol.PersistentVolumeClaim == nil {
			continue
		}
		pvc, err := pvcGet(vol.PersistentVolumeClaim.ClaimName, log)
		if err != nil || pvc.Spec.VolumeName == "" {
			continue
		}
		pvName := pvc.Spec.VolumeName
		// devicePresent is a local stat while volumeAttachmentAttached lists
		// every VolumeAttachment in the cluster, and this runs on every tick,
		// so let the cheap check reject the volume first.
		if !devicePresent(pvName) {
			continue
		}
		attached, err := volumeAttachmentAttached(pvName, z.nodeName, log)
		if err != nil || !attached {
			continue
		}
		return fmt.Sprintf("pod=%s pv=%s attached+device-present but unmounted, Pending %v",
			p.Name, pvName, age.Round(time.Second)), true
	}
	return "", false
}

// longhornDevicePresent reports whether the Longhorn block device for pvName
// exists on this node, i.e. the volume is attached at the node level.
func longhornDevicePresent(pvName string) bool {
	_, err := os.Stat(stuckMountDevPath + "/" + pvName)
	return err == nil
}

// podHasInitContainerError mirrors podHasContainerError over init containers:
// true if any init container is waiting on an error reason (image pull /
// create / run) or terminated non-zero. Used to exclude image-pull failures
// (e.g. a boot-image init container) from the mount-wedge signature.
func podHasInitContainerError(p corev1.Pod) bool {
	for _, cs := range p.Status.InitContainerStatuses {
		if w := cs.State.Waiting; w != nil {
			switch w.Reason {
			case "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull",
				"CreateContainerError", "CreateContainerConfigError", "RunContainerError":
				return true
			}
		}
		if t := cs.State.Terminated; t != nil && t.ExitCode != 0 {
			return true
		}
	}
	return false
}

// recoverKubeletMountWedge is the recovery action for the mount wedge. The only
// known remedy is a fresh kubelet, which means restarting k3s. Every attempt logs
// a distinctive marker so a restart is easy to spot in the device logs. While
// stuckMountDryRun is true it takes NO action and only logs.
//
// Which restart mechanism is available depends on what supervises k3s on this
// image, so it is chosen at run time by restartK3s.
func (z *zedkube) recoverKubeletMountWedge(wedged []string) {
	detail := strings.Join(wedged, "; ")
	if stuckMountDryRun {
		log.Noticef("%s: DRY-RUN would restart kubelet/k3s to clear the volume-mount wedge (attempt %d/%d): %s",
			stuckMountRecoveryMarker, z.stuckMountRecoverCount, stuckMountMaxRecover, detail)
		return
	}

	log.Warnf("%s: restarting kubelet/k3s to clear the volume-mount wedge (attempt %d/%d): %s",
		stuckMountRecoveryMarker, z.stuckMountRecoverCount, stuckMountMaxRecover, detail)

	how, err := restartK3s()
	if err != nil {
		log.Errorf("%s: attempt %d/%d FAILED to restart k3s via %s: %v; wedge: %s",
			stuckMountRecoveryMarker, z.stuckMountRecoverCount, stuckMountMaxRecover,
			how, err, detail)
		return
	}
	log.Warnf("%s: requested a k3s restart via %s; attempt %d/%d, wedge: %s",
		stuckMountRecoveryMarker, how, z.stuckMountRecoverCount, stuckMountMaxRecover, detail)
}

// restartK3s asks whatever supervises k3s on this image to restart it, and
// returns which mechanism it used.
//
// The kube-init daemon accepts a "restart" on its control socket and runs its own
// pre-restart hooks, so it is preferred whenever that socket is present. Images
// built from the stable branches, where the cluster-init.sh shell supervisor runs
// k3s, have no socket; there the only lever is to terminate the process and let
// that supervisor relaunch it. Detecting per attempt rather than once at start-up
// keeps a single pillar binary correct on both, including across an upgrade that
// swaps the supervisor underneath it.
func restartK3s() (string, error) {
	if _, err := os.Stat(k3sSupervisorSocket); err == nil {
		return "supervisor socket", restartK3sViaSupervisor(k3sSupervisorSocket)
	}
	return "SIGTERM", restartK3sViaSignal()
}

// restartK3sViaSupervisor speaks kube-init's control-socket protocol: write the
// verb, then read the reply until EOF. The daemon answers a single line, and
// prefixes it with ERR when the request failed.
func restartK3sViaSupervisor(socketPath string) error {
	conn, err := net.DialTimeout("unix", socketPath, k3sSupervisorTimeout)
	if err != nil {
		return fmt.Errorf("dial %s: %w", socketPath, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(k3sSupervisorTimeout)); err != nil {
		return fmt.Errorf("set deadline on %s: %w", socketPath, err)
	}
	if _, err := fmt.Fprintln(conn, "restart"); err != nil {
		return fmt.Errorf("write %s: %w", socketPath, err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("read %s: %w", socketPath, err)
	}
	last := ""
	for _, line := range strings.Split(strings.TrimRight(string(reply), "\n"), "\n") {
		if line != "" {
			last = line
		}
	}
	if last == "" {
		return fmt.Errorf("no reply from %s", socketPath)
	}
	if strings.HasPrefix(last, "ERR") {
		return fmt.Errorf("supervisor refused: %s", last)
	}
	log.Noticef("%s: supervisor replied %q", stuckMountRecoveryMarker, last)
	return nil
}

// restartK3sViaSignal is the cluster-init.sh path: reset the supervisor's
// exponential restart backoff so k3s comes back promptly rather than after a
// multi-minute wait, then SIGTERM it. pillar runs in the host PID namespace and
// shares the /run bind with the kube container, so it can do both.
func restartK3sViaSignal() error {
	if err := os.MkdirAll(filepath.Dir(stuckMountK3sStartFlag), 0755); err != nil {
		log.Errorf("%s: cannot create %s dir: %v", stuckMountRecoveryMarker, stuckMountK3sStartFlag, err)
	} else if f, err := os.Create(stuckMountK3sStartFlag); err != nil {
		log.Errorf("%s: cannot touch %s: %v", stuckMountRecoveryMarker, stuckMountK3sStartFlag, err)
	} else {
		f.Close()
	}

	pids, err := signalK3s()
	if err != nil {
		return fmt.Errorf("enumerate k3s: %w", err)
	}
	if len(pids) == 0 {
		return fmt.Errorf("no 'k3s server' process to signal")
	}
	log.Noticef("%s: sent SIGTERM to k3s server pid(s) %v; the supervisor relaunches it",
		stuckMountRecoveryMarker, pids)
	return nil
}

// signalK3sServer sends SIGTERM to every running "k3s server" process and
// returns the PIDs signaled. zedkube shares the host PID namespace, so the k3s
// process started in the kube container is visible and signalable here; the
// cluster-init.sh supervisor relaunches k3s once it exits, yielding a fresh
// kubelet volume manager. A PID whose signal fails is left out of the returned
// set, so an empty return means nothing was actually terminated.
func signalK3sServer() ([]int, error) {
	pids, err := k3sServerPids(procRootDir)
	if err != nil {
		return nil, err
	}
	var signaled []int
	for _, pid := range pids {
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			log.Errorf("%s: SIGTERM pid %d failed: %v", stuckMountRecoveryMarker, pid, err)
			continue
		}
		signaled = append(signaled, pid)
	}
	return signaled, nil
}

// k3sServerPids returns the PIDs of the "k3s server" processes visible under
// procRoot. A process that disappears mid-scan, or whose cmdline is unreadable,
// is skipped; only an unreadable procRoot is an error.
func k3sServerPids(procRoot string) ([]int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
		}
		raw, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "cmdline"))
		if err != nil {
			continue // process gone or unreadable
		}
		if !isK3sServerCmdline(raw) {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// isK3sServerCmdline reports whether a raw /proc/<pid>/cmdline belongs to the
// k3s server process.
//
// k3s rewrites its process title to the single string "k3s server", so cmdline
// is one NUL-terminated token "k3s server" rather than the separate
// "k3s"/"server" argv elements exec would leave. Tokenizing the whole cmdline on
// whitespace therefore matches both that retitled form and a path-launched
// "<dir>/k3s server ...", while excluding a shell that merely mentions the
// string in a later argument (its first token is the shell).
func isK3sServerCmdline(raw []byte) bool {
	cmdline := strings.ReplaceAll(strings.TrimRight(string(raw), "\x00"), "\x00", " ")
	fields := strings.Fields(cmdline)
	return len(fields) >= 2 && filepath.Base(fields[0]) == "k3s" && fields[1] == "server"
}
