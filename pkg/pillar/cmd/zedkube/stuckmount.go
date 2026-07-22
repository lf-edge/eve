// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// stuckMountThreshold is how long a pod must sit Pending with an attached
	// but unmounted volume before we treat it as a kubelet mount wedge. Node
	// staging normally completes in seconds, so minutes means wedged.
	stuckMountThreshold = 5 * time.Minute
	// stuckMountMaxRecover caps recovery attempts within one wedge episode;
	// reset once a tick observes no wedged pod.
	stuckMountMaxRecover = 3
	// stuckMountSuppressWindow is the cooldown after a recovery attempt, so the
	// detector cannot thrash a k3s restart faster than kubelet can recover.
	stuckMountSuppressWindow = 15 * time.Minute
	// stuckMountDevPath is where the Longhorn CSI node plugin materializes the
	// block device once the volume is attached to this node.
	stuckMountDevPath = "/dev/longhorn"
	// stuckMountDryRun gates the recovery action. When true the detector only
	// logs what it would do and takes NO action; when false it restarts k3s to
	// give kubelet a fresh volume manager.
	stuckMountDryRun = false
	// stuckMountK3sStartFlag is cluster-init.sh's manual-start flag
	// (K3S_MANUAL_START_FLAG in cluster-utils.sh). Touching it resets the
	// supervisor's exponential restart backoff so k3s is relaunched promptly
	// after we terminate it. It lives on the /run bind shared with the kube
	// container.
	stuckMountK3sStartFlag = "/run/kube/k3s-start"
	// stuckMountRecoveryMarker is a distinctive, greppable string emitted on
	// every recovery so operators can spot mount-wedge restarts in the logs.
	stuckMountRecoveryMarker = "MOUNT-WEDGE-RECOVERY"
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
	ctx, cancel := context.WithTimeout(context.Background(), kubeAPITimeout)
	defer cancel()
	pods, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Errorf("checkStuckVolumeMount: list pods: %v", err)
		return
	}

	now := time.Now()
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
		pvc, err := kubeapi.PVCGet(vol.PersistentVolumeClaim.ClaimName, log)
		if err != nil || pvc.Spec.VolumeName == "" {
			continue
		}
		pvName := pvc.Spec.VolumeName
		attached, err := kubeapi.GetVolumeAttachmentAttached(pvName, z.nodeName, log)
		if err != nil || !attached {
			continue
		}
		if !longhornDevicePresent(pvName) {
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
// known remedy is a fresh kubelet, which we get by terminating k3s and letting
// cluster-init.sh's supervisor relaunch it. Because pillar runs in the host PID
// namespace and shares the /run bind with the kube container, zedkube can both
// reset the supervisor's restart backoff (touch K3S_MANUAL_START_FLAG) and send
// SIGTERM to the k3s server process directly. Every attempt logs a distinctive
// marker so a restart is easy to spot in the device logs. While stuckMountDryRun
// is true it takes NO action and only logs.
func (z *zedkube) recoverKubeletMountWedge(wedged []string) {
	detail := strings.Join(wedged, "; ")
	if stuckMountDryRun {
		log.Noticef("%s: DRY-RUN would restart kubelet/k3s to clear the volume-mount wedge (attempt %d/%d): %s",
			stuckMountRecoveryMarker, z.stuckMountRecoverCount, stuckMountMaxRecover, detail)
		return
	}

	log.Warnf("%s: restarting kubelet/k3s to clear the volume-mount wedge (attempt %d/%d): %s",
		stuckMountRecoveryMarker, z.stuckMountRecoverCount, stuckMountMaxRecover, detail)

	// Reset the supervisor's exponential restart backoff so k3s is relaunched
	// promptly rather than after a multi-minute wait.
	if err := os.MkdirAll(filepath.Dir(stuckMountK3sStartFlag), 0755); err != nil {
		log.Errorf("%s: cannot create %s dir: %v", stuckMountRecoveryMarker, stuckMountK3sStartFlag, err)
	} else if f, err := os.Create(stuckMountK3sStartFlag); err != nil {
		log.Errorf("%s: cannot touch %s: %v", stuckMountRecoveryMarker, stuckMountK3sStartFlag, err)
	} else {
		f.Close()
	}

	pids, err := signalK3sServer()
	if err != nil {
		log.Errorf("%s: attempt %d/%d FAILED to enumerate k3s: %v; wedge: %s",
			stuckMountRecoveryMarker, z.stuckMountRecoverCount, stuckMountMaxRecover, err, detail)
		return
	}
	if len(pids) == 0 {
		log.Errorf("%s: attempt %d/%d found no 'k3s server' process to signal; wedge: %s",
			stuckMountRecoveryMarker, z.stuckMountRecoverCount, stuckMountMaxRecover, detail)
		return
	}
	log.Warnf("%s: sent SIGTERM to k3s server pid(s) %v; cluster-init.sh will relaunch. attempt %d/%d, wedge: %s",
		stuckMountRecoveryMarker, pids, z.stuckMountRecoverCount, stuckMountMaxRecover, detail)
}

// signalK3sServer sends SIGTERM to every running "k3s server" process and
// returns the PIDs signaled. zedkube shares the host PID namespace, so the k3s
// process started in the kube container is visible and signalable here; the
// cluster-init.sh supervisor relaunches k3s once it exits, yielding a fresh
// kubelet volume manager.
//
// k3s rewrites its process title to the single string "k3s server", so
// /proc/<pid>/cmdline is one NUL-terminated token "k3s server" rather than the
// separate "k3s"/"server" argv elements exec would leave. We therefore tokenize
// the whole cmdline on whitespace and match basename(fields[0])=="k3s" &&
// fields[1]=="server" — this matches both that retitled form and a
// path-launched "<dir>/k3s server ...", while excluding a shell that merely
// mentions the string in a later argument (its fields[0] is the shell).
func signalK3sServer() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var signaled []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
		}
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue // process gone or unreadable
		}
		cmdline := strings.ReplaceAll(strings.TrimRight(string(raw), "\x00"), "\x00", " ")
		fields := strings.Fields(cmdline)
		if len(fields) < 2 || filepath.Base(fields[0]) != "k3s" || fields[1] != "server" {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			log.Errorf("%s: SIGTERM pid %d failed: %v", stuckMountRecoveryMarker, pid, err)
			continue
		}
		signaled = append(signaled, pid)
	}
	return signaled, nil
}
