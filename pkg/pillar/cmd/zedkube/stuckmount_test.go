// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// stuckMountFakes drives the cluster and host lookups the detector makes.
// claims binds a PVC name to its PV; attachedPVs and presentPVs are the PVs
// this node reports as attached and as having a /dev/longhorn device.
type stuckMountFakes struct {
	claims      map[string]string
	attachedPVs map[string]bool
	presentPVs  map[string]bool
	pvcErr      map[string]error
	attachErr   map[string]error

	signalPids  []int
	signalErr   error
	signalCalls int

	flagPath string
}

// installStuckMountFakes points the detector's lookups at f and its k3s-start
// flag at a temporary path, restoring the real ones when the test ends.
func installStuckMountFakes(t *testing.T, f *stuckMountFakes) {
	t.Helper()
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-zedkube", 0)

	origPVCGet, origAttached := pvcGet, volumeAttachmentAttached
	origDevice, origSignal := devicePresent, signalK3s
	origFlag, origDryRun := stuckMountK3sStartFlag, stuckMountDryRun
	t.Cleanup(func() {
		pvcGet, volumeAttachmentAttached = origPVCGet, origAttached
		devicePresent, signalK3s = origDevice, origSignal
		stuckMountK3sStartFlag, stuckMountDryRun = origFlag, origDryRun
	})

	f.flagPath = filepath.Join(t.TempDir(), "kube", "k3s-start")
	stuckMountK3sStartFlag = f.flagPath

	pvcGet = func(pvcName string, _ *base.LogObject) (*corev1.PersistentVolumeClaim, error) {
		if err := f.pvcErr[pvcName]; err != nil {
			return nil, err
		}
		return &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: pvcName},
			Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: f.claims[pvcName]},
		}, nil
	}
	volumeAttachmentAttached = func(pvName, nodeName string, _ *base.LogObject) (bool, error) {
		if err := f.attachErr[pvName]; err != nil {
			return false, err
		}
		return f.attachedPVs[pvName] && nodeName == testNodeName, nil
	}
	devicePresent = func(pvName string) bool { return f.presentPVs[pvName] }
	signalK3s = func() ([]int, error) {
		f.signalCalls++
		return f.signalPids, f.signalErr
	}
}

// wedgeFakes is the all-green setup: pvc-a is bound to pv-a, which is attached
// to this node and has its device present, so a stale Pending pod referencing
// pvc-a is wedged.
func wedgeFakes(t *testing.T) *stuckMountFakes {
	t.Helper()
	f := &stuckMountFakes{
		claims:      map[string]string{"pvc-a": "pv-a"},
		attachedPVs: map[string]bool{"pv-a": true},
		presentPVs:  map[string]bool{"pv-a": true},
		signalPids:  []int{4242},
	}
	installStuckMountFakes(t, f)
	return f
}

// pendingPod builds a Pending pod on this node, created age ago relative to now,
// referencing the named PVCs.
func pendingPod(name string, now time.Time, age time.Duration, claims ...string) corev1.Pod {
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         kubeapi.EVEKubeNameSpace,
			CreationTimestamp: metav1.NewTime(now.Add(-age)),
		},
		Spec:   corev1.PodSpec{NodeName: testNodeName},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}
	for i, claim := range claims {
		p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{
			Name: "vol" + string(rune('a'+i)),
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim},
			},
		})
	}
	return p
}

func waitingPod(p corev1.Pod, reason string) corev1.Pod {
	p.Status.ContainerStatuses = []corev1.ContainerStatus{
		{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason}}},
	}
	return p
}

func waitingInitPod(p corev1.Pod, reason string) corev1.Pod {
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{
		{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason}}},
	}
	return p
}

func TestIsK3sServerCmdline(t *testing.T) {
	tests := []struct {
		name    string
		cmdline string
		want    bool
	}{
		// k3s rewrites its process title to one string, so the whole cmdline
		// arrives as a single NUL-terminated token.
		{"retitled single token", "k3s server\x00", true},
		{"argv form with flags", "k3s\x00server\x00--flannel-backend=none\x00", true},
		{"path launched retitled", "/var/lib/rancher/k3s/data/abc/bin/k3s server\x00", true},
		{"path launched argv", "/usr/bin/k3s\x00server\x00", true},
		{"no trailing NUL", "k3s server", true},
		// A shell that merely mentions the string must not be signaled.
		{"shell mentioning k3s server", "/bin/sh\x00-c\x00k3s server\x00", false},
		{"eve-k cluster-init wrapper", "/bin/sh\x00/usr/bin/cluster-init.sh\x00", false},
		{"k3s agent", "k3s\x00agent\x00", false},
		{"k3s alone", "k3s\x00", false},
		{"killall script", "k3s-killall.sh\x00", false},
		{"basename must be exact", "k3ss\x00server\x00", false},
		{"other binary", "kubelet\x00--config\x00", false},
		{"kernel thread empty cmdline", "", false},
		{"only NULs", "\x00\x00", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isK3sServerCmdline([]byte(tc.cmdline)))
		})
	}
}

func TestK3sServerPids(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-zedkube", 0)
	procRoot := t.TempDir()

	write := func(dir, cmdline string) {
		t.Helper()
		assert.NoError(t, os.MkdirAll(filepath.Join(procRoot, dir), 0755))
		assert.NoError(t, os.WriteFile(filepath.Join(procRoot, dir, "cmdline"), []byte(cmdline), 0644))
	}
	write("123", "k3s\x00server\x00--foo\x00")
	write("456", "/var/lib/rancher/k3s/data/abc/bin/k3s server\x00")
	write("789", "/bin/sh\x00-c\x00k3s server\x00")
	// Non-numeric entries are not processes, even when their cmdline matches.
	write("self", "k3s server\x00")
	// A process that exited between the readdir and the read has no cmdline.
	assert.NoError(t, os.MkdirAll(filepath.Join(procRoot, "999"), 0755))
	// Plain files at the top of /proc (uptime, meminfo, …) are not PIDs.
	assert.NoError(t, os.WriteFile(filepath.Join(procRoot, "uptime"), []byte("1 1"), 0644))

	pids, err := k3sServerPids(procRoot)
	assert.NoError(t, err)
	assert.Equal(t, []int{123, 456}, pids)

	_, err = k3sServerPids(filepath.Join(procRoot, "no-such-dir"))
	assert.Error(t, err)
}

func TestPodHasInitContainerError(t *testing.T) {
	mk := func(state corev1.ContainerState) corev1.Pod {
		return corev1.Pod{Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{{State: state}},
		}}
	}
	waiting := func(reason string) corev1.ContainerState {
		return corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason}}
	}

	tests := []struct {
		name string
		pod  corev1.Pod
		want bool
	}{
		{"CrashLoopBackOff", mk(waiting("CrashLoopBackOff")), true},
		{"ImagePullBackOff", mk(waiting("ImagePullBackOff")), true},
		{"ErrImagePull", mk(waiting("ErrImagePull")), true},
		{"CreateContainerError", mk(waiting("CreateContainerError")), true},
		{"CreateContainerConfigError", mk(waiting("CreateContainerConfigError")), true},
		{"RunContainerError", mk(waiting("RunContainerError")), true},
		// A normally-progressing init container is not an error.
		{"PodInitializing", mk(waiting("PodInitializing")), false},
		{"ContainerCreating", mk(waiting("ContainerCreating")), false},
		{"empty reason", mk(waiting("")), false},
		{"running", mk(corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}), false},
		{"terminated ok", mk(corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}), false},
		{"terminated non-zero", mk(corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{ExitCode: 1}}), true},
		{"no init containers", corev1.Pod{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, podHasInitContainerError(tc.pod))
		})
	}
}

func TestPodMountWedge(t *testing.T) {
	now := time.Now()
	stale := 2 * stuckMountThreshold

	tests := []struct {
		name    string
		pod     func(*stuckMountFakes) corev1.Pod
		mutate  func(*stuckMountFakes)
		want    bool
		wantPV  string
		wantPod string
	}{
		{
			name:    "attached, device present, stale Pending",
			pod:     func(*stuckMountFakes) corev1.Pod { return pendingPod("cdi-upload", now, stale, "pvc-a") },
			want:    true,
			wantPV:  "pv-a",
			wantPod: "cdi-upload",
		},
		{
			name: "pod on another node",
			pod: func(*stuckMountFakes) corev1.Pod {
				p := pendingPod("elsewhere", now, stale, "pvc-a")
				p.Spec.NodeName = "other-node"
				return p
			},
		},
		{
			name: "pod not yet scheduled",
			pod: func(*stuckMountFakes) corev1.Pod {
				p := pendingPod("unscheduled", now, stale, "pvc-a")
				p.Spec.NodeName = ""
				return p
			},
		},
		{
			name: "pod already Running",
			pod: func(*stuckMountFakes) corev1.Pod {
				p := pendingPod("running", now, stale, "pvc-a")
				p.Status.Phase = corev1.PodRunning
				return p
			},
		},
		{
			name: "pod terminating",
			pod: func(*stuckMountFakes) corev1.Pod {
				p := pendingPod("terminating", now, stale, "pvc-a")
				ts := metav1.NewTime(now)
				p.DeletionTimestamp = &ts
				return p
			},
		},
		{
			name: "image pull failure is a different wedge",
			pod: func(*stuckMountFakes) corev1.Pod {
				return waitingPod(pendingPod("badimage", now, stale, "pvc-a"), "ImagePullBackOff")
			},
		},
		{
			// The orphaned CDI upload pod whose TLS secret was deleted: it sits
			// Pending on an attached volume forever, but a kubelet restart will
			// not help it.
			name: "missing secret is a different wedge",
			pod: func(*stuckMountFakes) corev1.Pod {
				return waitingPod(pendingPod("nosecret", now, stale, "pvc-a"), "CreateContainerConfigError")
			},
		},
		{
			name: "init container image pull failure",
			pod: func(*stuckMountFakes) corev1.Pod {
				return waitingInitPod(pendingPod("badinit", now, stale, "pvc-a"), "ErrImagePull")
			},
		},
		{
			name: "container merely creating is not an error",
			pod: func(*stuckMountFakes) corev1.Pod {
				return waitingPod(pendingPod("creating", now, stale, "pvc-a"), "ContainerCreating")
			},
			want:    true,
			wantPV:  "pv-a",
			wantPod: "creating",
		},
		{
			name: "just under the threshold",
			pod: func(*stuckMountFakes) corev1.Pod {
				return pendingPod("young", now, stuckMountThreshold-time.Second, "pvc-a")
			},
		},
		{
			name: "just over the threshold",
			pod: func(*stuckMountFakes) corev1.Pod {
				return pendingPod("old", now, stuckMountThreshold+time.Second, "pvc-a")
			},
			want:    true,
			wantPV:  "pv-a",
			wantPod: "old",
		},
		{
			name: "no PVC volumes",
			pod: func(*stuckMountFakes) corev1.Pod {
				p := pendingPod("configonly", now, stale)
				p.Spec.Volumes = []corev1.Volume{{
					Name:         "cfg",
					VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
				}}
				return p
			},
		},
		{
			name:   "PVC lookup fails",
			pod:    func(*stuckMountFakes) corev1.Pod { return pendingPod("pvcerr", now, stale, "pvc-a") },
			mutate: func(f *stuckMountFakes) { f.pvcErr = map[string]error{"pvc-a": errors.New("nope")} },
		},
		{
			name:   "PVC not yet bound to a PV",
			pod:    func(*stuckMountFakes) corev1.Pod { return pendingPod("unbound", now, stale, "pvc-a") },
			mutate: func(f *stuckMountFakes) { f.claims = map[string]string{} },
		},
		{
			name:   "VolumeAttachment lookup fails",
			pod:    func(*stuckMountFakes) corev1.Pod { return pendingPod("vaerr", now, stale, "pvc-a") },
			mutate: func(f *stuckMountFakes) { f.attachErr = map[string]error{"pv-a": errors.New("nope")} },
		},
		{
			// Attach requested but not complete: kubelet is not at fault yet.
			name:   "attach still in progress",
			pod:    func(*stuckMountFakes) corev1.Pod { return pendingPod("attaching", now, stale, "pvc-a") },
			mutate: func(f *stuckMountFakes) { f.attachedPVs = map[string]bool{} },
		},
		{
			name:   "attached but no device on this node",
			pod:    func(*stuckMountFakes) corev1.Pod { return pendingPod("nodev", now, stale, "pvc-a") },
			mutate: func(f *stuckMountFakes) { f.presentPVs = map[string]bool{} },
		},
		{
			name: "second volume is the wedged one",
			pod: func(*stuckMountFakes) corev1.Pod {
				return pendingPod("multivol", now, stale, "pvc-unbound", "pvc-a")
			},
			want:    true,
			wantPV:  "pv-a",
			wantPod: "multivol",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := wedgeFakes(t)
			if tc.mutate != nil {
				tc.mutate(f)
			}
			z := &zedkube{nodeName: testNodeName}
			desc, got := z.podMountWedge(tc.pod(f), now)
			assert.Equal(t, tc.want, got)
			if !tc.want {
				assert.Empty(t, desc)
				return
			}
			// The description is what lands in the operator-facing recovery log.
			assert.Contains(t, desc, "pod="+tc.wantPod)
			assert.Contains(t, desc, "pv="+tc.wantPV)
		})
	}
}

// TestCheckStuckVolumeMountEpisode walks one wedge episode through the attempt
// cap and the cooldown, then confirms a cleared wedge re-arms recovery.
func TestCheckStuckVolumeMountEpisode(t *testing.T) {
	f := wedgeFakes(t)
	t0 := time.Now()
	pod := pendingPod("cdi-upload", t0, 2*stuckMountThreshold)
	pod.Spec.Volumes = []corev1.Volume{{
		Name: "vol",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "pvc-a"},
		},
	}}
	clientset := fake.NewSimpleClientset(&pod)
	z := &zedkube{nodeName: testNodeName}

	z.checkStuckVolumeMountWithClient(clientset, t0)
	assert.Equal(t, 1, z.stuckMountRecoverCount)
	assert.Equal(t, 1, f.signalCalls)
	assert.Equal(t, t0.Add(stuckMountSuppressWindow), z.stuckMountSuppressUntil)
	assert.FileExists(t, f.flagPath)

	// Inside the cooldown the detector must not touch k3s again.
	z.checkStuckVolumeMountWithClient(clientset, t0.Add(stuckMountSuppressWindow/2))
	assert.Equal(t, 1, z.stuckMountRecoverCount)
	assert.Equal(t, 1, f.signalCalls)

	// Cooldown expired and still wedged: attempt again, up to the cap.
	at := t0
	for i := 2; i <= stuckMountMaxRecover; i++ {
		at = at.Add(stuckMountSuppressWindow + time.Minute)
		z.checkStuckVolumeMountWithClient(clientset, at)
		assert.Equal(t, i, z.stuckMountRecoverCount)
		assert.Equal(t, i, f.signalCalls)
	}

	// At the cap the detector gives up rather than thrashing k3s.
	at = at.Add(stuckMountSuppressWindow + time.Minute)
	z.checkStuckVolumeMountWithClient(clientset, at)
	assert.Equal(t, stuckMountMaxRecover, z.stuckMountRecoverCount)
	assert.Equal(t, stuckMountMaxRecover, f.signalCalls)

	// The wedge clears, which ends the episode and resets the attempt count.
	f.presentPVs = map[string]bool{}
	at = at.Add(time.Minute)
	z.checkStuckVolumeMountWithClient(clientset, at)
	assert.Equal(t, 0, z.stuckMountRecoverCount)
	assert.Equal(t, stuckMountMaxRecover, f.signalCalls)

	// A later episode must be able to recover again, or the cap would disarm
	// the detector for the lifetime of the process.
	f.presentPVs = map[string]bool{"pv-a": true}
	at = at.Add(stuckMountSuppressWindow + time.Minute)
	z.checkStuckVolumeMountWithClient(clientset, at)
	assert.Equal(t, 1, z.stuckMountRecoverCount)
	assert.Equal(t, stuckMountMaxRecover+1, f.signalCalls)
}

func TestCheckStuckVolumeMountNoRecovery(t *testing.T) {
	t0 := time.Now()
	wedged := pendingPod("cdi-upload", t0, 2*stuckMountThreshold, "pvc-a")

	tests := []struct {
		name     string
		pods     []runtime.Object
		nodeName string
	}{
		{"no pods at all", nil, testNodeName},
		{"only a healthy pod", []runtime.Object{func() runtime.Object {
			p := pendingPod("young", t0, time.Minute, "pvc-a")
			return &p
		}()}, testNodeName},
		// The fake clientset does not evaluate field selectors, so these also
		// prove the client-side re-check in podMountWedge does the filtering.
		{"wedged pod on another node", []runtime.Object{func() runtime.Object {
			p := wedged.DeepCopy()
			p.Spec.NodeName = "other-node"
			return p
		}()}, testNodeName},
		{"node name not yet known", []runtime.Object{wedged.DeepCopy()}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := wedgeFakes(t)
			z := &zedkube{nodeName: tc.nodeName}
			z.checkStuckVolumeMountWithClient(fake.NewSimpleClientset(tc.pods...), t0)
			assert.Equal(t, 0, z.stuckMountRecoverCount)
			assert.Equal(t, 0, f.signalCalls)
			assert.NoFileExists(t, f.flagPath)
		})
	}
}

// TestCheckStuckVolumeMountTwoPodsOneRestart checks that a tick with several
// wedged pods restarts k3s once, not once per pod.
func TestCheckStuckVolumeMountTwoPodsOneRestart(t *testing.T) {
	f := wedgeFakes(t)
	f.claims["pvc-b"] = "pv-b"
	f.attachedPVs["pv-b"] = true
	f.presentPVs["pv-b"] = true

	t0 := time.Now()
	podA := pendingPod("cdi-upload-a", t0, 2*stuckMountThreshold, "pvc-a")
	podB := pendingPod("cdi-upload-b", t0, 2*stuckMountThreshold, "pvc-b")

	z := &zedkube{nodeName: testNodeName}
	z.checkStuckVolumeMountWithClient(fake.NewSimpleClientset(&podA, &podB), t0)
	assert.Equal(t, 1, z.stuckMountRecoverCount)
	assert.Equal(t, 1, f.signalCalls)
}

// TestCheckStuckVolumeMountListError checks that an API blip neither triggers
// recovery nor clears an episode already in progress.
func TestCheckStuckVolumeMountListError(t *testing.T) {
	f := wedgeFakes(t)
	clientset := fake.NewSimpleClientset()
	clientset.PrependReactor("list", "pods",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver unreachable")
		})

	z := &zedkube{nodeName: testNodeName, stuckMountRecoverCount: 2}
	z.checkStuckVolumeMountWithClient(clientset, time.Now())
	assert.Equal(t, 2, z.stuckMountRecoverCount)
	assert.Equal(t, 0, f.signalCalls)
}

func TestRecoverKubeletMountWedge(t *testing.T) {
	wedge := []string{"pod=cdi-upload pv=pv-a attached+device-present but unmounted, Pending 7m0s"}

	t.Run("touches the start flag and signals k3s", func(t *testing.T) {
		f := wedgeFakes(t)
		z := &zedkube{nodeName: testNodeName, stuckMountRecoverCount: 1}
		z.recoverKubeletMountWedge(wedge)
		assert.Equal(t, 1, f.signalCalls)
		assert.FileExists(t, f.flagPath)
	})

	t.Run("dry run takes no action", func(t *testing.T) {
		f := wedgeFakes(t)
		stuckMountDryRun = true
		z := &zedkube{nodeName: testNodeName, stuckMountRecoverCount: 1}
		z.recoverKubeletMountWedge(wedge)
		assert.Equal(t, 0, f.signalCalls)
		assert.NoFileExists(t, f.flagPath)
	})

	t.Run("unwritable start flag still restarts k3s", func(t *testing.T) {
		f := wedgeFakes(t)
		// A regular file where the flag's parent directory should be: MkdirAll
		// fails regardless of privileges.
		blocked := filepath.Join(t.TempDir(), "run")
		assert.NoError(t, os.WriteFile(blocked, nil, 0644))
		stuckMountK3sStartFlag = filepath.Join(blocked, "k3s-start")

		z := &zedkube{nodeName: testNodeName, stuckMountRecoverCount: 1}
		z.recoverKubeletMountWedge(wedge)
		assert.Equal(t, 1, f.signalCalls)
	})

	t.Run("enumeration failure still touched the flag", func(t *testing.T) {
		f := wedgeFakes(t)
		f.signalErr = errors.New("cannot read /proc")
		z := &zedkube{nodeName: testNodeName, stuckMountRecoverCount: 1}
		z.recoverKubeletMountWedge(wedge)
		assert.Equal(t, 1, f.signalCalls)
		assert.FileExists(t, f.flagPath)
	})

	t.Run("no k3s process found", func(t *testing.T) {
		f := wedgeFakes(t)
		f.signalPids = nil
		z := &zedkube{nodeName: testNodeName, stuckMountRecoverCount: 1}
		z.recoverKubeletMountWedge(wedge)
		assert.Equal(t, 1, f.signalCalls)
		assert.FileExists(t, f.flagPath)
	})
}
