// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

const testUploadPVC = "2c29c844-pvc-0"

func uploadServerPod(name string, uid types.UID, restarts int32, lastReason string) *corev1.Pod {
	cs := corev1.ContainerStatus{Name: "cdi-upload-server", RestartCount: restarts}
	if lastReason != "" {
		cs.LastTerminationState.Terminated = &corev1.ContainerStateTerminated{Reason: lastReason, ExitCode: 137}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: EVEKubeNameSpace, UID: uid},
		Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{cs}},
	}
}

func setPod(t *testing.T, client *fake.Clientset, pod *corev1.Pod) {
	t.Helper()
	pods := client.CoreV1().Pods(EVEKubeNameSpace)
	_ = pods.Delete(context.Background(), pod.Name, metav1.DeleteOptions{})
	if _, err := pods.Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestUploadServerWatchNoPod(t *testing.T) {
	w := newUploadServerWatch(fake.NewSimpleClientset(), testUploadPVC)
	if got := w.check(context.Background()); got != "" {
		t.Errorf("check() with no upload pod = %q, want \"\"", got)
	}
}

// Restarts the pod already had when the watch began belong to earlier attempts
// and must not count; the OOMKilled reason must be reported.
func TestUploadServerWatchCountsOnlyNewRestarts(t *testing.T) {
	client := fake.NewSimpleClientset()
	name := "cdi-upload-" + testUploadPVC
	w := newUploadServerWatch(client, testUploadPVC)
	ctx := context.Background()

	setPod(t, client, uploadServerPod(name, "uid-a", 5, "OOMKilled"))
	if got := w.check(ctx); got != "" {
		t.Fatalf("baseline check = %q, want \"\"", got)
	}
	setPod(t, client, uploadServerPod(name, "uid-a", 7, "OOMKilled"))
	if got := w.check(ctx); got != "" {
		t.Fatalf("2 new restarts = %q, want \"\"", got)
	}
	setPod(t, client, uploadServerPod(name, "uid-a", 8, "OOMKilled"))
	got := w.check(ctx)
	want := "CDI upload server " + name + " restarted 3 times (last exit: OOMKilled)"
	if got != want {
		t.Errorf("check() = %q, want %q", got, want)
	}
}

// CDI can replace the upload pod; restarts across pods add up.
func TestUploadServerWatchCarriesAcrossPodReplacement(t *testing.T) {
	client := fake.NewSimpleClientset()
	name := "cdi-upload-" + testUploadPVC
	w := newUploadServerWatch(client, testUploadPVC)
	ctx := context.Background()

	setPod(t, client, uploadServerPod(name, "uid-a", 0, ""))
	w.check(ctx)
	setPod(t, client, uploadServerPod(name, "uid-a", 2, "Error"))
	if got := w.check(ctx); got != "" {
		t.Fatalf("2 restarts on the first pod = %q, want \"\"", got)
	}
	setPod(t, client, uploadServerPod(name, "uid-b", 1, "OOMKilled"))
	if got := w.check(ctx); !strings.Contains(got, "restarted 3 times") {
		t.Errorf("check() after replacement = %q, want 3 restarts counted", got)
	}
}

// The pod name comes from CDI's annotation on the PVC when it is set.
func TestUploadServerWatchUsesAnnotatedPodName(t *testing.T) {
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: testUploadPVC, Namespace: EVEKubeNameSpace,
		Annotations: map[string]string{"cdi.kubevirt.io/storage.uploadPodName": "custom-upload"},
	}}
	client := fake.NewSimpleClientset(pvc)
	w := newUploadServerWatch(client, testUploadPVC)
	w.maxRestarts = 1

	setPod(t, client, uploadServerPod("custom-upload", "uid-a", 0, ""))
	w.check(context.Background())
	setPod(t, client, uploadServerPod("custom-upload", "uid-a", 1, "OOMKilled"))
	if got := w.check(context.Background()); !strings.Contains(got, "custom-upload") {
		t.Errorf("check() = %q, want the annotated pod name", got)
	}
}

func TestPodRestartsPrefersOOMKilled(t *testing.T) {
	pod := &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
		{RestartCount: 1, LastTerminationState: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{ExitCode: 2}}},
		{RestartCount: 2, LastTerminationState: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137}}},
	}}}
	restarts, reason := podRestarts(pod)
	if restarts != 3 || reason != "OOMKilled" {
		t.Errorf("podRestarts() = %d, %q; want 3, \"OOMKilled\"", restarts, reason)
	}
	pod.Status.ContainerStatuses = pod.Status.ContainerStatuses[:1]
	if _, reason := podRestarts(pod); reason != "exit code 2" {
		t.Errorf("reason without a Reason field = %q, want \"exit code 2\"", reason)
	}
}

func TestWatchUploadServerReportsOnceAndStops(t *testing.T) {
	client := fake.NewSimpleClientset()
	name := "cdi-upload-" + testUploadPVC
	setPod(t, client, uploadServerPod(name, "uid-a", 0, ""))
	w := newUploadServerWatch(client, testUploadPVC)
	w.maxRestarts = 0 // fail on the first check

	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0)
	calls := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchUploadServer(context.Background(), log, w, time.Millisecond,
			func(string) { calls++ })
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchUploadServer did not return after reporting a failure")
	}
	if calls != 1 {
		t.Errorf("onFailure called %d times, want 1", calls)
	}
}

func TestWatchUploadServerStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w := newUploadServerWatch(fake.NewSimpleClientset(), testUploadPVC)
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0)
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchUploadServer(ctx, log, w, time.Millisecond, func(string) {
			t.Error("onFailure called without a failing upload server")
		})
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchUploadServer did not return after cancel")
	}
}
