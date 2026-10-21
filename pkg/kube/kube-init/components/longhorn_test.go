// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
)

// TestPodExecStopsOnAHungUpgrade checks that podExec gives up at
// podExecTimeout when the apiserver accepts the exec upgrade and never
// answers. The SPDY executor alone waits forever in that case.
func TestPodExecStopsOnAHungUpgrade(t *testing.T) {
	saved := podExecTimeout
	podExecTimeout = 300 * time.Millisecond
	defer func() { podExecTimeout = saved }()

	hung := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer func() {
		hung.CloseClientConnections()
		hung.Close()
	}()

	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte(`apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: `+hung.URL+`
contexts:
- name: c
  context:
    cluster: c
    user: u
users:
- name: u
  user: {}
current-context: c
`), 0o600); err != nil {
		t.Fatal(err)
	}
	kc, err := kubeclient.New(kubeconfig)
	if err != nil {
		t.Fatalf("kubeclient.New: %v", err)
	}
	kubeclient.SetDefault(kc)
	defer kubeclient.SetDefault(nil)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- podExec(context.Background(), "csi", "longhorn-system",
			"longhorn-csi-plugin", []string{"true"}, nil)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("podExec against a hung apiserver returned no error")
		}
		if elapsed := time.Since(start); elapsed > podExecTimeout+2*time.Second {
			t.Errorf("podExec took %v; podExecTimeout is %v", elapsed, podExecTimeout)
		}
	case <-time.After(podExecTimeout + 5*time.Second):
		t.Fatalf("podExec is still blocked after podExecTimeout (%v)", podExecTimeout)
	}
}
