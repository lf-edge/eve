// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// stateAnnotation mirrors the FSM state onto this node's Node object,
// so `kubectl get node -o yaml` on any cluster member shows what each
// node's daemon is doing. Informational only: nothing reads it back,
// and pillar takes the same facts from the KubeInitStatus topic, which
// does not depend on the API server it describes.
const stateAnnotation = "eve.lfedge.org/kube-init-state"

// stateMirrorTimeout bounds one annotation write.
const stateMirrorTimeout = 10 * time.Second

// stateMirrorMsg is one state to write, with the node to write it on.
// The node name travels with it so the mirror goroutine reads nothing
// the event loop writes.
type stateMirrorMsg struct {
	node  string
	state string
}

// mirrorState hands the new state to the mirror goroutine. Never
// blocks the event loop: a state not yet written is replaced, since
// only the latest one is of interest.
func (d *daemon) mirrorState(s State) {
	if d.stateMirrorCh == nil {
		return
	}
	msg := stateMirrorMsg{node: state.ToK8sName(d.deviceName), state: s.String()}
	for {
		select {
		case d.stateMirrorCh <- msg:
			return
		default:
		}
		select {
		case <-d.stateMirrorCh:
		default:
		}
	}
}

// runStateMirror writes each state it is handed to the node
// annotation. Failures are logged and dropped: before k3s is Ready
// there is no client, and while k3s restarts there is no API.
func (d *daemon) runStateMirror(ctx context.Context) {
	for {
		var msg stateMirrorMsg
		select {
		case msg = <-d.stateMirrorCh:
		case <-ctx.Done():
			return
		}
		if !kubeclient.HasDefault() || msg.node == "" {
			continue
		}
		patch, err := kubectlx.BuildMergeLabelPatch(nil,
			map[string]string{stateAnnotation: msg.state})
		if err != nil {
			continue
		}
		writeCtx, cancel := context.WithTimeout(ctx, stateMirrorTimeout)
		_, err = kubeclient.Default().Clientset.CoreV1().Nodes().Patch(writeCtx,
			msg.node, types.MergePatchType, patch,
			metav1.PatchOptions{})
		cancel()
		if err != nil {
			log.Printf("state mirror: annotate node with %s: %v", msg.state, err)
		}
	}
}
