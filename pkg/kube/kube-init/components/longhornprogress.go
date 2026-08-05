// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"context"
	"fmt"
	"sort"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// longhornProgress extends the namespace probe with the state of each
// InstanceManager custom resource.
//
// While that resource converges on running, nothing the namespace probe
// watches changes — the image is pulled so no ingest is open, and the pod
// already counts as ready — so a probe blind to it reports a stall during
// genuine progress.
func longhornProgress(ctx context.Context) (string, error) {
	base, err := componentProgress(kubectlx.LonghornNamespace)(ctx)
	if err != nil {
		return "", err
	}
	return base + " " + instanceManagerStates(ctx), nil
}

// instanceManagerStates summarises every InstanceManager's currentState as a
// sorted string. Sorted so iteration order cannot make an unchanged cluster
// look like it moved; a flapping token defeats the deadline as surely as a
// frozen one. Errors degrade to a marker because the namespace half of the
// token is still useful before the CRD is established.
func instanceManagerStates(ctx context.Context) string {
	list, err := kubeclient.Default().Dynamic.
		Resource(kubectlx.LonghornInstanceManagersGVR).
		Namespace(kubectlx.LonghornNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "im=?"
	}
	states := make([]string, 0, len(list.Items))
	for i := range list.Items {
		states = append(states, instanceManagerState(&list.Items[i]))
	}
	sort.Strings(states)
	return fmt.Sprintf("im=%d%v", len(states), states)
}

func instanceManagerState(u *unstructured.Unstructured) string {
	node, _, _ := unstructured.NestedString(u.Object, "spec", "nodeID")
	state, _, _ := unstructured.NestedString(u.Object, "status", "currentState")
	if state == "" {
		state = "none"
	}
	return node + ":" + state
}
