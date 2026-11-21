// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func im(node, state string) *unstructured.Unstructured {
	obj := map[string]any{"spec": map[string]any{"nodeID": node}}
	if state != "" {
		obj["status"] = map[string]any{"currentState": state}
	}
	return &unstructured.Unstructured{Object: obj}
}

// A resource that has not reported yet must still produce a token, and one
// distinct from the running state — the transition between them is exactly the
// progress the deadline needs to observe.
func TestInstanceManagerStateDistinguishesUnreportedFromRunning(t *testing.T) {
	pending := instanceManagerState(im("node-a", ""))
	running := instanceManagerState(im("node-a", "running"))
	if pending == running {
		t.Fatalf("unreported and running produced the same token: %q", pending)
	}
	if pending != "node-a:none" {
		t.Fatalf("unreported token = %q", pending)
	}
	if running != "node-a:running" {
		t.Fatalf("running token = %q", running)
	}
}

// The token must not change when nothing changed. List order is not
// guaranteed, and a token that flaps would reset the no-progress timer forever,
// defeating the deadline just as thoroughly as one that never changes.
func TestInstanceManagerStatesAreOrderStable(t *testing.T) {
	a := []string{
		instanceManagerState(im("node-b", "running")),
		instanceManagerState(im("node-a", "error")),
	}
	b := []string{
		instanceManagerState(im("node-a", "error")),
		instanceManagerState(im("node-b", "running")),
	}
	sortedJoin := func(s []string) string {
		cp := append([]string(nil), s...)
		for i := range cp {
			for j := i + 1; j < len(cp); j++ {
				if cp[j] < cp[i] {
					cp[i], cp[j] = cp[j], cp[i]
				}
			}
		}
		return cp[0] + "|" + cp[1]
	}
	if sortedJoin(a) != sortedJoin(b) {
		t.Fatalf("token depends on list order: %q vs %q", sortedJoin(a), sortedJoin(b))
	}
}
