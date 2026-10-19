// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"encoding/json"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func witnessNode(t *testing.T, name string, state types.WitnessEtcdState) corev1.Node {
	t.Helper()
	raw, err := json.Marshal(types.WitnessStatus{State: state})
	if err != nil {
		t.Fatal(err)
	}
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:        name,
		Annotations: map[string]string{types.NodeWitnessAnnotation: string(raw)},
	}}
}

func TestParseWitnessStatusSkipsIdle(t *testing.T) {
	nodes := []corev1.Node{
		witnessNode(t, "parked", types.WitnessEtcdStateIdle),
		{ObjectMeta: metav1.ObjectMeta{Name: "plain"}},
		witnessNode(t, "host", types.WitnessEtcdStateJoined),
	}
	got := parseWitnessStatus(nodes)
	if got == nil || got.State != types.WitnessEtcdStateJoined {
		t.Fatalf("parseWitnessStatus = %+v, want the Joined entry", got)
	}
}

func TestParseWitnessStatusOnlyIdle(t *testing.T) {
	nodes := []corev1.Node{witnessNode(t, "parked", types.WitnessEtcdStateIdle)}
	if got := parseWitnessStatus(nodes); got != nil {
		t.Fatalf("parseWitnessStatus = %+v, want nil", got)
	}
}
