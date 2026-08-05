// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"encoding/json"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Shared GroupVersionResource handles used across kube-init.
var (
	KubeVirtGVR = schema.GroupVersionResource{
		Group: "kubevirt.io", Version: "v1", Resource: "kubevirts",
	}

	LonghornNodesGVR = schema.GroupVersionResource{
		Group: "longhorn.io", Version: "v1beta2", Resource: "nodes",
	}

	// LonghornInstanceManagersGVR is the CR that owns the per-node
	// instance-manager pod, where Longhorn runs a volume's engine and
	// replica processes. It is NOT a DaemonSet, so a readiness check
	// that lists DaemonSets cannot see it.
	LonghornInstanceManagersGVR = schema.GroupVersionResource{
		Group: "longhorn.io", Version: "v1beta2", Resource: "instancemanagers",
	}

	AddonGVR = schema.GroupVersionResource{
		Group: "k3s.cattle.io", Version: "v1", Resource: "addons",
	}
)

// Kubernetes namespaces used by kube-init.
const (
	LonghornNamespace = "longhorn-system"
	KubeVirtNamespace = "kubevirt"
	CDINamespace      = "cdi"

	// LonghornDefaultDiskPath is the disk path Longhorn is told to
	// use for its default replica store.
	LonghornDefaultDiskPath = "/persist/vault/volumes"
)

// IgnoreNotFound returns nil if err is a Kubernetes "not found" error, else err.
func IgnoreNotFound(err error) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// IsNodeReady reports whether a Node's Ready condition is True.
func IsNodeReady(node *corev1.Node) bool {
	if node == nil {
		return false
	}
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// BuildMergeLabelPatch produces a strategic-merge-friendly
// {"metadata":{"labels":..., "annotations":...}} patch. Either map
// may be nil; nil maps are omitted from the resulting JSON.
func BuildMergeLabelPatch(labels, annotations map[string]string) ([]byte, error) {
	meta := map[string]any{}
	if labels != nil {
		meta["labels"] = labels
	}
	if annotations != nil {
		meta["annotations"] = annotations
	}
	return json.Marshal(map[string]any{"metadata": meta})
}
