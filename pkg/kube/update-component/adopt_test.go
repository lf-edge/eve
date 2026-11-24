// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func managedEntry(manager string, op metav1.ManagedFieldsOperationType,
	subresource, fields string) metav1.ManagedFieldsEntry {
	return metav1.ManagedFieldsEntry{
		Manager:     manager,
		Operation:   op,
		APIVersion:  "apps/v1",
		FieldsType:  "FieldsV1",
		FieldsV1:    &metav1.FieldsV1{Raw: []byte(fields)},
		Subresource: subresource,
	}
}

func deploymentWith(entries ...metav1.ManagedFieldsEntry) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("apps/v1")
	u.SetKind("Deployment")
	u.SetNamespace("cdi")
	u.SetName("cdi-operator")
	u.SetResourceVersion("42")
	u.SetManagedFields(entries)
	return u
}

const (
	portsFields    = `{"f:spec":{"f:template":{"f:spec":{"f:containers":{"k:{\"name\":\"cdi-operator\"}":{"f:ports":{}}}}}}}`
	selectorFields = `{"f:spec":{"f:template":{"f:spec":{"f:nodeSelector":{"f:tie-breaker-node":{}}}}}}`
	statusFields   = `{"f:status":{"f:replicas":{}}}`
)

// patchedEntries applies adoptPatch's managedFields value to entries.
func patchedEntries(t *testing.T, obj *unstructured.Unstructured) []metav1.ManagedFieldsEntry {
	t.Helper()
	patch, err := adoptPatch(obj)
	if err != nil {
		t.Fatalf("adoptPatch: %v", err)
	}
	if patch == nil {
		return nil
	}
	var ops []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(patch, &ops); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	for _, op := range ops {
		if op.Path != "/metadata/managedFields" {
			continue
		}
		var entries []metav1.ManagedFieldsEntry
		if err := json.Unmarshal(op.Value, &entries); err != nil {
			t.Fatalf("decode managedFields: %v", err)
		}
		return entries
	}
	t.Fatalf("patch has no managedFields op: %s", patch)
	return nil
}

func TestAdoptPatchShellInstall(t *testing.T) {
	obj := deploymentWith(
		managedEntry("k3s", metav1.ManagedFieldsOperationUpdate, "status", statusFields),
		managedEntry("kubectl-patch", metav1.ManagedFieldsOperationUpdate, "", selectorFields),
		managedEntry("kubectl-create", metav1.ManagedFieldsOperationUpdate, "", portsFields),
	)
	entries := patchedEntries(t, obj)
	if entries == nil {
		t.Fatal("no patch for a kubectl-create owned object")
	}
	got := map[string]metav1.ManagedFieldsOperationType{}
	for _, e := range entries {
		got[e.Manager] = e.Operation
		if e.Manager == fieldManager && string(e.FieldsV1.Raw) != portsFields {
			t.Errorf("%s owns %s, want %s", fieldManager, e.FieldsV1.Raw, portsFields)
		}
		if e.Manager == "kubectl-patch" && string(e.FieldsV1.Raw) != selectorFields {
			t.Errorf("kubectl-patch owns %s, want %s", e.FieldsV1.Raw, selectorFields)
		}
	}
	want := map[string]metav1.ManagedFieldsOperationType{
		fieldManager:    metav1.ManagedFieldsOperationApply,
		"kubectl-patch": metav1.ManagedFieldsOperationUpdate,
		"k3s":           metav1.ManagedFieldsOperationUpdate,
	}
	if len(got) != len(want) {
		t.Fatalf("managers %v, want %v", got, want)
	}
	for m, op := range want {
		if got[m] != op {
			t.Errorf("manager %s operation %q, want %q", m, got[m], op)
		}
	}
}

func TestAdoptPatchKubeInitInstall(t *testing.T) {
	obj := deploymentWith(
		managedEntry("k3s", metav1.ManagedFieldsOperationUpdate, "status", statusFields),
		managedEntry(fieldManager, metav1.ManagedFieldsOperationApply, "", portsFields),
	)
	if entries := patchedEntries(t, obj); entries != nil {
		t.Fatalf("unexpected patch for a kube-init owned object: %v", entries)
	}
}

func TestLiveObjects(t *testing.T) {
	objs, err := liveObjects("")
	if err != nil || objs != nil {
		t.Fatalf("empty output: %v, %v", objs, err)
	}
	one := `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"cdi"}}`
	objs, err = liveObjects(one)
	if err != nil || len(objs) != 1 || objs[0].GetName() != "cdi" {
		t.Fatalf("single object: %v, %v", objs, err)
	}
	list := `{"apiVersion":"v1","kind":"List","items":[` + one +
		`,{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"cdi-operator","namespace":"cdi"}}]}`
	objs, err = liveObjects(list)
	if err != nil || len(objs) != 2 || objs[1].GetKind() != "Deployment" {
		t.Fatalf("list: %v, %v", objs, err)
	}
}
