// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/csaupgrade"
)

// fieldManager must match kubectlx.DefaultFieldManager in kube-init.
const fieldManager = "kube-init"

// kubectlRequestTimeout bounds each API request of the adoption step.
const kubectlRequestTimeout = "--request-timeout=60s"

// installManagers own objects installed before kube-init: the shell
// installer used kubectl create and client-side apply. Fields set later by
// kubectl patch keep their owner.
var installManagers = sets.New("kubectl-create", "kubectl-client-side-apply")

// adoptInstalledFields moves installManagers' fields on the live objects of
// the manifest file at path to fieldManager, as kubectl does when moving to
// server-side apply, so the apply can drop fields a release removed.
func adoptInstalledFields(path string) error {
	cmd := exec.Command("kubectl", "get", "-f", path, "--ignore-not-found",
		"-o", "json", "--show-managed-fields", kubectlRequestTimeout)
	out, getErr := runKubectl(cmd)
	if getErr != nil && strings.TrimSpace(out) == "" {
		return fmt.Errorf("get live objects: %w", getErr)
	}
	objs, err := liveObjects(out)
	if err != nil {
		return err
	}
	if getErr != nil {
		log.Printf("WARNING: not all live objects of %s listed: %v", path, getErr)
	}
	var errs []error
	for i := range objs {
		if err := adoptObject(&objs[i]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func adoptObject(obj *unstructured.Unstructured) error {
	patch, err := adoptPatch(obj)
	if err != nil || patch == nil {
		return err
	}
	data, err := obj.MarshalJSON()
	if err != nil {
		return fmt.Errorf("%s %s: %w", obj.GetKind(), obj.GetName(), err)
	}
	cmd := exec.Command("kubectl", "patch", "-f", "-", "--type=json",
		"-p", string(patch), kubectlRequestTimeout)
	cmd.Stdin = bytes.NewReader(data)
	if _, err := runKubectl(cmd); err != nil {
		return fmt.Errorf("patch managed fields of %s %s: %w",
			obj.GetKind(), obj.GetName(), err)
	}
	log.Printf("adopted installed fields of %s %s/%s for %s",
		obj.GetKind(), obj.GetNamespace(), obj.GetName(), fieldManager)
	return nil
}

// adoptPatch returns the JSON patch that moves installManagers' fields on
// obj to fieldManager, or nil when there is nothing to move.
func adoptPatch(obj *unstructured.Unstructured) ([]byte, error) {
	return csaupgrade.UpgradeManagedFieldsPatch(obj, installManagers, fieldManager)
}

// liveObjects decodes kubectl get output, a single object or a List.
func liveObjects(out string) ([]unstructured.Unstructured, error) {
	if strings.TrimSpace(out) == "" {
		return nil, nil
	}
	var u unstructured.Unstructured
	if err := u.UnmarshalJSON([]byte(out)); err != nil {
		return nil, fmt.Errorf("decode live objects: %w", err)
	}
	if !u.IsList() {
		return []unstructured.Unstructured{u}, nil
	}
	list, err := u.ToList()
	if err != nil {
		return nil, fmt.Errorf("decode live objects: %w", err)
	}
	return list.Items, nil
}

func runKubectl(cmd *exec.Cmd) (string, error) {
	var outStr, errStr strings.Builder
	cmd.Stdout = &outStr
	cmd.Stderr = &errStr
	if err := cmd.Run(); err != nil {
		return outStr.String(), fmt.Errorf("%v, stderr: %s", err, errStr.String())
	}
	return outStr.String(), nil
}
