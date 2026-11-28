// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

const crdKind = "CustomResourceDefinition"

// conversionNonePatch replaces a CRD's conversion with no conversion.
const conversionNonePatch = `[{"op":"replace","path":"/spec/conversion","value":{"strategy":"None"}}]`

// splitManifest splits a multi-document manifest into its
// CustomResourceDefinitions and everything else, each a manifest of its
// own, and returns the CRDs decoded.
func splitManifest(data []byte) (crds, rest []byte,
	crdObjs []unstructured.Unstructured, err error) {
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	var crdBuf, restBuf bytes.Buffer
	for {
		doc, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("read manifest: %w", err)
		}
		js, err := utilyaml.ToJSON(doc)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("decode manifest document: %w", err)
		}
		if trimmed := bytes.TrimSpace(js); len(trimmed) == 0 ||
			bytes.Equal(trimmed, []byte("null")) {
			continue
		}
		var obj unstructured.Unstructured
		if err := obj.UnmarshalJSON(js); err != nil {
			return nil, nil, nil, fmt.Errorf("decode manifest document: %w", err)
		}
		buf := &restBuf
		if obj.GetKind() == crdKind {
			buf = &crdBuf
			crdObjs = append(crdObjs, obj)
		}
		buf.WriteString("---\n")
		buf.Write(bytes.TrimRight(doc, "\n"))
		buf.WriteString("\n")
	}
	return crdBuf.Bytes(), restBuf.Bytes(), crdObjs, nil
}

// conversionToNone reports whether live, the installed copy of crd, must
// have its conversion set to None before crd is applied. crd declares no
// conversion and serves one version, so the API server never converts it,
// while live still names a webhook. Server-side apply would remove only
// the webhook fields the installer owns and keep the caBundle a controller
// injected, leaving a conversion the API server rejects.
func conversionToNone(crd, live *unstructured.Unstructured) bool {
	if _, found, _ := unstructured.NestedFieldNoCopy(crd.Object,
		"spec", "conversion"); found {
		return false
	}
	versions, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
	served := 0
	for _, v := range versions {
		if m, ok := v.(map[string]interface{}); ok && m["served"] == true {
			served++
		}
	}
	if served != 1 {
		return false
	}
	strategy, _, _ := unstructured.NestedString(live.Object,
		"spec", "conversion", "strategy")
	return strategy == "Webhook"
}

// dropWebhookConversions sets the conversion of each installed CRD to None
// where conversionToNone says so. path holds the CRDs of the manifest.
func dropWebhookConversions(path string, crds []unstructured.Unstructured) error {
	cmd := exec.Command("kubectl", "get", "-f", path, "--ignore-not-found",
		"-o", "json", kubectlRequestTimeout)
	out, err := runKubectl(cmd)
	if err != nil {
		return fmt.Errorf("get live CRDs: %w", err)
	}
	live, err := liveObjects(out)
	if err != nil {
		return err
	}
	installed := make(map[string]*unstructured.Unstructured, len(live))
	for i := range live {
		installed[live[i].GetName()] = &live[i]
	}
	var errs []error
	for i := range crds {
		name := crds[i].GetName()
		obj, ok := installed[name]
		if !ok || !conversionToNone(&crds[i], obj) {
			continue
		}
		cmd := exec.Command("kubectl", "patch", "crd", name, "--type=json",
			"-p", conversionNonePatch, "--field-manager="+fieldManager,
			kubectlRequestTimeout)
		if _, err := runKubectl(cmd); err != nil {
			errs = append(errs, fmt.Errorf("set conversion of CRD %s to None: %w", name, err))
			continue
		}
		log.Printf("set conversion of CRD %s to None: the manifest drops its webhook", name)
	}
	return errors.Join(errs...)
}

// applyCRDs applies the CRD manifest crdFile of the manifest name, setting
// removed webhook conversions to None first. A component's old controller
// may restore its webhook between that step and the apply, so a rejected
// conversion gets one more round.
func applyCRDs(crdFile string, crds []unstructured.Unstructured, name string) error {
	apply := func() error {
		if err := dropWebhookConversions(crdFile, crds); err != nil {
			log.Printf("WARNING: CRD conversions of %s: %v", name, err)
		}
		return kubectlApplyFile(crdFile, name+" (CRDs)")
	}
	err := apply()
	if isConversionRejection(err) {
		log.Printf("WARNING: %s: the API server rejected a CRD conversion, retrying once", name)
		err = apply()
	}
	return err
}

// isConversionRejection reports whether an apply error is the API server
// rejecting a CRD's conversion.
func isConversionRejection(err error) bool {
	return err != nil && strings.Contains(err.Error(), "spec.conversion")
}
