// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"os"
	"strings"
	"testing"
)

// nadCRDName is the CRD the multus manifest declares and then immediately
// instantiates. It is spelled out here rather than imported because nothing in
// the production path needs to name it: kubectlx.ApplyFile establishes every CRD
// document before continuing, whatever its kind.
const nadCRDName = "network-attachment-definitions.k8s.cni.cncf.io"

// TestNADCRDNameMatchesManifest guards the precondition that makes the
// establish-before-continue step in kubectlx.ApplyFile load-bearing for multus:
// the manifest declares a CRD and, in the same file, an instance of that kind.
// The apiserver rejects the instance until the CRD is established, so if the
// manifest ever stops shipping both, the reason ApplyMultusCNI depends on that
// ordering is gone and this test should be revisited rather than deleted.
func TestNADCRDNameMatchesManifest(t *testing.T) {
	const manifest = "../../multus-daemonset.yaml"
	b, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatalf("read %s: %v", manifest, err)
	}
	if !strings.Contains(string(b), "name: "+nadCRDName) {
		t.Errorf("%s declares no CRD named %q", manifest, nadCRDName)
	}
	if !strings.Contains(string(b), "kind: NetworkAttachmentDefinition") {
		t.Errorf("%s no longer declares a NetworkAttachmentDefinition instance; "+
			"the CRD-establish ordering ApplyMultusCNI relies on may be obsolete", manifest)
	}
}
