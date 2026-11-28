// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

const testManifest = `# leading comment
---
apiVersion: v1
kind: Namespace
metadata:
  name: longhorn-system
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: volumes.longhorn.io
spec:
  group: longhorn.io
  versions:
  - name: v1beta2
    served: true
    storage: true
---
# comment only
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: longhorn-manager
  namespace: longhorn-system
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: nodes.longhorn.io
spec:
  group: longhorn.io
  versions:
  - name: v1beta2
    served: true
    storage: true
`

func TestSplitManifest(t *testing.T) {
	crds, rest, objs, err := splitManifest([]byte(testManifest))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, o := range objs {
		names = append(names, o.GetName())
	}
	if got := strings.Join(names, ","); got != "volumes.longhorn.io,nodes.longhorn.io" {
		t.Errorf("CRDs = %s", got)
	}
	for _, want := range []string{"volumes.longhorn.io", "nodes.longhorn.io"} {
		if !strings.Contains(string(crds), want) {
			t.Errorf("CRD manifest misses %s", want)
		}
	}
	if strings.Contains(string(crds), "DaemonSet") || strings.Contains(string(crds), "Namespace") {
		t.Errorf("CRD manifest has other kinds:\n%s", crds)
	}
	for _, want := range []string{"kind: Namespace", "kind: DaemonSet"} {
		if !strings.Contains(string(rest), want) {
			t.Errorf("rest misses %s", want)
		}
	}
	if strings.Contains(string(rest), crdKind) {
		t.Errorf("rest has a CRD:\n%s", rest)
	}
	// Each part must be a manifest of its own.
	if _, again, objs, err := splitManifest(crds); err != nil || len(objs) != 2 || len(again) != 0 {
		t.Errorf("CRD manifest re-splits into %d CRDs and %q, err %v", len(objs), again, err)
	}
	if _, _, objs, err := splitManifest(rest); err != nil || len(objs) != 0 {
		t.Errorf("rest re-splits into %d CRDs, err %v", len(objs), err)
	}
}

func TestSplitManifestNoCRDs(t *testing.T) {
	crds, rest, objs, err := splitManifest([]byte("kind: Namespace\napiVersion: v1\nmetadata:\n  name: a\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 0 || len(crds) != 0 || !strings.Contains(string(rest), "kind: Namespace") {
		t.Errorf("crds=%q rest=%q objs=%d", crds, rest, len(objs))
	}
}

func crdFromYAML(t *testing.T, s string) *unstructured.Unstructured {
	t.Helper()
	js, err := utilyaml.ToJSON([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	u := &unstructured.Unstructured{}
	if err := u.UnmarshalJSON(js); err != nil {
		t.Fatal(err)
	}
	return u
}

const crdHead = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: volumes.longhorn.io
spec:
  group: longhorn.io
`

// liveWebhookCRD is a v1.9.1 Longhorn CRD after longhorn-manager injected
// the caBundle.
const liveWebhookCRD = crdHead + `  conversion:
    strategy: Webhook
    webhook:
      clientConfig:
        caBundle: Y2E=
        service:
          name: longhorn-conversion-webhook
          namespace: longhorn-system
          path: /v1/webhook/conversion
          port: 9501
      conversionReviewVersions:
      - v1beta2
      - v1beta1
  versions:
  - name: v1beta1
    served: true
    storage: false
  - name: v1beta2
    served: true
    storage: true
`

const oneServedVersion = `  versions:
  - name: v1beta2
    served: true
    storage: true
`

func TestConversionToNone(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		live     string
		want     bool
	}{
		{
			name:     "manifest drops the webhook, one served version",
			manifest: crdHead + oneServedVersion,
			live:     liveWebhookCRD,
			want:     true,
		},
		{
			name: "manifest declares a conversion",
			manifest: crdHead + `  conversion:
    strategy: Webhook
` + oneServedVersion,
			live: liveWebhookCRD,
		},
		{
			name: "manifest serves two versions",
			manifest: crdHead + `  versions:
  - name: v1beta1
    served: true
    storage: false
  - name: v1beta2
    served: true
    storage: true
`,
			live: liveWebhookCRD,
		},
		{
			name:     "live already None",
			manifest: crdHead + oneServedVersion,
			live: crdHead + `  conversion:
    strategy: None
` + oneServedVersion,
		},
		{
			name:     "live without conversion",
			manifest: crdHead + oneServedVersion,
			live:     crdHead + oneServedVersion,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := conversionToNone(crdFromYAML(t, tt.manifest), crdFromYAML(t, tt.live))
			if got != tt.want {
				t.Errorf("conversionToNone = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsConversionRejection(t *testing.T) {
	rejected := errors.New(`apply x (CRDs), rc: 1, stderr: Error from server (Invalid): ` +
		`CustomResourceDefinition.apiextensions.k8s.io "volumes.longhorn.io" is invalid: ` +
		`[spec.conversion.strategy: Required value, spec.conversion.webhookClientConfig: ` +
		`Forbidden: should not be set when strategy is not set to Webhook]`)
	if !isConversionRejection(rejected) {
		t.Error("conversion rejection not recognized")
	}
	if isConversionRejection(errors.New("apply x (CRDs), rc: 1, stderr: connection refused")) {
		t.Error("unrelated error taken for a conversion rejection")
	}
	if isConversionRejection(nil) {
		t.Error("nil taken for a conversion rejection")
	}
}
