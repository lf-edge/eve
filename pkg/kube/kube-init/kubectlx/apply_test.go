// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/mgmtproxy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// crdTerminatingErr reproduces what the apiserver returns when a CR is
// applied while its CRD is still finalizing. Observed verbatim on a
// single→cluster transition, where multus is uninstalled and immediately
// re-applied.
func crdTerminatingErr() error {
	return apierrors.NewForbidden(
		schema.GroupResource{
			Group:    "k8s.cni.cncf.io",
			Resource: "network-attachment-definitions",
		},
		"network-instance-attachment",
		errors.New("create not allowed while custom resource definition is terminating"),
	)
}

// kindNotServedErr reproduces the 404 the apiserver returns when the
// resource endpoint for a kind is not (yet) served — the other half of
// the same race, seen once the RESTMapper holds a stale mapping.
func kindNotServedErr() error {
	return apierrors.NewGenericServerResponse(
		http.StatusNotFound, "patch", schema.GroupResource{
			Group:    "k8s.cni.cncf.io",
			Resource: "network-attachment-definitions",
		}, "", "", 0, false)
}

func TestIsCRDLifecycleRace(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"crd terminating", crdTerminatingErr(), true},
		{"kind not served", kindNotServedErr(), true},
		// Permanent verdicts of the same HTTP classes must NOT be
		// swept up: over-broad matching would turn a genuine RBAC
		// denial or a missing object into a 10-attempt backoff.
		{"plain forbidden", apierrors.NewForbidden(
			schema.GroupResource{Resource: "pods"}, "p",
			errors.New("user cannot patch resource")), false},
		{"plain notfound", apierrors.NewNotFound(
			schema.GroupResource{Resource: "pods"}, "p"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCRDLifecycleRace(tc.err); got != tc.want {
				t.Errorf("isCRDLifecycleRace(%v) = %v, want %v",
					tc.err, got, tc.want)
			}
		})
	}
}

// TestIsRetryableCRDRace is the regression guard: both shapes reach
// isRetryable through the Forbidden/NotFound early-outs, which used to
// classify them as permanent and abort the whole transition on the
// first attempt.
func TestIsRetryableCRDRace(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"crd terminating retried", crdTerminatingErr(), true},
		{"kind not served retried", kindNotServedErr(), true},
		{"rbac denial still permanent", apierrors.NewForbidden(
			schema.GroupResource{Resource: "pods"}, "p",
			errors.New("user cannot patch resource")), false},
		{"missing object still permanent", apierrors.NewNotFound(
			schema.GroupResource{Resource: "pods"}, "p"), false},
		{"invalid still permanent", apierrors.NewInvalid(
			schema.GroupKind{Kind: "Pod"}, "p", nil), false},
		{"server timeout retried", apierrors.NewServerTimeout(
			schema.GroupResource{Resource: "pods"}, "patch", 1), true},
		{"unavailable retried", apierrors.NewServiceUnavailable("try later"), true},
		{"conflict retried (unknown class)", apierrors.NewConflict(
			schema.GroupResource{Resource: "pods"}, "p",
			errors.New("conflict")), true},
		{"status 404 with metav1 reason", &apierrors.StatusError{
			ErrStatus: metav1.Status{
				Code:    http.StatusNotFound,
				Reason:  metav1.StatusReasonNotFound,
				Message: "the server could not find the requested resource",
			},
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryable(tc.err); got != tc.want {
				t.Errorf("isRetryable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestCRDName decides whether Apply gates on establishment before the
// next document. Getting this wrong is silent: a false negative
// reinstates the CRD/CR race, a false positive blocks on a wait that
// can never be satisfied.
func TestCRDName(t *testing.T) {
	obj := func(apiVersion, kind, name string) *unstructured.Unstructured {
		u := &unstructured.Unstructured{}
		u.SetAPIVersion(apiVersion)
		u.SetKind(kind)
		if name != "" {
			u.SetName(name)
		}
		return u
	}

	cases := []struct {
		name     string
		obj      *unstructured.Unstructured
		wantName string
		wantOK   bool
	}{
		{
			name:     "v1 CRD gates on its own name",
			obj:      obj("apiextensions.k8s.io/v1", "CustomResourceDefinition", "network-attachment-definitions.k8s.cni.cncf.io"),
			wantName: "network-attachment-definitions.k8s.cni.cncf.io",
			wantOK:   true,
		},
		{
			// The group is matched without its version so a future
			// apiextensions/v2 still gates rather than silently
			// reinstating the race.
			name:     "future apiextensions version still gates",
			obj:      obj("apiextensions.k8s.io/v2", "CustomResourceDefinition", "widgets.example.com"),
			wantName: "widgets.example.com",
			wantOK:   true,
		},
		{
			name:   "a CR of a CRD does not gate",
			obj:    obj("k8s.cni.cncf.io/v1", "NetworkAttachmentDefinition", "network-instance-attachment"),
			wantOK: false,
		},
		{
			name:   "same kind in another group does not gate",
			obj:    obj("example.com/v1", "CustomResourceDefinition", "impostor"),
			wantOK: false,
		},
		{
			name:   "ordinary object does not gate",
			obj:    obj("apps/v1", "DaemonSet", "kube-multus-ds"),
			wantOK: false,
		},
		{
			name:   "nameless CRD cannot be waited on",
			obj:    obj("apiextensions.k8s.io/v1", "CustomResourceDefinition", ""),
			wantOK: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotName, gotOK := crdName(c.obj)
			if gotOK != c.wantOK {
				t.Fatalf("crdName ok = %v, want %v", gotOK, c.wantOK)
			}
			if gotOK && gotName != c.wantName {
				t.Errorf("crdName = %q, want %q", gotName, c.wantName)
			}
		})
	}
}

// TestFetchClientRoutesThroughMgmtproxy pins the regression this fixes:
// fetchURL (used for the KubeVirt CR, CDI operator, and CDI CR manifest
// fetches) must route through pillar's cost-aware mgmtproxy. This checks
// fetchClient's Proxy func directly rather than http.DefaultClient +
// HTTPS_PROXY, since the latter's env-var lookup is cached process-wide on
// first use and would not reliably reflect a per-test env change.
func TestFetchClientRoutesThroughMgmtproxy(t *testing.T) {
	oldFlag := mgmtproxy.DisableFlag
	mgmtproxy.DisableFlag = filepath.Join(t.TempDir(), "disable")
	t.Cleanup(func() { mgmtproxy.DisableFlag = oldFlag })

	transport, ok := fetchClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("fetchClient.Transport = %T, want *http.Transport", fetchClient.Transport)
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	got, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	if got == nil || got.String() != mgmtproxy.URL {
		t.Errorf("Proxy() = %v, want %s", got, mgmtproxy.URL)
	}

	if err := os.WriteFile(mgmtproxy.DisableFlag, nil, 0o644); err != nil {
		t.Fatalf("write disable flag: %v", err)
	}
	got, err = transport.Proxy(req)
	if err != nil {
		t.Fatalf("Proxy (off-switch set): %v", err)
	}
	if got != nil {
		t.Errorf("Proxy() with off-switch set = %v, want nil", got)
	}
}
