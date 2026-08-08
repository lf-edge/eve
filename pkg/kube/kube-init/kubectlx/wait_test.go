// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"context"
	"testing"
	"time"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestCRDEstablished covers the gate Apply uses before applying a CR of
// a just-applied CRD.
//
// The terminating case is the one that matters and the one that was
// missed: a CRD under deletion keeps Established=True for as long as
// its finalizers run, while the apiserver already refuses CRs of that
// kind. Treating that as satisfied is how a CR apply still took the 404
// this wait exists to prevent.
func TestCRDEstablished(t *testing.T) {
	crd := func(mutate func(*apiextv1.CustomResourceDefinition)) *apiextv1.CustomResourceDefinition {
		c := &apiextv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "network-attachment-definitions.k8s.cni.cncf.io"},
			Status: apiextv1.CustomResourceDefinitionStatus{
				Conditions: []apiextv1.CustomResourceDefinitionCondition{{
					Type:   apiextv1.Established,
					Status: apiextv1.ConditionTrue,
				}},
			},
		}
		if mutate != nil {
			mutate(c)
		}
		return c
	}
	now := metav1.Now()

	cases := []struct {
		name    string
		obj     *apiextv1.CustomResourceDefinition
		wantOK  bool
		wantErr bool
	}{
		{
			name:   "established and live",
			obj:    crd(nil),
			wantOK: true,
		},
		{
			name: "established but terminating is NOT ready",
			obj: crd(func(c *apiextv1.CustomResourceDefinition) {
				c.DeletionTimestamp = &now
				c.Finalizers = []string{"customresourcecleanup.apiextensions.k8s.io"}
			}),
			wantOK: false,
		},
		{
			name: "not established yet",
			obj: crd(func(c *apiextv1.CustomResourceDefinition) {
				c.Status.Conditions[0].Status = apiextv1.ConditionFalse
			}),
			wantOK: false,
		},
		{
			name: "no conditions at all",
			obj: crd(func(c *apiextv1.CustomResourceDefinition) {
				c.Status.Conditions = nil
			}),
			wantOK: false,
		},
		{
			name: "NamesAccepted=False is permanent, not a wait",
			obj: crd(func(c *apiextv1.CustomResourceDefinition) {
				c.Status.Conditions = []apiextv1.CustomResourceDefinitionCondition{{
					Type:    apiextv1.NamesAccepted,
					Status:  apiextv1.ConditionFalse,
					Message: "listKind conflicts with an existing CRD",
				}}
			}),
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := crdEstablished(c.obj)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, c.wantErr)
			}
			if ok != c.wantOK {
				t.Errorf("crdEstablished = %v, want %v", ok, c.wantOK)
			}
		})
	}
}

// A caller managing its own deadline must not have one imposed here.
// Getting this wrong is silent: the helper's timeout fires first, the
// caller's guard never runs, and the only symptom is that the guard
// appears to do nothing.
func TestWaitFromContextImposesNoDeadline(t *testing.T) {
	ctx, cancel := withOptionalTimeout(context.Background(), 0)
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("WaitFromContext must leave the ctx without a deadline")
	}
}

func TestWithOptionalTimeoutAppliesRealDeadlines(t *testing.T) {
	ctx, cancel := withOptionalTimeout(context.Background(), time.Minute)
	defer cancel()
	d, ok := ctx.Deadline()
	if !ok {
		t.Fatal("a positive timeout must produce a deadline")
	}
	if time.Until(d) > time.Minute+time.Second {
		t.Fatalf("deadline too far out: %s", time.Until(d))
	}
}

// The sentinel is negative, so it must not fall through to the "zero
// means default" branch anywhere it is rendered or compared.
func TestTimeoutStrDistinguishesSentinelFromDefault(t *testing.T) {
	if got := timeoutStr(WaitFromContext); got != "from ctx" {
		t.Fatalf("timeoutStr(WaitFromContext) = %q", got)
	}
	if got := timeoutStr(0); got != defaultWaitTimeout.String() {
		t.Fatalf("timeoutStr(0) = %q, want the default", got)
	}
	if got := timeoutStr(90 * time.Second); got != "1m30s" {
		t.Fatalf("timeoutStr(90s) = %q", got)
	}
}
