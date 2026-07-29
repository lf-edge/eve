// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func TestPublishBaseOsStatus(t *testing.T) {
	tc := newTestCtx(t)
	st := types.BaseOsStatus{
		ContentTreeUUID: "uuid-1",
		BaseOsVersion:   "13.4",
		PartitionLabel:  "IMGB",
	}
	publishBaseOsStatus(tc.ctx, &st)

	got, err := tc.pubBaseOsStatus.Get("uuid-1")
	if err != nil {
		t.Fatalf("not published: %v", err)
	}
	pst, ok := got.(types.BaseOsStatus)
	if !ok {
		t.Fatalf("wrong type %T", got)
	}
	if pst.PartitionLabel != "IMGB" || pst.BaseOsVersion != "13.4" {
		t.Fatalf("got %+v", pst)
	}
}

func TestUnpublishBaseOsStatus_KnownKey(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubBaseOsStatus.items["uuid-1"] = types.BaseOsStatus{ContentTreeUUID: "uuid-1"}

	unpublishBaseOsStatus(tc.ctx, "uuid-1")

	if _, err := tc.pubBaseOsStatus.Get("uuid-1"); err == nil {
		t.Fatal("expected key removed")
	}
}

func TestUnpublishBaseOsStatus_UnknownKeyIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	// Nothing to remove; the function logs an error but must not panic.
	unpublishBaseOsStatus(tc.ctx, "absent")
}

func TestPublishZbootStatus(t *testing.T) {
	tc := newTestCtx(t)
	st := types.ZbootStatus{
		PartitionLabel:   "IMGA",
		PartitionState:   "active",
		ShortVersion:     "13.4.0-kvm-amd64",
		CurrentPartition: true,
	}
	publishZbootStatus(tc.ctx, st)

	got, err := tc.pubZbootStatus.Get("IMGA")
	if err != nil {
		t.Fatalf("not published: %v", err)
	}
	pst, ok := got.(types.ZbootStatus)
	if !ok || pst.PartitionState != "active" || !pst.CurrentPartition {
		t.Fatalf("got %+v", pst)
	}
}
