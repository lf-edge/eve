// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// newDeferTestCtx returns a volumemgrContext with an in-memory
// pubDeferredDelete publication for exercising the deferred-delete guards.
func newDeferTestCtx(t *testing.T) *volumemgrContext {
	t.Helper()
	logger := logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, "test-volumemgr", 0)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DeferredContentDeleteStatus{},
	})
	if err != nil {
		t.Fatalf("NewPublication: %v", err)
	}
	return &volumemgrContext{pubDeferredDelete: pub}
}

func publishDefer(t *testing.T, ctx *volumemgrContext, refID string, blobs []string, expiry time.Time) types.DeferredContentDeleteStatus {
	t.Helper()
	id, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("uuid.NewV4: %v", err)
	}
	rec := types.DeferredContentDeleteStatus{
		ContentID:   id,
		ReferenceID: refID,
		Blobs:       blobs,
		DeleteTime:  expiry,
	}
	if err := ctx.pubDeferredDelete.Publish(rec.Key(), rec); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	return rec
}

func TestBlobDeferredProtected(t *testing.T) {
	ctx := newDeferTestCtx(t)
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	publishDefer(t, ctx, "ref-live", []string{"aaa", "bbb"}, future)
	publishDefer(t, ctx, "ref-expired", []string{"ccc"}, past)

	cases := map[string]bool{
		"aaa": true,  // listed in an unexpired record
		"bbb": true,  // listed in an unexpired record
		"ccc": false, // only in an expired record -> not protected
		"zzz": false, // not listed anywhere
	}
	for sha, want := range cases {
		if got := blobDeferredProtected(ctx, sha); got != want {
			t.Errorf("blobDeferredProtected(%q) = %v, want %v", sha, got, want)
		}
	}

	if !imageDeferredProtected(ctx, "ref-live") {
		t.Error("imageDeferredProtected(ref-live) = false, want true")
	}
	if imageDeferredProtected(ctx, "ref-expired") {
		t.Error("imageDeferredProtected(ref-expired) = true, want false (expired)")
	}
	if imageDeferredProtected(ctx, "ref-missing") {
		t.Error("imageDeferredProtected(ref-missing) = true, want false")
	}
}

func TestCancelDeferredDelete(t *testing.T) {
	ctx := newDeferTestCtx(t)
	rec := publishDefer(t, ctx, "ref", []string{"sha-1"}, time.Now().Add(time.Hour))

	if !blobDeferredProtected(ctx, "sha-1") {
		t.Fatal("blob should be protected before cancel")
	}
	cancelDeferredDelete(ctx, rec.Key())
	if blobDeferredProtected(ctx, "sha-1") {
		t.Error("blob should not be protected after cancel")
	}
	if item, _ := ctx.pubDeferredDelete.Get(rec.Key()); item != nil {
		t.Error("deferred-delete record should be gone after cancel")
	}
	// Cancelling a non-existent record must be a no-op (no panic).
	missing, _ := uuid.NewV4()
	cancelDeferredDelete(ctx, missing.String())
}
