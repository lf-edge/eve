// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"
)

// Leases of the tests: 10 minutes to start the upload, 1 minute without progress.
const (
	testStartLease    = 10 * time.Minute
	testProgressLease = time.Minute
)

func newTestImageClaims() (*imageClaims, *time.Time) {
	c := newImageClaims(testStartLease, testProgressLease)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	return c, &now
}

func TestImageClaimExclusive(t *testing.T) {
	c, _ := newTestImageClaims()
	ticket, ok := c.claim("img")
	if !ok || ticket == "" {
		t.Fatalf("first claim not granted: %q %v", ticket, ok)
	}
	if _, ok := c.claim("img"); ok {
		t.Fatal("second claim granted while the first is held")
	}
	if _, ok := c.claim("other"); !ok {
		t.Fatal("claim of a different image refused")
	}
}

func TestImageClaimRelease(t *testing.T) {
	c, _ := newTestImageClaims()
	ticket, _ := c.claim("img")
	c.release("img", "wrong-ticket")
	if _, ok := c.claim("img"); ok {
		t.Fatal("release with a wrong ticket freed the claim")
	}
	c.release("img", ticket)
	if _, ok := c.claim("img"); !ok {
		t.Fatal("claim not granted after release")
	}
}

func TestImageClaimLeaseExpiryAndTakeover(t *testing.T) {
	c, now := newTestImageClaims()
	old, _ := c.claim("img")

	*now = now.Add(testStartLease - time.Second)
	if _, ok := c.claim("img"); ok {
		t.Fatal("claim granted before the lease lapsed")
	}

	*now = now.Add(2 * time.Second)
	fresh, ok := c.claim("img")
	if !ok {
		t.Fatal("claim not granted after the lease lapsed")
	}
	if fresh == old {
		t.Fatal("takeover reused the old ticket")
	}
	if c.renew("img", old) {
		t.Fatal("superseded ticket was renewed")
	}
	if !c.renew("img", fresh) {
		t.Fatal("current ticket was not renewed")
	}
	// The superseded holder releasing late must not drop the new claim.
	c.release("img", old)
	if _, ok := c.claim("img"); ok {
		t.Fatal("late release by the previous holder dropped the new claim")
	}
}

// A claim waits long for the upload to start, but once the upload runs it
// lapses after the short progress lease.
func TestImageClaimStartAndProgressLeases(t *testing.T) {
	c, now := newTestImageClaims()
	ticket, _ := c.claim("img")

	*now = now.Add(5 * testProgressLease) // well past the progress lease
	if _, ok := c.claim("img"); ok {
		t.Fatal("a claim whose upload did not start lapsed after the progress lease")
	}

	if !c.renew("img", ticket) { // the upload starts
		t.Fatal("renew failed")
	}
	*now = now.Add(testProgressLease - time.Second)
	if _, ok := c.claim("img"); ok {
		t.Fatal("a running upload lapsed before the progress lease")
	}
	*now = now.Add(2 * time.Second)
	if _, ok := c.claim("img"); !ok {
		t.Fatal("a stalled upload did not lapse after the progress lease")
	}
}

func TestImageClaimRenewExtendsLease(t *testing.T) {
	c, now := newTestImageClaims()
	ticket, _ := c.claim("img")
	for i := 0; i < 5; i++ {
		*now = now.Add(45 * time.Second)
		if !c.renew("img", ticket) {
			t.Fatalf("renew %d failed", i)
		}
	}
	if _, ok := c.claim("img"); ok {
		t.Fatal("claim granted although the lease keeps being renewed")
	}
}

func TestImageClaimRenewAfterLapseWithoutTakeover(t *testing.T) {
	c, now := newTestImageClaims()
	ticket, _ := c.claim("img")
	*now = now.Add(2 * testStartLease)
	if !c.renew("img", ticket) {
		t.Fatal("a lapsed but not taken over claim must still be renewable")
	}
}

func TestImageClaimPrunesLapsedClaimsOfOtherImages(t *testing.T) {
	c, now := newTestImageClaims()
	c.claim("abandoned")
	*now = now.Add(testStartLease + time.Minute)
	c.claim("img")
	if _, left := c.claims["abandoned"]; left {
		t.Fatal("the lapsed claim of another image was not pruned")
	}
}

func TestImageClaimTakeoverCancelsPreviousUpload(t *testing.T) {
	c, now := newTestImageClaims()
	old, _ := c.claim("img")
	cancelled := false
	if !c.attach("img", old, func() { cancelled = true }) {
		t.Fatal("attach to the current claim failed")
	}
	if c.attach("img", "other", func() {}) {
		t.Fatal("attach with a foreign ticket succeeded")
	}
	*now = now.Add(testStartLease + time.Minute)
	if _, ok := c.claim("img"); !ok {
		t.Fatal("takeover refused")
	}
	if !cancelled {
		t.Fatal("the upload of the previous holder was not cancelled")
	}
}

func TestImageClaimImageOf(t *testing.T) {
	c, _ := newTestImageClaims()
	ticket, _ := c.claim("img")
	if img, ok := c.imageOf(ticket); !ok || img != "img" {
		t.Fatalf("imageOf(ticket) = %q, %v", img, ok)
	}
	if _, ok := c.imageOf("other"); ok {
		t.Fatal("imageOf found an image for an unknown ticket")
	}
	c.release("img", ticket)
	if _, ok := c.imageOf(ticket); ok {
		t.Fatal("imageOf found an image for a released ticket")
	}
}
