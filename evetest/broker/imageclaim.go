// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const (
	// imageClaimStartLease is how long a granted claim waits for the upload to
	// start. It has to cover the claimer obtaining the image first, e.g.
	// downloading a CI artifact of 1-2 GB, with a retry.
	imageClaimStartLease = 60 * time.Minute

	// imageClaimProgressLease is how long a claim whose upload has started
	// stays valid without upload progress. Every received chunk renews it.
	imageClaimProgressLease = 10 * time.Minute
)

// imageClaims tracks which client is entitled to upload a given EVE container
// image to the broker, so that of many clients needing the same image only one
// fetches and uploads it. A claim is a lease: when it lapses, the next claimer
// takes over and the previous holder's ticket stops being valid. The lease is
// long until the upload starts (the holder is still obtaining the image) and
// short once it runs (a stalled upload is not worth waiting for).
type imageClaims struct {
	mutex         sync.Mutex
	startLease    time.Duration // from the grant to the start of the upload
	progressLease time.Duration // from each upload progress to the next
	now           func() time.Time
	claims        map[string]imageClaim // key: docker image name
}

type imageClaim struct {
	ticket  string
	expires time.Time
	// cancel aborts the holder's upload in progress, if any, when another
	// client takes the claim over.
	cancel context.CancelFunc
}

func newImageClaims(startLease, progressLease time.Duration) *imageClaims {
	return &imageClaims{
		startLease:    startLease,
		progressLease: progressLease,
		now:           time.Now,
		claims:        make(map[string]imageClaim),
	}
}

// claim grants the claim of the image to the caller, unless a different client
// holds it and its lease has not lapsed.
func (c *imageClaims) claim(image string) (ticket string, granted bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	now := c.now()
	for name, cur := range c.claims {
		// Claims of images nobody asks for again would otherwise pile up.
		if name != image && !now.Before(cur.expires) {
			delete(c.claims, name)
		}
	}
	if cur, held := c.claims[image]; held {
		if now.Before(cur.expires) {
			return "", false
		}
		// The holder stalled for the whole lease; do not leave its upload
		// hanging next to the new holder's.
		if cur.cancel != nil {
			cur.cancel()
		}
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand does not fail on supported platforms.
		panic(err)
	}
	ticket = hex.EncodeToString(raw[:])
	c.claims[image] = imageClaim{ticket: ticket, expires: now.Add(c.startLease)}
	return ticket, true
}

// imageOf returns the image that the ticket is the current claim of.
func (c *imageClaims) imageOf(ticket string) (image string, ok bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for name, cur := range c.claims {
		if cur.ticket == ticket {
			return name, true
		}
	}
	return "", false
}

// attach registers the function that aborts the upload running under the
// ticket, for a takeover to call. It reports false if the ticket is not the
// current claim of the image.
func (c *imageClaims) attach(image, ticket string, cancel context.CancelFunc) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	cur, held := c.claims[image]
	if !held || cur.ticket != ticket {
		return false
	}
	cur.cancel = cancel
	c.claims[image] = cur
	return true
}

// renew records upload progress under the ticket: from now on the claim lapses
// after the (short) progress lease. It fails if the claim was released or taken
// over by another client, even when the lease of the caller's own claim had
// lapsed in between without anybody noticing.
func (c *imageClaims) renew(image, ticket string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	cur, held := c.claims[image]
	if !held || cur.ticket != ticket {
		return false
	}
	cur.expires = c.now().Add(c.progressLease)
	c.claims[image] = cur
	return true
}

// release gives up the claim identified by the ticket. It does nothing for a
// claim that was already released or taken over.
func (c *imageClaims) release(image, ticket string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if cur, held := c.claims[image]; held && cur.ticket == ticket {
		delete(c.claims, image)
	}
}
