// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package lpsapi

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/lf-edge/eve-api/go/profile"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// ndjsonMime is the MIME type of the signal stream.
	ndjsonMime = "application/x-ndjson"

	// signalWriteTimeout bounds each individual write so a stuck EVE
	// client cannot indefinitely block the goroutine.
	signalWriteTimeout = 5 * time.Second
)

// signal implements GET /api/v1/signal. It is a long-lived NDJSON stream
// that emits one profile.Signal message per line whenever the set of
// LPS endpoints with pending configuration changes grows. On a newly
// opened connection, if any endpoints are already pending, an initial
// Signal covering all of them is emitted immediately.
//
// See PROFILE.md in the eve-api repo for the full protocol.
func (h *Handler) signal(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ndjsonMime)
	w.Header().Set("Cache-Control", "no-store")

	rc := http.NewResponseController(w)
	broker := h.state.Broker()
	ch, unsub := broker.SubscribePending()
	defer unsub()

	// Initial emission: if anything is already pending at the moment of
	// subscription, send it immediately. Subscribing before snapshotting
	// guarantees we do not miss a MarkPending that happens between the
	// two steps — it will land in ch and the loop below will re-read
	// the snapshot (possibly producing a duplicate Signal, which is
	// harmless since each Signal only tells EVE to poll).
	if pending := broker.SnapshotPending(); len(pending) > 0 {
		if err := writeSignal(w, rc, pending); err != nil {
			log.Printf("signal: initial write failed: %v", err)
			return
		}
		flusher.Flush()
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			pending := broker.SnapshotPending()
			if len(pending) == 0 {
				continue
			}
			if err := writeSignal(w, rc, pending); err != nil {
				log.Printf("signal: write failed: %v", err)
				return
			}
			flusher.Flush()
		}
	}
}

// writeSignal serializes a Signal covering the given endpoints as one
// canonical-JSON line terminated by '\n'. Applies a short write deadline
// so a stuck client cannot wedge the handler.
func writeSignal(w http.ResponseWriter, rc *http.ResponseController,
	pending []profile.ConfigEndpoint) error {
	sig := &profile.Signal{PendingChanges: pending}
	data, err := protojson.Marshal(sig)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := rc.SetWriteDeadline(time.Now().Add(signalWriteTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if _, err := w.Write([]byte{'\n'}); err != nil {
		return err
	}
	return nil
}
