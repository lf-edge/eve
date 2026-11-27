// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package quorum

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// recordPath holds everything this node remembers about quorum recovery,
// in one file so that related facts change together. Under /var/lib so it
// lives on the same vault-backed storage as the etcd data it describes,
// survives the reboots a recovery involves, and is saved and restored with
// the rest of /var/lib on a single/cluster conversion. Var for test
// override.
var recordPath = "/var/lib/quorum-recovery.json"

// record is the whole on-disk state.
type record struct {
	// Applied is the generation this node has fully converged to.
	// Written only once etcd is healthy again, or as a baseline when
	// nothing was owed.
	Applied *appliedRecord `json:",omitempty"`

	// Intent is a convergence that has begun. Written before anything
	// destructive happens.
	Intent *intentRecord `json:",omitempty"`

	// Failure is why the most recent convergence attempt failed or a
	// bump was rejected, so it survives the retry delay (and a kube-init
	// restart across it) for StampNodeStatus to report to the
	// controller.
	Failure string `json:",omitempty"`
}

type appliedRecord struct {
	Generation k3s.Generation
	// AsSeed is whether the node was the seed when the generation was
	// recorded, and has not been seen as anything else since. A later
	// generation change is only a recovery if the node was not already
	// the seed: the controller moves join_server_ip to the survivor in
	// the same change, and the old seed's cluster config is withdrawn.
	AsSeed bool
	// At is when Generation was first recorded.
	At time.Time
}

type intentRecord struct {
	Generation k3s.Generation
	Action     string
	StartedAt  time.Time
}

// Intent is a convergence in progress.
type Intent struct {
	Generation k3s.Generation
	Action     Action
	StartedAt  time.Time
}

// mu serialises read-modify-write cycles: Evaluate runs from the monitor
// and from the daemon, and failures are recorded from the daemon while
// StampNodeStatus reads.
var mu sync.Mutex

// load reads the record; a missing file is an empty record.
func load() (record, error) {
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return record{}, nil
		}
		return record{}, fmt.Errorf("read %s: %w", recordPath, err)
	}
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return record{}, fmt.Errorf("malformed %s: %w", recordPath, err)
	}
	return rec, nil
}

// update applies fn to the record and writes it back atomically. Nothing
// is written when fn changes nothing, and an emptied record removes the
// file so that "never recorded" stays distinguishable.
func update(fn func(rec *record)) error {
	mu.Lock()
	defer mu.Unlock()
	rec, err := load()
	if err != nil {
		return err
	}
	before, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	fn(&rec)
	after, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if bytes.Equal(before, after) {
		return nil
	}
	if rec == (record{}) {
		if err := os.Remove(recordPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", recordPath, err)
		}
		return nil
	}
	if err := state.AtomicWriteFile(recordPath, append(after, '\n'), 0644); err != nil {
		return fmt.Errorf("write %s: %w", recordPath, err)
	}
	return nil
}

// read loads the record under the lock.
func read() (record, error) {
	mu.Lock()
	defer mu.Unlock()
	return load()
}

// readApplied returns the applied generation, and whether the node was
// the seed when it was recorded.
func readApplied() (g k3s.Generation, asSeed, recorded bool, err error) {
	rec, err := read()
	if err != nil || rec.Applied == nil {
		return k3s.Generation{}, false, false, err
	}
	return rec.Applied.Generation, rec.Applied.AsSeed, true, nil
}

// ReadApplied returns the last generation this node converged to.
func ReadApplied() (g k3s.Generation, recorded bool, err error) {
	g, _, recorded, err = readApplied()
	return g, recorded, err
}

// ReadAppliedAsSeed reports whether the node was the seed when it last
// recorded a generation, and has not been seen as anything else since.
func ReadAppliedAsSeed() (bool, error) {
	_, asSeed, _, err := readApplied()
	return asSeed, err
}

// setApplied records g, keeping the time it was first recorded when only
// the role changes.
func setApplied(rec *record, g k3s.Generation, asSeed bool) {
	at := time.Now()
	if rec.Applied != nil && rec.Applied.Generation == g {
		at = rec.Applied.At
	}
	rec.Applied = &appliedRecord{Generation: g, AsSeed: asSeed, At: at}
}

// WriteApplied records convergence. Call only once the node is healthy
// in the recovered cluster: this is what stops the action repeating.
func WriteApplied(g k3s.Generation, asSeed bool) error {
	return update(func(rec *record) { setApplied(rec, g, asSeed) })
}

// CompleteIntent records convergence and clears the in-progress intent in
// one write, so a crash cannot leave a finished intent behind.
func CompleteIntent(g k3s.Generation, asSeed bool) error {
	return update(func(rec *record) {
		setApplied(rec, g, asSeed)
		rec.Intent = nil
	})
}

// AppliedAt is when the recorded generation was first recorded, which for
// a converged node is when it got there.
func AppliedAt() (t time.Time, recorded bool, err error) {
	rec, err := read()
	if err != nil || rec.Applied == nil {
		return time.Time{}, false, err
	}
	return rec.Applied.At, true, nil
}

// ReadIntent returns a convergence that began and has not been
// committed, if any.
func ReadIntent() (in Intent, found bool, err error) {
	rec, err := read()
	if err != nil || rec.Intent == nil {
		return Intent{}, false, err
	}
	action, err := parseAction(rec.Intent.Action)
	if err != nil {
		return Intent{}, false, err
	}
	return Intent{
		Generation: rec.Intent.Generation,
		Action:     action,
		StartedAt:  rec.Intent.StartedAt,
	}, true, nil
}

// WriteIntent records that a convergence is starting. Must be called
// before the first destructive step.
//
// The pair of intent and applied exists because neither alone is safe.
// Recording only on completion means a crash after the wipe repeats it on
// the next boot, and the second wipe destroys a member that had already
// rejoined. Recording only up front means a crash before the work is done
// leaves the node believing it converged, holding etcd state from a
// cluster that no longer exists, and nothing ever revisits it.
func WriteIntent(in Intent) error {
	return update(func(rec *record) {
		rec.Intent = &intentRecord{
			Generation: in.Generation,
			Action:     in.Action.String(),
			StartedAt:  in.StartedAt,
		}
	})
}

// ClearIntent removes the in-progress record.
func ClearIntent() error {
	return update(func(rec *record) { rec.Intent = nil })
}

// WriteFailure records why the convergence for g failed, for reporting
// back to the controller until either that generation succeeds or a
// fresher attempt begins.
func WriteFailure(g k3s.Generation, cause error) error {
	msg := fmt.Sprintf("Failed to promote cluster to generation %d: %v", g.Counter, cause)
	return update(func(rec *record) { rec.Failure = msg })
}

// ReadFailure returns the reason recorded by WriteFailure, if any.
func ReadFailure() (msg string, found bool, err error) {
	rec, err := read()
	if err != nil || rec.Failure == "" {
		return "", false, err
	}
	return rec.Failure, true, nil
}

// ClearFailure removes the failure record. Call once a subsequent
// attempt succeeds.
func ClearFailure() error {
	return update(func(rec *record) { rec.Failure = "" })
}

// Resume returns the action to take on boot when a previous attempt did
// not finish.
//
// The action comes from the intent, never from re-deciding against the
// current cluster status. A config push landing mid-reset would
// otherwise restart the reset against a newer generation on the next
// reboot, leaving the database half-reset with no record of which
// attempt it belongs to.
func Resume() (in Intent, found bool, err error) {
	in, found, err = ReadIntent()
	if err != nil || !found {
		return Intent{}, false, err
	}
	applied, recorded, err := ReadApplied()
	if err != nil {
		return Intent{}, false, err
	}
	// An intent left over from a generation already applied is
	// finished work whose marker was not cleared.
	if recorded && applied == in.Generation {
		return Intent{}, false, ClearIntent()
	}
	return in, true, nil
}
