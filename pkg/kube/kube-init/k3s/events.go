// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// kineDB is the kine/SQLite datastore of a single-node k3s server.
// Declared as a var so tests can shadow it.
var kineDB = "/var/lib/rancher/k3s/server/db/state.db"

// legacyEventLease is the lease, in seconds, of events written under the
// former event-ttl=72h default: the TTL plus the 60 s the apiserver adds.
//
// kine stores each key's lease in its row and re-arms expiry from that
// lease at every k3s start, so lowering event-ttl does not expire events
// already written. A device that reboots more often than every 72 h never
// expires them at all, and the datastore grows by hundreds of MB.
// Matching this exact lease leaves events from a deliberately longer
// user-override TTL alone.
const legacyEventLease = 72*60*60 + 60

// runSQLite runs statements against db with the sqlite3 CLI and returns
// its output. Declared as a var so tests can stub it; the CLI keeps
// kube-init a static CGO_ENABLED=0 binary (see sqliteVacuumInto).
var runSQLite = func(db, sql string) (string, error) {
	out, err := exec.Command("sqlite3", "-cmd", ".timeout 60000", db, sql).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// pruneLegacyEvents deletes events still carrying legacyEventLease from
// the kine datastore and vacuums it if any were removed. It must run
// while k3s is stopped, since it changes rows under kine. Best-effort:
// failures are logged and k3s starts regardless.
func pruneLegacyEvents() {
	if _, err := os.Stat(kineDB); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("prune legacy events: stat %s: %v", kineDB, err)
		}
		return
	}
	start := time.Now()
	out, err := runSQLite(kineDB, fmt.Sprintf(
		"DELETE FROM kine WHERE name LIKE '/registry/events/%%' AND lease = %d; SELECT changes();",
		legacyEventLease))
	if err != nil {
		log.Printf("prune legacy events: %v (output: %s)", err, out)
		return
	}
	n, err := strconv.Atoi(out)
	if err != nil {
		log.Printf("prune legacy events: unexpected sqlite3 output %q", out)
		return
	}
	if n == 0 {
		return
	}
	if out, err := runSQLite(kineDB, "VACUUM;"); err != nil {
		log.Printf("prune legacy events: vacuum: %v (output: %s)", err, out)
	}
	log.Printf("prune legacy events: removed %d events in %s",
		n, time.Since(start).Round(time.Millisecond))
}
