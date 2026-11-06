// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubSQLite replaces runSQLite for one test, records each statement and
// answers the DELETE with changes.
func stubSQLite(t *testing.T, changes string) *[]string {
	t.Helper()
	var calls []string
	orig := runSQLite
	runSQLite = func(_, sql string) (string, error) {
		calls = append(calls, sql)
		if strings.HasPrefix(sql, "DELETE") {
			return changes, nil
		}
		return "", nil
	}
	t.Cleanup(func() { runSQLite = orig })
	return &calls
}

func withKineDB(t *testing.T, create bool) {
	t.Helper()
	orig := kineDB
	kineDB = filepath.Join(t.TempDir(), "state.db")
	if create {
		if err := os.WriteFile(kineDB, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { kineDB = orig })
}

func TestPruneLegacyEventsNoDatastore(t *testing.T) {
	withKineDB(t, false)
	calls := stubSQLite(t, "5")
	pruneLegacyEvents()
	if len(*calls) != 0 {
		t.Fatalf("sqlite3 ran without a datastore: %q", *calls)
	}
}

func TestPruneLegacyEventsNothingToDelete(t *testing.T) {
	withKineDB(t, true)
	calls := stubSQLite(t, "0")
	pruneLegacyEvents()
	if len(*calls) != 1 {
		t.Fatalf("want only the DELETE, got %q", *calls)
	}
	if !strings.Contains((*calls)[0], "lease = 259260") ||
		!strings.Contains((*calls)[0], "'/registry/events/%'") {
		t.Fatalf("DELETE does not target 72h-lease events: %q", (*calls)[0])
	}
}

func TestPruneLegacyEventsVacuumsAfterDelete(t *testing.T) {
	withKineDB(t, true)
	calls := stubSQLite(t, "297835")
	pruneLegacyEvents()
	if len(*calls) != 2 || (*calls)[1] != "VACUUM;" {
		t.Fatalf("want DELETE then VACUUM, got %q", *calls)
	}
}
