// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package instances

import (
	"testing"
	"time"
)

func TestRegisterListRemove(t *testing.T) {
	t.Setenv("EVETEST_HOME", t.TempDir())
	now := time.Now()
	unregA, err := Register(Instance{Name: "a/suite", Port: 50022, StartedAt: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Register(Instance{Name: "b", Port: 50021, StartedAt: now}); err != nil {
		t.Fatal(err)
	}
	list, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "b" || list[1].Name != "a/suite" {
		t.Fatalf("unexpected list (want oldest first): %+v", list)
	}
	unregA()
	list, _ = List()
	if len(list) != 1 || list[0].Port != 50021 {
		t.Fatalf("unexpected list after unregister: %+v", list)
	}
}

func TestListWithoutRegistry(t *testing.T) {
	t.Setenv("EVETEST_HOME", t.TempDir())
	list, err := List()
	if err != nil || len(list) != 0 {
		t.Fatalf("got %+v, %v", list, err)
	}
}

func TestMatch(t *testing.T) {
	list := []Instance{
		{Name: "networking/dpc", Port: 50021, Container: "evetest-50021"},
		{Name: "networking/switch", Port: 50022, Container: "evetest-50022"},
		{Name: "apps/lps", Port: 50023, Container: "evetest-50023"},
	}
	tests := []struct {
		selector string
		wantPort int
		wantErr  bool
	}{
		{"1", 50021, false},
		{"3", 50023, false},
		{"50022", 50022, false},
		{"4", 0, true},
		{"apps/lps", 50023, false},
		{"evetest-50022", 50022, false},
		{"apps", 50023, false},
		{"lps", 50023, false},
		{"networking", 0, true},
		{"networking/s", 50022, false},
		{"nonexistent", 0, true},
		{"", 0, true},
	}
	for _, tc := range tests {
		got, err := Match(list, tc.selector)
		if (err != nil) != tc.wantErr || (err == nil && got.Port != tc.wantPort) {
			t.Errorf("Match(%q) = %+v, %v; want port %d, error %t",
				tc.selector, got, err, tc.wantPort, tc.wantErr)
		}
	}
}
