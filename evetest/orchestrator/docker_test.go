// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"slices"
	"testing"
)

func TestRunArgsUseVersionsOfJob(t *testing.T) {
	d := DockerExecutor{Image: "lfedge/evetest:e1", CommonArgs: []string{"-e", "EVETEST_SDN_VERSION=s1"}}

	args := d.runArgs(&Job{Name: "a", Port: 50021, Container: "evetest-50021"})
	if args[len(args)-1] != "lfedge/evetest:e1" || slices.Contains(args, "EVETEST_SDN_VERSION=s2") {
		t.Errorf("job without versions must use the shared settings: %v", args)
	}

	args = d.runArgs(&Job{Name: "a", Port: 50021, Container: "evetest-50021",
		Versions: Versions{Evetest: "e2", SDN: "s2"}})
	if args[len(args)-1] != "lfedge/evetest:e2" {
		t.Errorf("image = %s, want lfedge/evetest:e2", args[len(args)-1])
	}
	shared := slices.Index(args, "EVETEST_SDN_VERSION=s1")
	override := slices.Index(args, "EVETEST_SDN_VERSION=s2")
	if override < shared {
		t.Errorf("the SDN version of the job must come after the shared one: %v", args)
	}
}

func TestImageRepo(t *testing.T) {
	for ref, want := range map[string]string{
		"lfedge/evetest:abc":         "lfedge/evetest",
		"localhost:5000/evetest:abc": "localhost:5000/evetest",
		"localhost:5000/evetest":     "localhost:5000/evetest",
		"evetest":                    "evetest",
	} {
		if got := ImageRepo(ref); got != want {
			t.Errorf("ImageRepo(%q) = %q, want %q", ref, got, want)
		}
	}
}
