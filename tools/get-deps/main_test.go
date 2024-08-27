package main

import (
	"os"
	"sort"
	"strings"
	"testing"
)

func TestParseDockerfile(t *testing.T) {
	targets := readDockerFile()

	expected := map[string]bool{
		"abcd:12345": false,
		"f":          false,
		"f-amd64":    false,
		"lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f121":       false,
		"lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f121-amd64": false,
		"lfedge/eve-rust:1.80.1":                                  false,
		"lfedge/eve-xen-tools:":                                   false,
	}

	for _, target := range targets {
		expected[target] = true
	}

	if len(expected) != len(targets) {
		t.Fatalf("expected %d, got %d", len(expected), len(targets))
	}

	for target, found := range expected {
		if !found {
			t.Fatalf("did not find target %s", target)
		}
	}
}

func readDockerFile() []string {
	f := strings.NewReader(`
			FROM abcd:12345 AS f
			RUN echo \
			FROM thisshouldnotbeincluded:666666
			FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f121
			FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f121-amd64
			FROM lfedge/eve-rust:1.80.1
			FROM lfedge/eve-xen-tools:$XENTOOLS

			FROM f
			RUN echo

			FROM f-${TARGETARCH}
		`)

	targets := parseDockerfile(f)
	return targets
}

func TestNoneLinuxKitImage(t *testing.T) {
	// set current directory to ../..
	// so that we can find ./pkg/xxx
	if os.Chdir("../..") != nil {
		t.Fatalf("could not change working directory")
	}

	targets := readDockerFile()
	filtered := filterPkg(targets)
	sort.Strings(filtered)

	expected := []string{"pkg/alpine", "pkg/xen-tools"}
	sort.Strings(expected)

	if len(filtered) != len(expected) {
		t.Fatalf("expected %d, got %d [%v, %v]", len(expected), len(filtered), expected, filtered)
	}

	for i, target := range filtered {
		if target != expected[i] {
			t.Fatalf("expected %s, got %s", expected[i], target)
		}
	}
}
