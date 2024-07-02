package main

import (
	"strings"
	"testing"
)

func TestParseDockerfile(t *testing.T) {
	targetArch = "amd64"
	f := strings.NewReader(`
			FROM abcd:12345 AS f
			RUN echo \
			FROM thisshouldnotbeincluded:666666

			FROM f
			RUN echo

			FROM f-${TARGETARCH}
		`)

	targets := parseDockerfile(f)

	foundMap := map[string]bool{
		"abcd:12345": false,
		"f":          false,
		"f-amd64":    false,
	}

	for _, target := range targets {
		foundMap[target] = true
	}

	for target, found := range foundMap {
		if !found {
			t.Fatalf("did not find target %s", target)
		}
	}
}
