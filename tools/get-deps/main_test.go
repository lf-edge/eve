package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/lf-edge/eve/tools/dockerfile-from-checker/dockerfilefrom"
)

func TestParseDockerfile(t *testing.T) {
	targets := readDockerFile()

	expected := map[string]bool{
		"abcd:12345": false,
		"lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f121":       false,
		"lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f121-amd64": false,
		"lfedge/eve-rust:1.80.1":                                  false,
		"lfedge/eve-qemu:":                                        false,
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
	f := `
			FROM abcd:12345 AS f
			RUN echo \
			FROM thisshouldnotbeincluded:666666
			FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f121
			FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f121-amd64
			FROM lfedge/eve-rust:1.80.1
			FROM lfedge/eve-qemu:$QEMU_TAG

			FROM f
			RUN echo

			FROM f-${TARGETARCH}
		`

	b := `
org: lfedge
image: eve-pillar
`

	tempDir, err := os.MkdirTemp("", "get-deps-test")
	if err != nil {
		panic(err)
	}

	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	buildYmlPath := filepath.Join(tempDir, "build.yml")

	err = os.WriteFile(dockerfilePath, []byte(f), 0600)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(buildYmlPath, []byte(b), 0600)
	if err != nil {
		panic(err)
	}

	targets := parseDockerfile(tempDir, []string{"amd64"}, "amd64")
	return targets
}

// The stage layout of pkg/pillar: the cross toolchain is only reachable
// when the target and build architectures differ.
const reachDockerfile = `
ARG BASE=lfedge/eve-alpine:1
FROM lfedge/eve-indexed:1
FROM lfedge/eve-uefi:1 AS uefi
FROM lfedge/eve-unused:1 AS unused
FROM ${BASE} AS build-native
FROM --platform=${BUILDPLATFORM} ${BASE} AS build-cross
FROM --platform=${BUILDPLATFORM} lfedge/eve-cross-compilers:1 AS cross-compilers
FROM build-cross AS build-cross-target
COPY --from=cross-compilers /packages /packages
FROM build-cross-target AS target-arm64-build-amd64
FROM build-cross-target AS target-amd64-build-arm64
FROM build-native AS target-amd64-build-amd64
FROM build-native AS target-arm64-build-arm64
FROM target-${TARGETARCH}-build-${BUILDARCH} AS build
RUN --mount=type=bind,from=lfedge/eve-mounted:1,target=/m true
FROM scratch
COPY --from=0 / /
COPY --from=UEFI / /
COPY --from=build / /
COPY --from=lfedge/eve-copied:1 / /
`

func TestParseDockerfileReachable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(reachDockerfile), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "build.yml"), []byte("org: lfedge\nimage: eve-reach\n"), 0600); err != nil {
		t.Fatal(err)
	}

	native := []string{
		"lfedge/eve-alpine:1",
		"lfedge/eve-copied:1",
		"lfedge/eve-indexed:1",
		"lfedge/eve-mounted:1",
		"lfedge/eve-uefi:1",
		"scratch",
	}
	cross := append([]string{"lfedge/eve-cross-compilers:1"}, native...)
	all := append([]string{"lfedge/eve-unused:1"}, cross...)
	cases := []struct {
		target []string
		build  string
		want   []string
	}{
		{[]string{"amd64"}, "amd64", native},
		{[]string{"arm64"}, "arm64", native},
		{[]string{"arm64"}, "amd64", cross},
		{[]string{"amd64"}, "arm64", cross},
		{[]string{"arm64", "amd64"}, "amd64", cross},
		// no target-riscv64-build-amd64 stage: keep every FROM
		{[]string{"riscv64"}, "amd64", all},
	}
	for _, tc := range cases {
		got := parseDockerfile(dir, tc.target, tc.build)
		sort.Strings(got)
		sort.Strings(tc.want)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("target %v build %s:\n got  %q\n want %q", tc.target, tc.build, got, tc.want)
		}
	}
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

	expected := []string{"pkg/alpine", "pkg/qemu"}
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

func TestStageNamedLikeItsBase(t *testing.T) {
	res, err := dockerfilefrom.Scan(strings.NewReader("FROM alpine AS alpine\nFROM alpine\n"))
	if err != nil {
		t.Fatal(err)
	}
	images, unresolved := newStageGraph(res, nil).reachableImages()
	if unresolved != "" || !reflect.DeepEqual(images, []string{"alpine"}) {
		t.Fatalf("got %q, %q, want [alpine]", images, unresolved)
	}
}
